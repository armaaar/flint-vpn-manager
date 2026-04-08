"""FlintVPN Manager — Flask REST API + SSE.

Main application server. Wires together proton_api, router_api,
profile_store, and device_tracker into a REST API with Server-Sent
Events for live tunnel health updates.

Run: python app.py (or flask run)
Access: http://localhost:5000 or http://<surface-ip>:5000 from LAN
"""

import json
import logging
import time
import threading
from pathlib import Path
from typing import Optional

from flask import Flask, request, jsonify, Response, send_from_directory

import secrets_manager as sm
import profile_store as ps
from proton_api import ProtonAPI
from router_api import RouterAPI, generate_lan_rules
from device_tracker import start_tracker, stop_tracker, get_tracker
from server_optimizer import find_better_server
from auto_optimizer import start_optimizer, stop_optimizer

app = Flask(__name__, static_folder="static", static_url_path="")

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Separate log files by purpose
APP_LOG = LOG_DIR / "app.log"       # Actions: connect, disconnect, create, delete, assign
ERROR_LOG = LOG_DIR / "error.log"   # Errors and exceptions only
ACCESS_LOG = LOG_DIR / "access.log" # HTTP request log

# App logger (actions + errors)
log = logging.getLogger("flintvpn")
log.setLevel(logging.DEBUG)

app_handler = logging.FileHandler(APP_LOG)
app_handler.setLevel(logging.INFO)
app_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

error_handler = logging.FileHandler(ERROR_LOG)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s\n%(exc_info)s"))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

log.addHandler(app_handler)
log.addHandler(error_handler)
log.addHandler(console_handler)

# Werkzeug access log → access.log
access_logger = logging.getLogger("werkzeug")
access_handler = logging.FileHandler(ACCESS_LOG)
access_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
access_logger.addHandler(access_handler)

# ── Global State ──────────────────────────────────────────────────────────────

_proton_api: Optional[ProtonAPI] = None
_router_api: Optional[RouterAPI] = None
_session_unlocked = False

SSH_KEY_PATH = "/home/armaaar/.ssh/id_ed25519"


def _get_proton():
    global _proton_api
    if _proton_api is None:
        _proton_api = ProtonAPI()
    return _proton_api


def _get_router():
    global _router_api
    if _router_api is None:
        config = sm.get_config()
        _router_api = RouterAPI(
            host=config.get("router_ip", "192.168.8.1"),
            key_filename=SSH_KEY_PATH,
        )
    return _router_api


def _require_unlocked():
    """Return error response if session is not unlocked."""
    if not _session_unlocked:
        return jsonify({"error": "Session locked. POST /api/unlock first."}), 401
    return None


def _rebuild_lan_rules():
    """Rebuild all LAN access control rules on the router from current store state.

    Stage 8: device IPs are read live from the router's DHCP leases (not the
    removed device_ips local cache). LAN policies and assignments still come
    from local profile_store (no native router source for the 3-state policy).
    """
    data = ps.load()
    router = _get_router()
    try:
        leases = router.get_dhcp_leases()
        device_ips = {l["mac"].lower(): l.get("ip", "") for l in leases}
    except Exception:
        device_ips = {}
    rules, ipsets = generate_lan_rules(data, device_ips=device_ips)
    for short_id, (macs, ips) in ipsets.items():
        router.lan_sync_group_ipsets(short_id, macs, ips)
    router.lan_rebuild_rules(rules)


def _reconcile_no_internet_rules():
    """Stage 9: Ensure firewall.fvpn_noinet_* rules match local NoInternet assignments.

    The local store is the source of truth for NoInternet group identity (the
    router can't distinguish multiple no_internet groups since the iptables
    DROP rules per device look identical). This reconciles the two sides:

      - For every MAC assigned to a no_internet profile in the local store,
        ensure firewall.fvpn_noinet_<mac>_* exists on the router.
      - For every firewall.fvpn_noinet_<mac>_* on the router NOT matching a
        local no_internet assignment, remove it.

    Called on: session unlock, after api_assign_device when old/new is
    no_internet, after api_delete_profile when a no_internet profile is gone.
    """
    try:
        router = _get_router()
        data = ps.load()
        no_int_profile_ids = {
            p["id"] for p in data.get("profiles", [])
            if p.get("type") == "no_internet"
        }
        should_block = set()
        for mac, pid in data.get("device_assignments", {}).items():
            if pid in no_int_profile_ids:
                should_block.add(mac.lower())

        # Read currently-blocked MACs from router firewall
        raw = router.exec(
            "uci show firewall 2>/dev/null | grep 'fvpn_noinet_' | grep '_drop=rule'"
        )
        currently_blocked = set()
        for line in raw.strip().splitlines():
            # firewall.fvpn_noinet_aabbccddeeff_drop=rule
            if "fvpn_noinet_" not in line:
                continue
            try:
                sec = line.split(".")[1].split("=")[0]
            except IndexError:
                continue
            mac_part = sec.replace("fvpn_noinet_", "").replace("_drop", "").replace("_lan", "")
            if len(mac_part) == 12:
                mac = ":".join(mac_part[i:i + 2] for i in (0, 2, 4, 6, 8, 10)).lower()
                currently_blocked.add(mac)

        leases = []
        try:
            leases = router.get_dhcp_leases()
        except Exception:
            pass
        ip_by_mac = {l["mac"].lower(): l.get("ip", "") for l in leases}

        # Add new blocks
        for mac in should_block - currently_blocked:
            ip = ip_by_mac.get(mac, "")
            if ip:
                try:
                    router.set_device_no_internet(mac, ip)
                    log.info(f"NoInternet reconcile: blocked {mac} ({ip})")
                except Exception as e:
                    log.warning(f"NoInternet reconcile: failed to block {mac}: {e}")

        # Remove stale blocks
        for mac in currently_blocked - should_block:
            try:
                router.remove_device_no_internet(mac)
                log.info(f"NoInternet reconcile: unblocked {mac}")
            except Exception as e:
                log.warning(f"NoInternet reconcile: failed to unblock {mac}: {e}")
    except Exception as e:
        log.error(f"_reconcile_no_internet_rules failed: {e}")


# ── Status / Setup / Unlock ───────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """App status: setup-needed, locked, or unlocked."""
    if not sm.is_setup():
        return jsonify({"status": "setup-needed"})
    if not _session_unlocked:
        return jsonify({"status": "locked"})
    return jsonify({
        "status": "unlocked",
        "proton_logged_in": _get_proton().is_logged_in,
    })


@app.route("/api/setup", methods=["POST"])
def api_setup():
    """First-time setup: store encrypted credentials."""
    data = request.json
    required = ["proton_user", "proton_pass", "router_pass", "master_password"]
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    sm.setup(
        proton_user=data["proton_user"],
        proton_pass=data["proton_pass"],
        router_pass=data["router_pass"],
        master_password=data["master_password"],
        router_ip=data.get("router_ip", "192.168.8.1"),
    )
    return jsonify({"success": True})


@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    """Unlock session with master password."""
    global _session_unlocked
    data = request.json
    if "master_password" not in data:
        return jsonify({"error": "master_password required"}), 400

    try:
        sm.unlock(data["master_password"])
        _session_unlocked = True

        # Start device tracker and poll immediately so devices are ready
        router = _get_router()
        tracker = start_tracker(router)
        tracker.poll_once()

        # Initialize LAN access control chain and rebuild rules
        try:
            router.lan_init_chain()
            _rebuild_lan_rules()
        except Exception as e:
            log.warning(f"LAN access control init failed: {e}")

        # Stage 9: reconcile NoInternet firewall rules with local assignments
        try:
            _reconcile_no_internet_rules()
        except Exception as e:
            log.warning(f"NoInternet reconcile on unlock failed: {e}")

        # Start auto-optimizer (Stage 11: uses live router health via build_profile_list)
        try:
            start_optimizer(
                get_proton=_get_proton,
                get_router=_get_router,
                switch_fn=_switch_server,
                build_profile_list_fn=build_profile_list,
            )
        except Exception as e:
            log.warning(f"Auto-optimizer start failed: {e}")

        return jsonify({"success": True})
    except (ValueError, FileNotFoundError) as e:
        return jsonify({"error": str(e)}), 401


# ── Profiles ──────────────────────────────────────────────────────────────────

def _resolve_server_live(proton, local_profile: dict) -> dict:
    """Stage 7: resolve server info from Proton API by id.

    Reads server_id from local profile (top-level or nested under server.id
    for legacy data), then calls proton.get_server_by_id() to get the live
    server dict (name, country, city, load, etc.). Falls back to the locally
    cached server dict if Proton is unavailable or the server is gone.

    Preserves the cached `endpoint` and `physical_server_domain` fields if
    they exist (these come from the WG/OVPN config generation and aren't
    re-derivable from the Proton server list alone).
    """
    cached = local_profile.get("server") or {}
    server_id = local_profile.get("server_id") or cached.get("id")
    if not server_id:
        return cached
    if not proton or not proton.is_logged_in:
        return cached
    try:
        server_obj = proton.get_server_by_id(server_id)
        if server_obj is None:
            return cached
        live = proton.server_to_dict(server_obj)
        # Preserve fields that come from the physical-server selection at
        # config-generation time (not in the logical server list)
        if cached.get("endpoint"):
            live["endpoint"] = cached["endpoint"]
        if cached.get("physical_server_domain"):
            live["physical_server_domain"] = cached["physical_server_domain"]
        if cached.get("protocol"):
            live["protocol"] = cached["protocol"]
        return live
    except Exception:
        return cached


def _local_router_key(local_profile: dict) -> tuple:
    """Stable key for matching a local profile to a router rule.

    Uses (vpn_protocol, peer_id) for WG and (vpn_protocol, client_id) for OVPN.
    These survive section renames by the GL.iNet UI (which can replace
    fvpn_rule_9001 with @rule[4] but always preserves peer_id/client_id).
    """
    ri = local_profile.get("router_info") or {}
    vpn_protocol = ri.get("vpn_protocol", "wireguard")
    if vpn_protocol == "openvpn":
        # client_id may be stored as '9051' or 'peer_9051' style; normalize
        cid = str(ri.get("client_id", "")).lstrip("peer_").lstrip("client_")
        return ("openvpn", cid)
    pid = str(ri.get("peer_id", "")).lstrip("peer_").lstrip("client_")
    return ("wireguard", pid)


def _router_rule_key(rule: dict) -> tuple:
    """Stable key for a router rule (matches _local_router_key)."""
    via = rule.get("via_type", "wireguard")
    if via == "openvpn":
        return ("openvpn", str(rule.get("client_id", "")))
    return ("wireguard", str(rule.get("peer_id", "")))


def build_profile_list(router, store_data: dict, proton=None) -> list:
    """Build the canonical profile list, merging router state with local metadata.

    Stage 5: This is THE source of truth for `/api/profiles`. It iterates the
    router's route_policy rules first (so manual SSH or GL.iNet UI changes are
    visible) and merges in local UI metadata (color, icon, options, lan_access)
    by matching on the stable (vpn_protocol, peer_id|client_id) key.

    Stage 7: server info (name, country, city, load) is resolved live from
    Proton via server_id rather than read from a local cache. Falls back to
    cached values if Proton is unavailable or the server is gone.

    Self-heals anonymous '@rule[N]' sections back to their fvpn_rule_NNNN names
    when matched to a local profile, so subsequent calls use the canonical name.
    """
    # Index local profiles for quick lookup by (protocol, id)
    local_vpn_by_key = {}
    local_non_vpn = []
    for p in store_data.get("profiles", []):
        if p.get("type") == "vpn":
            key = _local_router_key(p)
            if key[1]:  # only if we have a peer/client id
                local_vpn_by_key[key] = p
        else:
            local_non_vpn.append(p)

    # Live router data — batched into a few SSH calls
    try:
        router_rules = router.get_flint_vpn_rules()  # one SSH call
    except Exception as e:
        log.error(f"build_profile_list: failed to read router rules: {e}")
        router_rules = []

    try:
        vpn_assignments_raw = router.get_device_assignments()  # {mac: rule_name (router section)}
    except Exception:
        vpn_assignments_raw = {}

    vpn_profiles = []
    matched_local_keys = set()
    healed_count = 0
    rule_name_remap = {}  # router section name → canonical fvpn_rule name (for assignment count)

    for rule in router_rules:
        router_section = rule.get("rule_name", "")
        key = _router_rule_key(rule)
        local = local_vpn_by_key.get(key, {})

        # Self-heal: if router has anonymized our section, rename it back
        canonical_rule_name = router_section
        if local and router_section.startswith("@rule"):
            local_section = (local.get("router_info") or {}).get("rule_name", "")
            if local_section and local_section.startswith("fvpn_rule"):
                try:
                    router.heal_anonymous_rule_section(router_section, local_section)
                    canonical_rule_name = local_section
                    healed_count += 1
                    log.info(f"Healed anonymous section {router_section} → {local_section}")
                except Exception as e:
                    log.warning(f"Failed to heal {router_section}: {e}")
        rule_name_remap[router_section] = canonical_rule_name

        if local:
            matched_local_keys.add(key)

        # Tunnel health is per-profile and can't be batched (queries wg show / ifstatus)
        try:
            health = router.get_tunnel_health(canonical_rule_name)
        except Exception:
            health = "loading"

        # router_info bridges local UI and router operations
        ri = local.get("router_info") or {}
        ri = dict(ri)  # don't mutate the local profile
        ri["rule_name"] = canonical_rule_name
        ri["vpn_protocol"] = "openvpn" if rule.get("via_type") == "openvpn" else "wireguard"
        if rule.get("peer_id"):
            ri.setdefault("peer_id", rule["peer_id"])
        if rule.get("client_id"):
            ri.setdefault("client_id", rule["client_id"])

        merged = {
            "id": local.get("id") or canonical_rule_name,
            "type": "vpn",
            "name": rule.get("name") or local.get("name") or canonical_rule_name,
            "color": local.get("color", "#3498db"),
            "icon": local.get("icon", "🔒"),
            "is_guest": local.get("is_guest", False),
            "kill_switch": rule.get("killswitch") == "1",
            "health": health,
            "server": _resolve_server_live(proton, local),
            "server_scope": local.get("server_scope", {"type": "server"}),
            "options": local.get("options", {}),
            "lan_access": local.get("lan_access", {"outbound": "allowed", "inbound": "allowed"}),
            "router_info": ri,
            "device_count": 0,  # filled below
        }
        if not local:
            merged["_orphan"] = True
        vpn_profiles.append(merged)

    # Compute device counts using the (possibly remapped) canonical rule names
    device_counts = {}
    for mac, router_section in vpn_assignments_raw.items():
        canonical = rule_name_remap.get(router_section, router_section)
        device_counts[canonical] = device_counts.get(canonical, 0) + 1
    for p in vpn_profiles:
        p["device_count"] = device_counts.get(p["router_info"]["rule_name"], 0)

    # Ghost: local VPN profile whose router rule no longer exists
    for key, local in local_vpn_by_key.items():
        if key in matched_local_keys:
            continue
        ghost = dict(local)
        ghost["health"] = "red"
        ghost["kill_switch"] = False
        ghost["_ghost"] = True
        ghost.pop("status", None)
        if "lan_access" not in ghost:
            ghost["lan_access"] = {"outbound": "allowed", "inbound": "allowed"}
        ghost["device_count"] = 0
        vpn_profiles.append(ghost)

    # Non-VPN profiles (local-only), sorted by display_order, always rendered after VPN
    non_vpn = sorted(local_non_vpn, key=lambda p: p.get("display_order", 999))
    for p in non_vpn:
        p = dict(p)  # don't mutate the original
        p.pop("status", None)
        p["device_count"] = sum(
            1 for mac, pid in store_data.get("device_assignments", {}).items()
            if pid == p["id"]
        )
        if "lan_access" not in p:
            p["lan_access"] = {"outbound": "allowed", "inbound": "allowed"}
        vpn_profiles.append(p)

    return vpn_profiles


@app.route("/api/profiles")
def api_get_profiles():
    """Get all profiles. Built from router rules + local UI metadata (Stage 5)."""
    err = _require_unlocked()
    if err:
        return err

    router = _get_router()
    proton = _get_proton()
    data = ps.load()
    profiles = build_profile_list(router, data, proton=proton)
    return jsonify(profiles)


@app.route("/api/profiles", methods=["POST"])
def api_create_profile():
    """Create a new profile.

    Body: {name, type, color?, icon?, is_guest?, kill_switch?,
           server_id? (VPN), options? (VPN)}
    """
    err = _require_unlocked()
    if err:
        return err

    MAX_WG_GROUPS = 5
    MAX_OVPN_GROUPS = 5

    data = request.json
    if "name" not in data or "type" not in data:
        return jsonify({"error": "name and type required"}), 400

    profile_type = data["type"]
    vpn_protocol = data.get("vpn_protocol", "wireguard")  # "wireguard" or "openvpn"

    # Enforce VPN group limits per protocol
    if profile_type == "vpn":
        existing_profiles = ps.get_profiles()
        if vpn_protocol == "wireguard":
            count = len([p for p in existing_profiles if p["type"] == "vpn" and p.get("router_info", {}).get("vpn_protocol") != "openvpn"])
            if count >= MAX_WG_GROUPS:
                return jsonify({
                    "error": f"Cannot create more than {MAX_WG_GROUPS} WireGuard VPN groups. "
                    "Try OpenVPN instead (5 additional slots), or delete an existing WireGuard group."
                }), 400
        else:
            count = len([p for p in existing_profiles if p.get("router_info", {}).get("vpn_protocol") == "openvpn"])
            if count >= MAX_OVPN_GROUPS:
                return jsonify({
                    "error": f"Cannot create more than {MAX_OVPN_GROUPS} OpenVPN groups. "
                    "Try WireGuard instead, or delete an existing OpenVPN group."
                }), 400

    router_info = None
    server_info = None

    # For VPN profiles: generate config and upload to router
    if profile_type == "vpn":
        if "server_id" not in data:
            return jsonify({"error": "server_id required for VPN profiles"}), 400

        proton = _get_proton()
        if not proton.is_logged_in:
            return jsonify({"error": "Not logged into ProtonVPN"}), 400

        server = proton.get_server_by_id(data["server_id"])
        options = data.get("options", {})
        router = _get_router()

        try:
          if vpn_protocol == "openvpn":
            # Generate OpenVPN config
            ovpn_proto = data.get("ovpn_protocol", "udp")
            config_str, server_info, ovpn_user, ovpn_pass = proton.generate_openvpn_config(
                server,
                protocol=ovpn_proto,
                netshield=options.get("netshield", 0),
            )

            router_info = router.upload_openvpn_config(
                profile_name=data["name"],
                ovpn_config=config_str,
                username=ovpn_user,
                password=ovpn_pass,
            )
          else:
            # Generate WireGuard config
            config_str, server_info = proton.generate_wireguard_config(
                server,
                netshield=options.get("netshield", 0),
                moderate_nat=options.get("moderate_nat", False),
                nat_pmp=options.get("nat_pmp", False),
                vpn_accelerator=options.get("vpn_accelerator", True),
            )

            # Parse config to extract keys
            lines = config_str.strip().splitlines()
            private_key = public_key = endpoint = ""
            dns = "10.2.0.1"
            for line in lines:
                line = line.strip()
                if line.startswith("PrivateKey"):
                    private_key = line.split("=", 1)[1].strip()
                elif line.startswith("PublicKey"):
                    public_key = line.split("=", 1)[1].strip()
                elif line.startswith("Endpoint"):
                    endpoint = line.split("=", 1)[1].strip()
                elif line.startswith("DNS"):
                    dns = line.split("=", 1)[1].strip()

            router_info = router.upload_wireguard_config(
                profile_name=data["name"],
                private_key=private_key,
                public_key=public_key,
                endpoint=endpoint,
                dns=dns,
            )
        except Exception as e:
            log.error(f"Failed to create VPN profile: {e}", exc_info=True)
            return jsonify({"error": f"Failed to configure router: {e}"}), 500

    profile = ps.create_profile(
        name=data["name"],
        profile_type=profile_type,
        color=data.get("color", "#3498db"),
        icon=data.get("icon", "🔒"),
        is_guest=data.get("is_guest", False),
        server=server_info,
        options=data.get("options"),
        router_info=router_info,
        server_scope=data.get("server_scope"),
    )

    # Apply requested kill_switch state to the router (Stage 3: router is the source of truth).
    # upload_*_config writes killswitch='1' by default; only override if the caller asked for off.
    if profile_type == "vpn" and router_info and router_info.get("rule_name"):
        requested_ks = data.get("kill_switch", True)
        if not requested_ks:
            try:
                router.set_kill_switch(router_info["rule_name"], False)
            except Exception as e:
                log.warning(f"Failed to apply initial kill_switch=False for {profile['name']}: {e}")
        # Reflect live router state in the response
        try:
            profile["kill_switch"] = router.get_kill_switch(router_info["rule_name"])
        except Exception:
            pass

    log.info(f"Created profile '{profile['name']}' (type={profile['type']}, id={profile['id']})")
    return jsonify(profile), 201


@app.route("/api/profiles/reorder", methods=["PUT"])
def api_reorder_profiles():
    """Reorder profiles.

    Stage 10: VPN profile order is router-canonical — `uci reorder` is applied
    to route_policy sections so the router evaluates rules in the same priority
    as displayed in the dashboard. Non-VPN profiles (NoVPN/NoInternet) have no
    router section; their order is stored locally as `display_order`.

    Body: {profile_ids: ["id1", "id2", ...]} — full ordered list including
    both VPN and non-VPN profiles.
    """
    err = _require_unlocked()
    if err:
        return err

    body = request.json or {}
    ids = body.get("profile_ids", [])
    if not ids:
        return jsonify({"error": "profile_ids required"}), 400

    store_data = ps.load()
    # Index local profiles by id
    by_id = {p["id"]: p for p in store_data.get("profiles", [])}

    # Split VPN vs non-VPN, preserving the requested order within each group
    vpn_rule_names = []
    non_vpn_ids = []
    for pid in ids:
        p = by_id.get(pid)
        if not p:
            continue
        if p.get("type") == "vpn":
            rn = (p.get("router_info") or {}).get("rule_name")
            if rn:
                vpn_rule_names.append(rn)
        else:
            non_vpn_ids.append(pid)

    # 1. Apply VPN order to router (source of truth for VPN profile order)
    if vpn_rule_names:
        try:
            router = _get_router()
            router.reorder_vpn_rules(vpn_rule_names)
        except Exception as e:
            log.warning(f"reorder_vpn_rules failed: {e}")

    # 2. Apply non-VPN order to local store via display_order ints
    for i, pid in enumerate(non_vpn_ids):
        p = by_id.get(pid)
        if p:
            p["display_order"] = i
    ps.save(store_data)

    return jsonify({"success": True})


@app.route("/api/profiles/<profile_id>", methods=["PUT"])
def api_update_profile(profile_id):
    """Update profile metadata (name, color, icon, options, kill_switch).

    Kill switch is router-canonical (Stage 3): writes go directly to UCI,
    not to local store.
    """
    err = _require_unlocked()
    if err:
        return err

    data = dict(request.json or {})

    # Pull kill_switch out before writing to local store — it lives on the router only
    new_kill_switch = data.pop("kill_switch", None)

    profile = ps.update_profile(profile_id, **data)
    if profile is None:
        return jsonify({"error": "Profile not found"}), 404

    router = _get_router()
    ri = profile.get("router_info", {})
    rule_name = ri.get("rule_name")

    # Apply kill_switch change to the router (source of truth)
    if new_kill_switch is not None and rule_name:
        try:
            router.set_kill_switch(rule_name, bool(new_kill_switch))
            # Reflect the live router value in the response — never trust the request
            profile["kill_switch"] = router.get_kill_switch(rule_name)
        except Exception as e:
            log.error(f"Failed to set kill switch on {rule_name}: {e}")

    # Sync name to router if this is a VPN profile (Stage 4: router is the source of truth).
    if "name" in data and rule_name:
        try:
            router.rename_profile(
                rule_name=rule_name,
                new_name=data["name"],
                peer_id=ri.get("peer_id", "") if ri.get("vpn_protocol") != "openvpn" else "",
                client_uci_id=ri.get("client_uci_id", "") if ri.get("vpn_protocol") == "openvpn" else "",
            )
            # Reflect the live router name in the response
            profile["name"] = router.get_profile_name(rule_name) or data["name"]
        except Exception as e:
            log.warning(f"Failed to rename profile on router: {e}")

    # Always include live kill_switch in the response so the UI is in sync
    if rule_name:
        try:
            profile["kill_switch"] = router.get_kill_switch(rule_name)
        except Exception:
            pass

    return jsonify(profile)


@app.route("/api/profiles/<profile_id>", methods=["DELETE"])
def api_delete_profile(profile_id):
    """Delete a profile and tear down its tunnel if VPN."""
    err = _require_unlocked()
    if err:
        return err

    profile = ps.get_profile(profile_id)
    if not profile:
        return jsonify({"error": "Profile not found"}), 404

    # Tear down router resources
    router = _get_router()
    if profile["type"] == "vpn" and profile.get("router_info"):
        ri = profile["router_info"]
        try:
            if ri.get("vpn_protocol") == "openvpn":
                router.delete_openvpn_config(
                    ri.get("client_uci_id", ""),
                    ri.get("rule_name", ""),
                )
            else:
                router.delete_wireguard_config(
                    ri.get("peer_id", ""),
                    ri.get("rule_name", ""),
                )
        except Exception:
            pass  # Best effort cleanup

    elif profile["type"] == "no_internet":
        # Remove firewall rules for all assigned devices
        data = ps.load()
        for mac, pid in data["device_assignments"].items():
            if pid == profile_id:
                try:
                    router.remove_device_no_internet(mac)
                except Exception:
                    pass

    log.info(f"Deleted profile '{profile['name']}' (id={profile_id})")

    # Clean up LAN ipsets for this group
    short_id = profile_id[:8]
    try:
        router.lan_destroy_group_ipsets(short_id)
    except Exception:
        pass

    deleted_type = profile["type"]
    ps.delete_profile(profile_id)

    # Rebuild LAN rules (device overrides cleaned up by delete_profile)
    try:
        _rebuild_lan_rules()
    except Exception as e:
        log.warning(f"LAN rule rebuild after delete failed: {e}")

    # Stage 9: reconcile NoInternet firewall rules if a no_internet profile was deleted
    if deleted_type == "no_internet":
        try:
            _reconcile_no_internet_rules()
        except Exception as e:
            log.warning(f"NoInternet reconcile after delete failed: {e}")

    return jsonify({"success": True})


# ── Server Selection ──────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/servers")
def api_get_servers(profile_id):
    """Get ProtonVPN server list for a profile's server picker."""
    err = _require_unlocked()
    if err:
        return err

    proton = _get_proton()
    if not proton.is_logged_in:
        return jsonify({"error": "Not logged into ProtonVPN"}), 400

    country = request.args.get("country")
    city = request.args.get("city")
    feature = request.args.get("feature")

    servers = proton.get_servers(country=country, city=city, feature=feature)
    return jsonify(servers)


_switch_locks = {}  # Per-profile locks to prevent concurrent switches


def _switch_server(profile_id: str, server_id: str, options: dict = None,
                   server_scope: dict = None) -> dict:
    """Core server-switch logic. Used by API endpoint and auto-optimizer.

    Returns the updated profile dict. Raises on error.
    """
    # Per-profile lock to prevent concurrent switches
    if profile_id not in _switch_locks:
        _switch_locks[profile_id] = threading.Lock()
    lock = _switch_locks[profile_id]

    if not lock.acquire(blocking=False):
        raise RuntimeError("Server switch already in progress for this profile")

    try:
        profile = ps.get_profile(profile_id)
        if not profile:
            raise ValueError("Profile not found")
        if profile["type"] != "vpn":
            raise ValueError("Not a VPN profile")

        proton = _get_proton()
        router = _get_router()

        # Capture devices currently assigned to the OLD rule on the router so
        # we can reassign them to the new rule below. Must happen BEFORE the
        # tear-down or the from_mac list is gone.
        old_ri = profile.get("router_info", {})
        old_assigned_macs = []
        if old_ri.get("rule_name"):
            try:
                old_assigned_macs = [
                    t.lower() for t in router._from_mac_tokens(old_ri["rule_name"])
                ]
            except Exception as e:
                log.warning(f"_switch_server: failed to read old from_mac: {e}")

        # Tear down old tunnel
        if old_ri.get("rule_name"):
            try:
                if old_ri.get("vpn_protocol") == "openvpn":
                    router.delete_openvpn_config(
                        old_ri.get("client_uci_id", ""), old_ri["rule_name"]
                    )
                else:
                    router.delete_wireguard_config(
                        old_ri.get("peer_id", ""), old_ri["rule_name"]
                    )
            except Exception:
                pass

        # Generate new config based on protocol
        server = proton.get_server_by_id(server_id)
        opts = options or profile.get("options", {})
        vpn_protocol = old_ri.get("vpn_protocol", "wireguard")

        if vpn_protocol == "openvpn":
            ovpn_proto = "tcp" if profile.get("server", {}).get("protocol", "").endswith("tcp") else "udp"
            config_str, server_info, ovpn_user, ovpn_pass = proton.generate_openvpn_config(
                server, protocol=ovpn_proto, netshield=opts.get("netshield", 0),
            )
            new_ri = router.upload_openvpn_config(
                profile_name=profile["name"], ovpn_config=config_str,
                username=ovpn_user, password=ovpn_pass,
            )
        else:
            config_str, server_info = proton.generate_wireguard_config(
                server, netshield=opts.get("netshield", 0),
                moderate_nat=opts.get("moderate_nat", False),
                nat_pmp=opts.get("nat_pmp", False),
                vpn_accelerator=opts.get("vpn_accelerator", True),
            )
            private_key = public_key = endpoint = dns = ""
            for line in config_str.strip().splitlines():
                line = line.strip()
                if line.startswith("PrivateKey"):
                    private_key = line.split("=", 1)[1].strip()
                elif line.startswith("PublicKey"):
                    public_key = line.split("=", 1)[1].strip()
                elif line.startswith("Endpoint"):
                    endpoint = line.split("=", 1)[1].strip()
                elif line.startswith("DNS"):
                    dns = line.split("=", 1)[1].strip()
            new_ri = router.upload_wireguard_config(
                profile_name=profile["name"], private_key=private_key,
                public_key=public_key, endpoint=endpoint, dns=dns,
            )

        # Re-assign devices from the OLD rule to the NEW rule.
        # Stage 5+: VPN device assignments are router-canonical, not in local
        # store. We must read the OLD rule's from_mac BEFORE deleting it (we
        # already deleted above), so we capture the MACs first below.
        # NOTE: this code path runs AFTER delete_*_config above, which deletes
        # the old rule entirely. So we need to capture the MACs BEFORE the
        # delete. See the rewrite of the tear-down section.
        for mac in old_assigned_macs:
            try:
                router.set_device_vpn(mac, new_ri["rule_name"])
            except Exception as e:
                log.warning(f"_switch_server: failed to reassign {mac}: {e}")

        router.bring_tunnel_up(new_ri["rule_name"])

        scope = server_scope or profile.get("server_scope", {"type": "server"})
        # Stage 7: persist only the server_id reference + minimal cache for
        # endpoint / physical_server_domain / protocol (not in Proton logical list).
        server_cache = {}
        for k in ("id", "endpoint", "physical_server_domain", "protocol"):
            if server_info.get(k):
                server_cache[k] = server_info[k]
        ps.update_profile(
            profile_id,
            server_id=server_info.get("id", ""),
            server=server_cache,
            options=opts,
            router_info=new_ri,
            server_scope=scope,
        )
        return ps.get_profile(profile_id)

    finally:
        lock.release()


@app.route("/api/profiles/<profile_id>/server", methods=["PUT"])
def api_change_server(profile_id):
    """Change the server for a VPN profile.

    Body: {server_id, options?, server_scope?}
    """
    err = _require_unlocked()
    if err:
        return err

    data = request.json
    if "server_id" not in data:
        return jsonify({"error": "server_id required"}), 400

    try:
        profile = _switch_server(
            profile_id, data["server_id"],
            options=data.get("options"),
            server_scope=data.get("server_scope"),
        )
        return jsonify(profile)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 409
    except Exception as e:
        log.error(f"Failed to switch server: {e}", exc_info=True)
        return jsonify({"error": f"Failed to switch server: {e}"}), 500


# ── Tunnel Control ────────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/connect", methods=["POST"])
def api_connect(profile_id):
    """Bring a VPN profile's tunnel up."""
    err = _require_unlocked()
    if err:
        return err

    profile = ps.get_profile(profile_id)
    if not profile or profile["type"] != "vpn":
        return jsonify({"error": "VPN profile not found"}), 404

    ri = profile.get("router_info", {})
    if not ri.get("rule_name"):
        return jsonify({"error": "No tunnel configured. Try changing the server to recreate it."}), 400

    router = _get_router()

    try:
        log.info(f"Connecting profile '{profile['name']}' (rule={ri['rule_name']}, protocol={ri.get('vpn_protocol', 'wireguard')})")
        router.bring_tunnel_up(ri["rule_name"])
        # Read live health from router instead of caching status locally
        try:
            health = router.get_tunnel_health(ri["rule_name"])
        except Exception:
            health = "loading"
        log.info(f"Profile '{profile['name']}' connect issued (health={health})")
        return jsonify({"success": True, "health": health})
    except Exception as e:
        log.error(f"Failed to connect profile '{profile['name']}': {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiles/<profile_id>/disconnect", methods=["POST"])
def api_disconnect(profile_id):
    """Bring a VPN profile's tunnel down."""
    err = _require_unlocked()
    if err:
        return err

    profile = ps.get_profile(profile_id)
    if not profile or profile["type"] != "vpn":
        return jsonify({"error": "VPN profile not found"}), 404

    ri = profile.get("router_info", {})
    if not ri.get("rule_name"):
        return jsonify({"error": "No tunnel configured"}), 400

    router = _get_router()
    try:
        log.info(f"Disconnecting profile '{profile['name']}' (rule={ri['rule_name']})")
        router.bring_tunnel_down(ri["rule_name"])
        log.info(f"Profile '{profile['name']}' disconnected")
        return jsonify({"success": True, "health": "red"})
    except Exception as e:
        log.error(f"Failed to disconnect profile '{profile['name']}': {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiles/<profile_id>/guest", methods=["PUT"])
def api_set_guest(profile_id):
    """Set this profile as the guest profile."""
    err = _require_unlocked()
    if err:
        return err

    if not ps.set_guest_profile(profile_id):
        return jsonify({"error": "Profile not found"}), 404
    return jsonify({"success": True})


# ── Devices ───────────────────────────────────────────────────────────────────

@app.route("/api/devices/<mac>/label", methods=["PUT"])
def api_set_device_label(mac):
    """Set a custom label and/or device class for a device.

    Stage 8: gl-client.alias and gl-client.class are router-canonical.
    No local cache write — _build_devices_live reads them from the router live.

    Body: {label: "Living Room TV", device_class?: "computer"}
    """
    err = _require_unlocked()
    if err:
        return err

    data = request.json or {}
    label = data.get("label", "").strip()
    device_class = data.get("device_class", "")

    try:
        router = _get_router()
        mac_upper = mac.upper()
        existing = router.exec(
            f"uci show gl-client 2>/dev/null | grep -B1 \"mac='{mac_upper}'\" | "
            "grep '=client' | head -1 | cut -d. -f2 | cut -d= -f1"
        ).strip()
        if existing:
            section = existing
        else:
            router.exec(f"uci add gl-client client")
            section = router.exec(
                "uci show gl-client 2>/dev/null | grep '=client' | tail -1 | "
                "cut -d. -f2 | cut -d= -f1"
            ).strip()
            router.exec(f"uci set gl-client.{section}.mac='{mac_upper}'")

        cmds = [f"uci set gl-client.{section}.alias='{label}'"]
        if device_class:
            cmds.append(f"uci set gl-client.{section}.class='{device_class}'")
        cmds.append("uci commit gl-client")
        router.exec(" && ".join(cmds))
    except Exception as e:
        log.error(f"Failed to set device label on router: {e}")
        return jsonify({"error": str(e)}), 500

    # Invalidate cache so next /api/devices call picks up the change
    _invalidate_device_cache()
    return jsonify({"success": True, "label": label, "device_class": device_class})


def _resolve_device_assignments(router, store_data: dict) -> dict:
    """Return {mac: profile_id} merging router VPN assignments + local non-VPN.

    Stage 5: VPN assignments come from router.from_mac (canonical). Matching
    is by stable (vpn_protocol, peer_id|client_id) key — survives section
    renames by the GL.iNet UI.
    Non-VPN/NoInternet assignments come from local profile_store.
    """
    # (protocol, id) → local profile_id  AND  router_section_name → local profile_id
    key_to_pid = {}
    rule_section_to_pid = {}
    for p in store_data.get("profiles", []):
        if p.get("type") == "vpn":
            k = _local_router_key(p)
            if k[1]:
                key_to_pid[k] = p["id"]
            rn = (p.get("router_info") or {}).get("rule_name")
            if rn:
                rule_section_to_pid[rn] = p["id"]

    try:
        rules = router.get_flint_vpn_rules()
    except Exception:
        rules = []
    # router section name → local profile_id, resolved via stable key
    section_to_pid = {}
    for rule in rules:
        section = rule.get("rule_name", "")
        if not section:
            continue
        key = _router_rule_key(rule)
        pid = key_to_pid.get(key) or rule_section_to_pid.get(section)
        if pid:
            section_to_pid[section] = pid

    try:
        vpn_assignments_raw = router.get_device_assignments()
    except Exception:
        vpn_assignments_raw = {}

    out = {}
    for mac, section in vpn_assignments_raw.items():
        pid = section_to_pid.get(section)
        if pid:
            out[mac] = pid
        # Else: orphan rule on router — device shows as unassigned

    # Non-VPN: local store
    for mac, pid in store_data.get("device_assignments", {}).items():
        if pid is None:
            continue
        for p in store_data.get("profiles", []):
            if p.get("id") == pid and p.get("type") != "vpn":
                out[mac] = pid
                break
    return out


# Stage 8: in-memory device cache with short TTL.
# Avoids hammering the router on rapid SSE ticks while keeping the data live.
_device_cache = {"data": None, "ts": 0.0}
_DEVICE_CACHE_TTL = 5  # seconds


def _invalidate_device_cache():
    _device_cache["data"] = None
    _device_cache["ts"] = 0.0


def _build_devices_live(router) -> list:
    """Build the device list from live router data (Stage 8).

    Sources:
      - DHCP leases (router /tmp/dhcp.leases): mac, ip, hostname
      - GL.iNet client tracking (ubus call gl-clients list): online, speeds,
        signal, alias (= user-set label), device_class
      - Router from_mac lists: VPN profile assignment (via _resolve_device_assignments)
      - Local store: non-VPN profile assignment + LAN access overrides

    Hostname / IP / online / class / label / speeds are NEVER cached on disk.
    Display name precedence: gl-client.alias > DHCP hostname > MAC.
    """
    try:
        leases = router.get_dhcp_leases()
    except Exception:
        leases = []
    try:
        client_details = router.get_client_details()
    except Exception:
        client_details = {}

    store_data = ps.load()
    assignment_map = _resolve_device_assignments(router, store_data)

    devices = {}
    for lease in leases:
        mac = lease["mac"].lower()
        devices[mac] = {
            "mac": mac,
            "ip": lease.get("ip", ""),
            "hostname": lease.get("hostname", ""),
            "label": "",
            "device_class": "",
            "profile_id": assignment_map.get(mac),
            "router_online": False,
            "iface": "",
            "rx_speed": 0,
            "tx_speed": 0,
            "total_rx": 0,
            "total_tx": 0,
            "signal_dbm": None,
            "link_speed_mbps": None,
        }

    for mac, details in client_details.items():
        mac = mac.lower()
        d = devices.setdefault(mac, {
            "mac": mac,
            "ip": "",
            "hostname": "",
            "profile_id": assignment_map.get(mac),
        })
        d["router_online"] = bool(details.get("online", False))
        d["device_class"] = details.get("device_class", "")
        d["label"] = details.get("alias", "")  # router-canonical custom label
        d["rx_speed"] = details.get("rx_speed", 0)
        d["tx_speed"] = details.get("tx_speed", 0)
        d["total_rx"] = details.get("total_rx", 0)
        d["total_tx"] = details.get("total_tx", 0)
        d["signal_dbm"] = details.get("signal_dbm")
        d["link_speed_mbps"] = details.get("link_speed_mbps")
        d["iface"] = details.get("iface", "")
        if details.get("ip") and not d.get("ip"):
            d["ip"] = details["ip"]
        # gl-clients exposes a 'name' field (mDNS/Bonjour discovered hostname)
        # for devices not currently in DHCP leases. Use it as a hostname fallback
        # so offline / recently-departed devices still display their name.
        if not d.get("hostname") and details.get("name"):
            d["hostname"] = details["name"]

    # Router-only MACs (e.g. assigned via SSH but never seen via DHCP)
    for mac, pid in assignment_map.items():
        if mac not in devices:
            devices[mac] = {
                "mac": mac, "ip": "", "hostname": "", "label": "",
                "device_class": "", "profile_id": pid, "router_online": False,
                "iface": "", "rx_speed": 0, "tx_speed": 0, "total_rx": 0,
                "total_tx": 0, "signal_dbm": None, "link_speed_mbps": None,
            }

    # Display name precedence and effective LAN access
    out = []
    for mac, d in sorted(devices.items()):
        d["display_name"] = d.get("label") or d.get("hostname") or mac
        eff = ps.get_effective_lan_access(mac, store_data)
        d["lan_outbound"] = eff["outbound"]
        d["lan_inbound"] = eff["inbound"]
        d["lan_inherited"] = eff["inherited"]
        d["last_seen"] = None  # legacy field, no longer tracked
        out.append(d)
    return out


def _get_devices_cached(router) -> list:
    """5-second TTL wrapper around _build_devices_live to throttle SSH calls."""
    now = time.time()
    if _device_cache["data"] is not None and (now - _device_cache["ts"]) < _DEVICE_CACHE_TTL:
        return _device_cache["data"]
    _device_cache["data"] = _build_devices_live(router)
    _device_cache["ts"] = now
    return _device_cache["data"]


@app.route("/api/devices")
def api_get_devices():
    """Get all devices, fetched live from router (Stage 8)."""
    err = _require_unlocked()
    if err:
        return err

    router = _get_router()
    return jsonify(_get_devices_cached(router))


@app.route("/api/devices/<mac>/profile", methods=["PUT"])
def api_assign_device(mac):
    """Assign a device to a profile.

    Body: {profile_id: "uuid" or null}

    Stage 5: VPN assignments are written ONLY to the router (source of truth).
    Non-VPN/NoInternet assignments are written to local profile_store.
    """
    err = _require_unlocked()
    if err:
        return err

    try:
        mac = ps._validate_mac(mac)
    except ValueError:
        return jsonify({"error": f"Invalid MAC address: {mac}"}), 400

    data = request.json
    profile_id = data.get("profile_id")

    router = _get_router()
    store_data = ps.load()

    # Find current assignment from BOTH sources (router for VPN, local for non-VPN)
    current_map = _resolve_device_assignments(router, store_data)
    old_pid = current_map.get(mac)

    # Tear down any existing assignment cleanly
    if old_pid:
        old_profile = ps.get_profile(old_pid)
        if old_profile:
            if old_profile["type"] == "no_internet":
                router.remove_device_no_internet(mac)
            # For VPN: removed below via remove_device_from_all_vpn
    # Always clear any router VPN rule containing this MAC (idempotent)
    try:
        router.remove_device_from_all_vpn(mac)
    except Exception as e:
        log.warning(f"remove_device_from_all_vpn({mac}) failed: {e}")
    # Also clear any local non-VPN assignment
    if mac in store_data.get("device_assignments", {}):
        store_data["device_assignments"][mac] = None
        ps.save(store_data)

    # Apply new assignment
    if profile_id:
        new_profile = ps.get_profile(profile_id)
        if not new_profile:
            return jsonify({"error": "Profile not found"}), 404

        if new_profile["type"] == "vpn" and new_profile.get("router_info"):
            # Router is the source for VPN assignments
            router.set_device_vpn(mac, new_profile["router_info"]["rule_name"])
        elif new_profile["type"] == "no_internet":
            # Local store is the source for assignment; the firewall rule is
            # the execution layer. Look up the device IP from live DHCP leases
            # (Stage 8: no longer cached locally).
            ps.assign_device(mac, profile_id)
            try:
                leases = router.get_dhcp_leases()
                ip = next((l["ip"] for l in leases if l["mac"].lower() == mac), "")
                if ip:
                    router.set_device_no_internet(mac, ip)
            except Exception as e:
                log.warning(f"NoInternet firewall apply for {mac} failed: {e}")
        else:
            # no_vpn — local store only
            ps.assign_device(mac, profile_id)

    target = ps.get_profile(profile_id)["name"] if profile_id and ps.get_profile(profile_id) else "Unassigned"
    log.info(f"Device {mac} assigned to '{target}'")

    # Stage 9: reconcile NoInternet rules if either side touched no_internet
    old_profile = ps.get_profile(old_pid) if old_pid else None
    new_profile_obj = ps.get_profile(profile_id) if profile_id else None
    if (old_profile and old_profile.get("type") == "no_internet") or \
       (new_profile_obj and new_profile_obj.get("type") == "no_internet"):
        try:
            _reconcile_no_internet_rules()
        except Exception as e:
            log.warning(f"NoInternet reconcile after assign failed: {e}")

    # Rebuild LAN rules (device changed groups, effective settings may differ)
    try:
        _rebuild_lan_rules()
    except Exception as e:
        log.warning(f"LAN rule rebuild after assignment failed: {e}")

    # Invalidate the device cache so the next /api/devices call sees the new assignment
    _invalidate_device_cache()

    return jsonify({"success": True})


# ── LAN Access Control ────────────────────────────────────────────────────────

@app.route("/api/profiles/<profile_id>/lan-access", methods=["PUT"])
def api_set_profile_lan_access(profile_id):
    """Set LAN access rules for a profile.

    Body: {"outbound": "allowed"|"group_only"|"blocked",
           "inbound": "allowed"|"group_only"|"blocked"}
    """
    err = _require_unlocked()
    if err:
        return err

    data = request.json
    outbound = data.get("outbound", "allowed")
    inbound = data.get("inbound", "allowed")

    try:
        result = ps.set_profile_lan_access(profile_id, outbound, inbound)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not result:
        return jsonify({"error": "Profile not found"}), 404

    try:
        _rebuild_lan_rules()
    except Exception as e:
        log.warning(f"LAN rule rebuild failed: {e}")

    log.info(f"LAN access for profile '{result['name']}': out={outbound}, in={inbound}")
    return jsonify({"success": True, "lan_access": result.get("lan_access")})


@app.route("/api/devices/<mac>/lan-access", methods=["PUT"])
def api_set_device_lan_access(mac):
    """Set per-device LAN access override.

    Body: {"outbound": "allowed"|"group_only"|"blocked"|null,
           "inbound": "allowed"|"group_only"|"blocked"|null}
    null values mean inherit from group.
    """
    err = _require_unlocked()
    if err:
        return err

    data = request.json
    outbound = data.get("outbound")
    inbound = data.get("inbound")

    try:
        ps.set_device_lan_override(mac, outbound, inbound)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        _rebuild_lan_rules()
    except Exception as e:
        log.warning(f"LAN rule rebuild failed: {e}")

    log.info(f"LAN override for {mac}: out={outbound}, in={inbound}")
    return jsonify({"success": True})


# ── Refresh ───────────────────────────────────────────────────────────────────

@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """Refresh DHCP leases, tunnel handshakes, and server list."""
    err = _require_unlocked()
    if err:
        return err

    tracker = get_tracker()
    if tracker:
        tracker.poll_once()

    return jsonify({"success": True})


# ── SSE Stream ────────────────────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    """Server-Sent Events stream for live tunnel health + device updates.

    Pushes updates every 10 seconds with:
    - Tunnel health per VPN profile (green/amber/red)
    - Device count changes
    """
    def generate():
        sse_tick = 0
        while True:
            sse_tick += 1
            try:
                # Trigger a device tracker poll to refresh client details
                tracker = get_tracker()
                if tracker:
                    tracker.poll_once()

                data = ps.load()
                router = _get_router()
                proton = _get_proton()

                # Build the canonical profile list once per tick — this batches
                # router queries and gives us live health, kill_switch, name,
                # device assignments, and (Stage 7) live Proton server info.
                merged_profiles = build_profile_list(router, data, proton=proton)
                tunnel_health = {}
                kill_switch_state = {}
                profile_names = {}
                for p in merged_profiles:
                    if p.get("type") != "vpn":
                        continue
                    pid = p["id"]
                    if "health" in p:
                        tunnel_health[pid] = p["health"]
                    if "kill_switch" in p:
                        kill_switch_state[pid] = p["kill_switch"]
                    if p.get("name"):
                        profile_names[pid] = p["name"]

                # Rebuild LAN rules if device IPs changed
                if tracker and tracker.lan_rules_stale:
                    try:
                        _rebuild_lan_rules()
                        tracker.lan_rules_stale = False
                    except Exception:
                        pass

                # Check for better servers every 3rd tick (~30s).
                # Eligibility uses live router health from the merged profile list.
                better_servers = {}
                if sse_tick % 3 == 0:
                    try:
                        proton = _get_proton()
                        if proton and proton.is_logged_in:
                            all_servers = proton.get_servers()
                            for p in merged_profiles:
                                if (p.get("type") == "vpn"
                                    and p.get("health") in ("green", "amber")
                                    and p.get("server_scope", {}).get("type") != "server"):
                                    better = find_better_server(p, all_servers)
                                    if better:
                                        better_servers[p["id"]] = {
                                            "id": better["id"],
                                            "name": better["name"],
                                            "city": better.get("city", ""),
                                            "country_code": better["country_code"],
                                            "load": better["load"],
                                            "current_load": p.get("server", {}).get("load", 0),
                                        }
                    except Exception:
                        pass

                # Stage 8: device list is fully live from router (DHCP + gl-clients).
                # Cache invalidation: refresh on every SSE tick (10s) so the SSE
                # always reflects the latest device state.
                _invalidate_device_cache()
                all_devices = _get_devices_cached(router)

                event_data = {
                    "tunnel_health": tunnel_health,
                    "kill_switch": kill_switch_state,
                    "profile_names": profile_names,
                    "better_servers": better_servers,
                    "devices": all_devices,
                    "device_count": len(all_devices),
                    "timestamp": time.time(),
                }
                yield f"data: {json.dumps(event_data)}\n\n"
            except Exception:
                yield f"data: {json.dumps({'error': 'update failed'})}\n\n"

            time.sleep(10)

    return Response(generate(), mimetype="text/event-stream")


# ── Logs ──────────────────────────────────────────────────────────────────────

@app.route("/api/logs")
def api_get_logs():
    """Get available log files."""
    err = _require_unlocked()
    if err:
        return err

    logs = []
    for f in sorted(LOG_DIR.glob("*.log")):
        logs.append({
            "name": f.name,
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return jsonify(logs)


@app.route("/api/logs/<name>")
def api_get_log_content(name):
    """Get the last N lines of a log file.

    Query params: lines (default 100)
    """
    err = _require_unlocked()
    if err:
        return err

    # Sanitize filename
    if "/" in name or ".." in name or not name.endswith(".log"):
        return jsonify({"error": "Invalid log name"}), 400

    log_file = LOG_DIR / name
    if not log_file.exists():
        return jsonify({"error": "Log not found"}), 404

    lines = int(request.args.get("lines", 200))
    try:
        all_lines = log_file.read_text().splitlines()
        tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
        return jsonify({
            "name": name,
            "total_lines": len(all_lines),
            "lines": tail,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs/<name>", methods=["DELETE"])
def api_clear_log(name):
    """Clear a log file."""
    err = _require_unlocked()
    if err:
        return err

    if "/" in name or ".." in name or not name.endswith(".log"):
        return jsonify({"error": "Invalid log name"}), 400

    log_file = LOG_DIR / name
    if log_file.exists():
        log_file.write_text("")
    return jsonify({"success": True})


# ── Settings ──────────────────────────────────────────────────────────────────

@app.route("/api/settings")
def api_get_settings():
    """Get non-sensitive config."""
    return jsonify(sm.get_config())


@app.route("/api/settings", methods=["PUT"])
def api_update_settings():
    """Update non-sensitive config (router_ip etc)."""
    data = request.json
    config = sm.update_config(**data)

    # Reset router API if IP changed
    global _router_api
    _router_api = None

    return jsonify(config)


@app.route("/api/settings/credentials", methods=["PUT"])
def api_update_credentials():
    """Update encrypted credentials."""
    err = _require_unlocked()
    if err:
        return err

    data = request.json
    master_password = data.pop("master_password", None)
    if not master_password:
        return jsonify({"error": "master_password required"}), 400

    try:
        sm.update(master_password, **data)
        return jsonify({"success": True})
    except (ValueError, KeyError) as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/settings/master-password", methods=["PUT"])
def api_change_master_password():
    """Change the master password.

    Body: {old_password, new_password}
    """
    err = _require_unlocked()
    if err:
        return err

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"error": "Both old_password and new_password required"}), 400

    if len(new_password) < 4:
        return jsonify({"error": "New password too short (minimum 4 characters)"}), 400

    try:
        sm.change_master_password(old_password, new_password)
        log.info("Master password changed")
        return jsonify({"success": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── Static Files ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard."""
    return send_from_directory("static", "index.html")


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)

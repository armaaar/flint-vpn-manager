"""Split VPN Service — CRUD, credentials, runtime install and tunnel control.

A split VPN is a third-party VPN (currently Barracuda CloudGen / TINA) that
runs on the router and carries only selected destinations for selected
groups; the groups keep their Proton tunnel for everything else. See
``router/facades/split_vpn.py`` for the router-side design and
``docs/internals/split-vpn-internals.md``.

Storage:
  * ``config.json`` → ``split_vpns.vpns``: settings + last pushed routes/DNS
  * ``secrets.enc`` → ``split_vpn_credentials``: {vpn_id: {password, totp}}
    where ``totp`` is the parsed TOTP secret. Writing it needs the master
    password; after unlock the credentials live in memory only.
  * One-time codes are generated on demand from the TOTP secret (or passed
    explicitly) and never stored.
"""

from __future__ import annotations

import hashlib
import io
import logging
import lzma
import tarfile
import threading
import time
import urllib.request
import uuid
from typing import TYPE_CHECKING

import persistence.secrets_manager as sm
from consts import (
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_VPN,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
    SPLITVPN_MAX,
    SPLITVPN_RUNTIME,
    SPLITVPN_TYPES,
)
from router.facades.split_vpn import build_client_config, normalize_cidr, _SAFE_DOMAIN_RE
from vpn.totp import parse_totp, seconds_left, totp_code

if TYPE_CHECKING:
    from router.api import RouterAPI

log = logging.getLogger(__name__)

_CONNECTED_STATES = {"CONNECTED", "ESTABLISHED", "UP", "ONLINE"}
_EDITABLE = ("name", "server", "port", "tunnel_mode", "username", "group_ids",
             "domains", "cidrs", "use_pushed_routes", "enabled", "auto_connect")
# Don't submit a code that expires mid-handshake (emulated client + AD auth)
_MIN_CODE_LIFETIME = 10
# Auto-reconnect monitor
_MONITOR_INTERVAL = 60
_BACKOFF_START = 120
_BACKOFF_MAX = 3600


class SplitVpnService:
    def __init__(self, router: RouterAPI):
        self.router = router
        self._creds: dict[str, dict] = {}
        self._lock = threading.RLock()          # serialises connect/disconnect
        self._monitor: threading.Thread | None = None
        self._stop = threading.Event()
        self._backoff: dict[str, tuple[float, float]] = {}  # id -> (next_try, delay)

    # ── Secrets ───────────────────────────────────────────────────────────

    def load_secrets(self, secrets: dict) -> None:
        """Called on unlock with the decrypted secrets."""
        self._creds = {k: dict(v) for k, v in (secrets.get("split_vpn_credentials") or {}).items()}

    def _save_credentials(self, vpn_id: str, master_password: str,
                          password: str | None = None, totp: dict | None = None,
                          delete: bool = False) -> None:
        if not master_password:
            raise ValueError("Master password is required to store VPN credentials")
        try:
            secrets = sm.unlock(master_password)
        except ValueError as e:
            raise ValueError("Wrong master password") from e
        creds = {k: dict(v) for k, v in (secrets.get("split_vpn_credentials") or {}).items()}
        if delete:
            creds.pop(vpn_id, None)
        else:
            entry = creds.setdefault(vpn_id, {})
            if password is not None:
                entry["password"] = password
            if totp is not None:
                entry["totp"] = totp
        sm.update(master_password, split_vpn_credentials=creds)
        self._creds = creds

    def _forget_credentials(self, vpn_id: str) -> None:
        """Drop from memory; the encrypted copy is removed on the next save
        that has the master password (stale entries are harmless)."""
        self._creds.pop(vpn_id, None)

    # ── Read ──────────────────────────────────────────────────────────────

    def _vpns(self) -> list[dict]:
        return list(sm.get_config().get("split_vpns", {}).get("vpns", []))

    def _save_vpns(self, vpns: list[dict]) -> None:
        config = sm.get_config()
        sv = config.get("split_vpns", {})
        sv["vpns"] = vpns
        sm.update_config(split_vpns=sv)

    def _find(self, vpn_id: str) -> dict:
        for v in self._vpns():
            if v["id"] == vpn_id:
                return v
        raise ValueError(f"Split VPN not found: {vpn_id}")

    def _public(self, vpn: dict, live: dict | None = None) -> dict:
        out = {k: v for k, v in vpn.items()}
        creds = self._creds.get(vpn["id"], {})
        out["has_password"] = bool(creds.get("password"))
        out["has_totp"] = bool(creds.get("totp"))
        if live is not None:
            out["status"] = live
        return out

    def get_overview(self, live: bool = True) -> dict:
        vpns = []
        for v in self._vpns():
            st = None
            if live:
                try:
                    st = self.router.split_vpn.status(v["slot"])
                    st["connected"] = _is_connected(st)
                except Exception as e:
                    st = {"state": "UNKNOWN", "error": str(e), "connected": False}
            vpns.append(self._public(v, st))
        return {"vpns": vpns, "runtime": self.runtime_status(), "max": SPLITVPN_MAX}

    def runtime_status(self) -> dict:
        try:
            hashes = self.router.split_vpn.runtime_status()
        except Exception as e:
            return {"installed": False, "error": str(e)}
        files = {}
        for name, spec in SPLITVPN_RUNTIME.items():
            files[name] = hashes.get(name) == spec["binary_sha256"]
        return {"installed": all(files.values()), "files": files}

    # ── CRUD ──────────────────────────────────────────────────────────────

    def create(self, data: dict) -> dict:
        vpns = self._vpns()
        used = {v["slot"] for v in vpns}
        free = [s for s in range(SPLITVPN_MAX) if s not in used]
        if not free:
            raise ValueError(f"At most {SPLITVPN_MAX} split VPNs are supported")
        vpn = {
            "id": f"sv_{uuid.uuid4().hex[:8]}",
            "type": data.get("type", "barracuda"),
            "slot": free[0],
            "name": "",
            "server": "",
            "port": 691,
            "tunnel_mode": "TCP",
            "username": "",
            "group_ids": [],
            "domains": [],
            "cidrs": [],
            "use_pushed_routes": True,
            "enabled": True,
            "auto_connect": True,
            "pushed_routes": [],
            "pushed_dns": [],
        }
        self._apply_fields(vpn, data)
        if vpn["type"] not in SPLITVPN_TYPES:
            raise ValueError(f"Unsupported VPN type: {vpn['type']}")
        password = data.get("password")
        if not password:
            raise ValueError("password is required")
        totp = parse_totp(data["totp_secret"]) if data.get("totp_secret") else None
        self._save_credentials(vpn["id"], data.get("master_password", ""), password=password, totp=totp)
        self.router.split_vpn.write_client_config(vpn["slot"], vpn)
        vpns.append(vpn)
        self._save_vpns(vpns)
        self.reapply_all()
        log.info(f"Split VPN '{vpn['name']}' created (slot {vpn['slot']})")
        return self._public(vpn)

    def update(self, vpn_id: str, data: dict) -> dict:
        vpns = self._vpns()
        vpn = next((v for v in vpns if v["id"] == vpn_id), None)
        if not vpn:
            raise ValueError(f"Split VPN not found: {vpn_id}")
        self._apply_fields(vpn, data)
        if data.get("password") or data.get("totp_secret"):
            totp = parse_totp(data["totp_secret"]) if data.get("totp_secret") else None
            self._save_credentials(vpn_id, data.get("master_password", ""),
                                   password=data.get("password") or None, totp=totp)
        self.router.split_vpn.write_client_config(vpn["slot"], vpn)
        self._save_vpns(vpns)
        self.reapply_all()
        log.info(f"Split VPN '{vpn['name']}' updated")
        return self._public(vpn)

    def delete(self, vpn_id: str) -> dict:
        vpns = self._vpns()
        vpn = next((v for v in vpns if v["id"] == vpn_id), None)
        if not vpn:
            raise ValueError(f"Split VPN not found: {vpn_id}")
        try:
            self.router.split_vpn.disconnect(vpn["slot"], teardown=True)
        except Exception as e:
            log.warning(f"Split VPN teardown failed: {e}")
        self.router.split_vpn.remove_slot_files(vpn["slot"])
        vpns = [v for v in vpns if v["id"] != vpn_id]
        self._save_vpns(vpns)
        self._forget_credentials(vpn_id)
        self._backoff.pop(vpn_id, None)
        self.reapply_all()
        log.info(f"Split VPN '{vpn['name']}' deleted")
        return {"success": True}

    def _apply_fields(self, vpn: dict, data: dict) -> None:
        for key in _EDITABLE:
            if key in data:
                vpn[key] = data[key]
        vpn["name"] = str(vpn.get("name", "")).strip()[:64]
        vpn["username"] = str(vpn.get("username", "")).strip()
        vpn["server"] = str(vpn.get("server", "")).strip()
        vpn["tunnel_mode"] = str(vpn.get("tunnel_mode") or "TCP").upper()
        vpn["port"] = int(vpn.get("port") or 691)
        if not vpn["name"]:
            raise ValueError("name is required")
        if not vpn["username"]:
            raise ValueError("username is required")
        build_client_config(vpn)  # validates server / port / mode
        vpn["group_ids"] = self._validate_groups(vpn.get("group_ids") or [])
        domains = []
        for d in vpn.get("domains") or []:
            d = str(d).strip().strip(".").lower()
            if not d:
                continue
            if not _SAFE_DOMAIN_RE.match(d):
                raise ValueError(f"Invalid domain: {d}")
            if d not in domains:
                domains.append(d)
        vpn["domains"] = domains
        cidrs = []
        for c in vpn.get("cidrs") or []:
            if not str(c).strip():
                continue
            n = normalize_cidr(c)
            if not n:
                raise ValueError(f"Invalid IPv4 network (default routes not allowed): {c}")
            if n not in cidrs:
                cidrs.append(n)
        vpn["cidrs"] = cidrs
        vpn["use_pushed_routes"] = bool(vpn.get("use_pushed_routes", True))
        vpn["enabled"] = bool(vpn.get("enabled", True))
        vpn["auto_connect"] = bool(vpn.get("auto_connect", True))

    @staticmethod
    def _validate_groups(group_ids: list) -> list[str]:
        import persistence.profile_store as ps
        profiles = {p["id"]: p for p in ps.load().get("profiles", [])}
        out = []
        for gid in group_ids:
            p = profiles.get(gid)
            if not p:
                raise ValueError(f"Group not found: {gid}")
            if p.get("type") not in (PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN):
                raise ValueError(f"Group '{p.get('name', gid)}' has no internet access")
            if gid not in out:
                out.append(gid)
        return out

    # ── Tunnel control ────────────────────────────────────────────────────

    def connect(self, vpn_id: str, otp: str | None = None) -> dict:
        """Connect. Without ``otp`` the code is generated from the stored
        TOTP secret (waiting for a fresh window if the current code is about
        to expire)."""
        with self._lock:
            vpn = self._find(vpn_id)
            creds = self._creds.get(vpn_id, {})
            password = creds.get("password")
            if not password:
                raise ValueError("No stored password for this VPN — edit it and enter the password")
            otp = str(otp or "").strip()
            if not otp:
                totp = creds.get("totp")
                if not totp:
                    raise ValueError("No TOTP secret stored — add it to the VPN or pass a one-time code")
                left = seconds_left(totp)
                if left < _MIN_CODE_LIFETIME:
                    time.sleep(left + 0.5)
                otp = totp_code(totp)
            if not self.runtime_status().get("installed"):
                raise ValueError("The VPN client runtime is not installed on the router")
            self.router.split_vpn.write_client_config(vpn["slot"], vpn)
            log.info(f"Split VPN '{vpn['name']}' connecting")
            result = self.router.split_vpn.connect(vpn["slot"], vpn["username"], password, otp)
            result["connected"] = _is_connected(result)
            if result["connected"]:
                self._record_pushed(vpn_id, result)
                self._backoff.pop(vpn_id, None)
                log.info(
                    f"Split VPN '{vpn['name']}' connected: ip={result.get('ip')} "
                    f"routes={result.get('routes')} dns={result.get('dns')}"
                )
            else:
                log.warning(f"Split VPN '{vpn['name']}' failed to connect (state={result.get('state')})")
            self.reapply_all()
            return result

    def disconnect(self, vpn_id: str) -> dict:
        with self._lock:
            vpn = self._find(vpn_id)
            self.router.split_vpn.disconnect(vpn["slot"], teardown=True)
            # a manual disconnect pauses auto-reconnect until the next connect
            self._backoff[vpn_id] = (float("inf"), _BACKOFF_START)
        log.info(f"Split VPN '{vpn['name']}' disconnected")
        return {"success": True}

    def get_log(self, vpn_id: str) -> dict:
        vpn = self._find(vpn_id)
        return {"log": self.router.split_vpn.connect_log(vpn["slot"], 200)}

    def _record_pushed(self, vpn_id: str, status: dict) -> None:
        vpns = self._vpns()
        for v in vpns:
            if v["id"] == vpn_id:
                v["pushed_routes"] = list(status.get("routes") or [])
                v["pushed_dns"] = list(status.get("dns") or [])
                v["last_connected_at"] = int(time.time())
        self._save_vpns(vpns)

    # ── Routing (re)application ───────────────────────────────────────────

    def reapply_all(self) -> None:
        """Rebuild host routing + DNS for all enabled split VPNs. Called on
        unlock and after every change. Applied whether or not the tunnel is
        up: marked traffic fails closed (blackhole) while it's down."""
        from services.vpn_bypass_service import build_group_ipset_map

        vpns = [v for v in self._vpns() if v.get("enabled") and v.get("group_ids")]
        if not vpns:
            self.router.split_vpn.apply_routing([])
            return
        group_map = build_group_ipset_map(self.router)
        iface_map = self._dnsmasq_iface_map()
        instances = []
        for v in vpns:
            cidrs = list(v.get("cidrs") or [])
            if v.get("use_pushed_routes", True):
                cidrs += v.get("pushed_routes") or []
            instances.append({
                "slot": v["slot"],
                "group_ipsets": [group_map[g] for g in v["group_ids"] if g in group_map],
                "cidrs": cidrs,
                "dns_servers": list(v.get("pushed_dns") or []),
                "domains": list(v.get("domains") or []),
                "dnsmasq_ifaces": sorted({iface_map[g] for g in v["group_ids"] if g in iface_map}),
            })
        self.router.split_vpn.apply_routing(instances)

    def _dnsmasq_iface_map(self) -> dict[str, str]:
        """profile_id → dnsmasq instance serving that group's devices."""
        import persistence.profile_store as ps
        result: dict[str, str] = {}
        try:
            rp_rules = self.router.uci.show("route_policy")
        except Exception:
            rp_rules = {}
        for p in ps.load().get("profiles", []):
            ptype = p.get("type")
            if ptype == PROFILE_TYPE_NO_VPN:
                result[p["id"]] = "main"
            elif ptype == PROFILE_TYPE_VPN:
                ri = p.get("router_info") or {}
                if ri.get("vpn_protocol") in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS):
                    if ri.get("tunnel_name"):
                        result[p["id"]] = ri["tunnel_name"]
                else:
                    via = rp_rules.get(ri.get("rule_name", ""), {}).get("via", "")
                    if via and via != "novpn":
                        result[p["id"]] = via
        return result

    def on_group_deleted(self, profile_id: str) -> None:
        vpns = self._vpns()
        changed = False
        for v in vpns:
            if profile_id in v.get("group_ids", []):
                v["group_ids"] = [g for g in v["group_ids"] if g != profile_id]
                changed = True
        if changed:
            self._save_vpns(vpns)
            self.reapply_all()

    # ── Auto-connect monitor ──────────────────────────────────────────────

    def start_monitor(self) -> None:
        """Start the background loop that (re)connects ``auto_connect`` VPNs
        whose tunnel is down. Called on unlock."""
        if self._monitor and self._monitor.is_alive():
            return
        self._stop.clear()
        self._monitor = threading.Thread(target=self._monitor_loop, name="split-vpn-monitor", daemon=True)
        self._monitor.start()

    def stop_monitor(self) -> None:
        self._stop.set()

    def _monitor_loop(self) -> None:
        # first pass shortly after unlock, then every _MONITOR_INTERVAL
        if self._stop.wait(5):
            return
        while not self._stop.is_set():
            try:
                self.check_and_reconnect()
            except Exception as e:
                log.warning(f"Split VPN monitor error: {e}")
            if self._stop.wait(_MONITOR_INTERVAL):
                return

    def check_and_reconnect(self, now: float | None = None) -> list[str]:
        """One monitor pass. Returns the ids it tried to connect."""
        now = time.time() if now is None else now
        tried = []
        for v in self._vpns():
            vid = v["id"]
            creds = self._creds.get(vid, {})
            if not (v.get("enabled") and v.get("auto_connect", True)
                    and creds.get("password") and creds.get("totp")):
                continue
            next_try, delay = self._backoff.get(vid, (0.0, _BACKOFF_START))
            if now < next_try:
                continue
            try:
                st = self.router.split_vpn.status(v["slot"])
            except Exception as e:
                log.warning(f"Split VPN '{v['name']}' status check failed: {e}")
                continue
            if _is_connected(st):
                continue
            tried.append(vid)
            log.info(f"Split VPN '{v['name']}' is down — auto-connecting")
            try:
                ok = self.connect(vid).get("connected")
            except Exception as e:
                log.warning(f"Split VPN '{v['name']}' auto-connect error: {e}")
                ok = False
            if not ok:
                # exponential backoff so a wrong password/secret can't lock the account
                self._backoff[vid] = (time.time() + delay, min(delay * 2, _BACKOFF_MAX))
        return tried

    # ── Runtime install ───────────────────────────────────────────────────

    def install_runtime(self) -> dict:
        """Download the pinned emulator + client, verify, upload to router."""
        for name, spec in SPLITVPN_RUNTIME.items():
            log.info(f"Split VPN runtime: fetching {name}")
            archive = _download(spec["url"], spec["sha256"])
            binary = _extract_member(spec["url"], archive, spec["member"])
            if hashlib.sha256(binary).hexdigest() != spec["binary_sha256"]:
                raise ValueError(f"Checksum mismatch for extracted {name}")
            self.router.split_vpn.install_runtime_file(name, binary)
        status = self.runtime_status()
        log.info(f"Split VPN runtime installed: {status}")
        return status


_DOWN_STATES = {"DOWN", "DISCONNECTED", "CONNECTING", "RECONNECTING", "UNKNOWN"}


def _is_connected(status: dict) -> bool:
    """The client's exact state wording isn't documented, so a tunnel IP
    with a non-down state also counts as connected."""
    state = str(status.get("state", "")).upper()
    if state in _CONNECTED_STATES:
        return True
    return bool(status.get("ip")) and state not in _DOWN_STATES


def _download(url: str, sha256: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "flint-vpn-manager"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise ValueError(f"Checksum mismatch for {url}: {digest}")
    return data


def _extract_member(url: str, data: bytes, member: str) -> bytes:
    if url.endswith(".deb"):
        return _extract_from_deb(data, member)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        f = tf.extractfile(member)
        if f is None:
            raise ValueError(f"{member} not found in archive")
        return f.read()


def _extract_from_deb(data: bytes, member: str) -> bytes:
    """Minimal ``ar`` reader → data.tar.* → member."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("Not a .deb archive")
    pos = 8
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        body = data[pos + 60:pos + 60 + size]
        if name.startswith("data.tar"):
            raw = lzma.decompress(body) if name.endswith(".xz") else body
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                f = tf.extractfile(member)
                if f is None:
                    raise ValueError(f"{member} not found in package")
                return f.read()
        pos += 60 + size + (size % 2)
    raise ValueError("data.tar not found in .deb")

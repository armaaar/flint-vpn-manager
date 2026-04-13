"""Profile Service — Profile CRUD and mutation operations.

Handles create, update, delete, change_type, change_protocol,
switch_server, reorder, and guest assignment. Uses callbacks for
cross-cutting concerns (sync, smart protocol cancellation) to avoid
circular dependencies with VPNService.

Extracted from VPNService to separate profile lifecycle logic from
tunnel control, device management, and sync orchestration.
"""

import logging
import threading

import persistence.profile_store as ps
from consts import (
    PROFILE_TYPE_VPN,
    PROFILE_TYPE_NO_VPN,
    PROFILE_TYPE_NO_INTERNET,
    PROTO_OPENVPN,
    PROTO_WIREGUARD,
    PROTO_WIREGUARD_TCP,
    PROTO_WIREGUARD_TLS,
)
from vpn.tunnel_strategy import get_strategy
from vpn.protocol_limits import require_protocol_slot

log = logging.getLogger("flintvpn")


# ── Module-level helpers ────────────────────────────────────────────────────


class NotFoundError(Exception):
    pass


class ConflictError(Exception):
    pass


class LimitExceededError(Exception):
    pass


class NotLoggedInError(Exception):
    pass


def require_vpn_profile(profile_id):
    """Load a profile and validate it exists and is VPN type.

    Returns the profile dict.

    Raises:
        NotFoundError: If the profile is not found.
        ValueError: If the profile is not a VPN profile.
    """
    profile = ps.get_profile(profile_id)
    if not profile:
        raise NotFoundError("Profile not found")
    if profile["type"] != PROFILE_TYPE_VPN:
        raise ValueError("Not a VPN profile")
    return profile


# ── ProfileService ──────────────────────────────────────────────────────────


class ProfileService:
    """Profile CRUD and mutation operations.

    Uses callbacks for cross-cutting concerns that live in VPNService:
    - cancel_smart_fn: cancel smart protocol monitoring before mutations
    - sync_noint_fn: reconcile NoInternet ipset after type/protocol changes
    - sync_adblock_fn: reconcile adblock ipset after create/update/delete
    - reconcile_ipset_fn: re-add proton-wg ipset members after vpn-client restart
    """

    def __init__(self, router, proton, ipset, switch_locks,
                 cancel_smart_fn, sync_noint_fn, sync_adblock_fn,
                 reconcile_ipset_fn):
        self.router = router
        self.proton = proton
        self._ipset = ipset
        self._switch_locks = switch_locks
        self._cancel_smart = cancel_smart_fn
        self._sync_noint = sync_noint_fn
        self._sync_adblock = sync_adblock_fn
        self._reconcile_ipset = reconcile_ipset_fn

    # ── Private helpers ─────────────────────────────────────────────────────

    def _acquire_lock(self, profile_id, blocking=True):
        """Acquire the per-profile switch lock.

        Returns the lock on success.

        Raises:
            RuntimeError: If non-blocking and lock is already held.
        """
        lock = self._switch_locks.setdefault(profile_id, threading.RLock())
        if blocking:
            lock.acquire()
        elif not lock.acquire(blocking=False):
            raise RuntimeError("Another operation is in progress for this profile")
        return lock

    def _create_tunnel(self, vpn_protocol, name, server, opts):
        """Create a tunnel via the appropriate strategy.

        Returns (router_info, server_info, wg_key, cert_expiry).

        Raises:
            RuntimeError: If tunnel creation fails.
        """
        wg_transport = {PROTO_WIREGUARD_TCP: "tcp", PROTO_WIREGUARD_TLS: "tls"}.get(vpn_protocol, "udp")
        strategy = get_strategy(vpn_protocol)
        try:
            return strategy.create(
                self.router, self.proton, name, server, opts,
                transport=wg_transport,
            )
        except Exception as e:
            log.error(f"Tunnel creation failed: {e}", exc_info=True)
            raise RuntimeError(f"Failed to configure router: {e}") from e

    def _teardown_tunnel(self, router_info):
        """Best-effort tunnel teardown via strategy.delete."""
        proto = router_info.get("vpn_protocol", PROTO_WIREGUARD)
        try:
            strategy = get_strategy(proto)
            strategy.delete(self.router, router_info)
        except Exception as e:
            log.warning(f"Tunnel teardown failed: {e}")

    def _reassign_devices(self, macs, router_info):
        """Re-assign a list of MACs to a new tunnel (after protocol change or type change)."""
        is_proton_wg = router_info.get("vpn_protocol", "").startswith("wireguard-")
        for mac in macs:
            try:
                if is_proton_wg:
                    ipset_name = router_info.get("ipset_name", f"src_mac_{router_info.get('tunnel_id', 0)}")
                    self._ipset.ensure_and_add(ipset_name, mac)
                else:
                    self.router.devices.set_device_vpn(mac, router_info["rule_name"])
            except Exception as e:
                log.warning(f"Device reassign {mac} failed: {e}")

    def _persist_tunnel_update(self, profile_id, router_info, server_info,
                               wg_key, cert_expiry, opts, server_scope=None,
                               clear_wg_key=False):
        """Persist tunnel fields to local profile store after create/switch/protocol change."""
        server_cache = {}
        for k in ("id", "endpoint", "physical_server_domain", "protocol"):
            if server_info.get(k):
                server_cache[k] = server_info[k]

        update_kwargs = {
            "router_info": router_info,
            "server_id": server_info.get("id", ""),
            "server": server_cache,
            "options": opts,
        }
        if server_scope is not None:
            update_kwargs["server_scope"] = ps.normalize_server_scope(server_scope)
        if wg_key:
            update_kwargs["wg_key"] = wg_key
        if cert_expiry:
            update_kwargs["cert_expiry"] = cert_expiry
        if clear_wg_key:
            update_kwargs["wg_key"] = None
            update_kwargs["cert_expiry"] = None
        ps.update_profile(profile_id, **update_kwargs)

    def _sync_lan_state(self, sync_noint=True, sync_adblock=False):
        """Post-mutation LAN state sync. Best-effort, never propagates."""
        if sync_noint:
            try:
                self._sync_noint()
            except Exception as e:
                log.warning(f"NoInternet sync failed: {e}")
        if sync_adblock:
            try:
                self._sync_adblock()
            except Exception:
                pass

    # ── Profile CRUD ────────────────────────────────────────────────────────

    def create_profile(self, name, profile_type, vpn_protocol=PROTO_WIREGUARD,
                       server_id=None, options=None, color="#3498db",
                       icon="\U0001f512", is_guest=False, kill_switch=True,
                       server_scope=None, ovpn_protocol="udp", adblock=False):
        """Create a new profile (VPN, NoVPN, or NoInternet).

        Raises:
            LimitExceededError: If the per-protocol group limit is exceeded.
            NotLoggedInError: If Proton is not logged in (VPN profiles).
            ValueError: If required fields are missing.
            RuntimeError: If router config upload fails.
        """
        is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)

        # Enforce VPN group limits per protocol
        if profile_type == PROFILE_TYPE_VPN:
            require_protocol_slot(vpn_protocol)

        router_info = None
        server_info = None
        wg_key = None
        cert_expiry = None

        # For VPN profiles: generate config and upload to router
        if profile_type == PROFILE_TYPE_VPN:
            if not server_id:
                raise ValueError("server_id required for VPN profiles")
            if not self.proton.is_logged_in:
                raise NotLoggedInError("Not logged into ProtonVPN")

            server = self.proton.get_server_by_id(server_id)
            opts = options or {}
            opts["ovpn_protocol"] = ovpn_protocol

            router_info, server_info, wg_key, cert_expiry = self._create_tunnel(
                vpn_protocol, name, server, opts,
            )

        # wg_key + cert_expiry are set for WG profiles (persistent cert path)
        extra_fields = {}
        if profile_type == PROFILE_TYPE_VPN and vpn_protocol.startswith("wireguard") and wg_key:
            extra_fields["wg_key"] = wg_key
            extra_fields["cert_expiry"] = cert_expiry

        profile = ps.create_profile(
            name=name,
            profile_type=profile_type,
            color=color,
            icon=icon,
            is_guest=is_guest,
            server=server_info,
            options=options,
            router_info=router_info,
            server_scope=ps.normalize_server_scope(server_scope),
            adblock=adblock,
            **extra_fields,
        )

        # Apply requested kill_switch state to the router (router is the source of truth).
        # proton-wg profiles always have kill switch on (blackhole route) -- skip UCI operations.
        if profile_type == PROFILE_TYPE_VPN and router_info and router_info.get("rule_name") and not is_proton_wg:
            if not kill_switch:
                try:
                    self.router.policy.set_kill_switch(router_info["rule_name"], False)
                except Exception as e:
                    log.warning(f"Failed to apply initial kill_switch=False for {profile['name']}: {e}")
            # Reflect live router state in the response
            try:
                profile["kill_switch"] = self.router.policy.get_kill_switch(router_info["rule_name"])
            except Exception:
                pass

        log.info(f"Created profile '{profile['name']}' (type={profile['type']}, id={profile['id']})")

        if adblock:
            self._sync_adblock()

        return profile

    def update_profile(self, profile_id, **data):
        """Update profile metadata (name, color, icon, options, kill_switch).

        Kill switch is router-canonical: writes go directly to UCI, not to
        local store.

        Raises:
            NotFoundError: If the profile is not found.
        """
        # Pull kill_switch out before writing to local store -- it lives on the router only
        new_kill_switch = data.pop("kill_switch", None)

        profile = ps.update_profile(profile_id, **data)
        if profile is None:
            raise NotFoundError("Profile not found")

        ri = profile.get("router_info", {})
        rule_name = ri.get("rule_name")
        proto = ri.get("vpn_protocol", PROTO_WIREGUARD)
        is_pwg = proto.startswith("wireguard-")

        # Apply kill_switch change to the router (source of truth).
        # proton-wg always has kill switch on (blackhole route) -- skip UCI ops.
        if new_kill_switch is not None and rule_name and not is_pwg:
            try:
                self.router.policy.set_kill_switch(rule_name, bool(new_kill_switch))
                profile["kill_switch"] = self.router.policy.get_kill_switch(rule_name)
            except Exception as e:
                log.error(f"Failed to set kill switch on {rule_name}: {e}")

        # Sync name to router if this is a VPN profile (router is the source of truth).
        # proton-wg profiles have no route_policy rule -- name is local-only.
        if "name" in data and rule_name and not is_pwg:
            try:
                self.router.policy.rename_profile(
                    rule_name=rule_name,
                    new_name=data["name"],
                    peer_id=ri.get("peer_id", "") if proto != PROTO_OPENVPN else "",
                    client_uci_id=ri.get("client_uci_id", "") if proto == PROTO_OPENVPN else "",
                )
                profile["name"] = self.router.policy.get_profile_name(rule_name) or data["name"]
            except Exception as e:
                log.warning(f"Failed to rename profile on router: {e}")

        # Always include live kill_switch in the response so the UI is in sync
        if rule_name and not is_pwg:
            try:
                profile["kill_switch"] = self.router.policy.get_kill_switch(rule_name)
            except Exception:
                pass
        elif is_pwg:
            profile["kill_switch"] = True  # Always on

        if "adblock" in data:
            self._sync_adblock()

        return profile

    def delete_profile(self, profile_id):
        """Delete a profile and tear down its tunnel if VPN.

        Acquires the per-profile switch lock (blocking) to wait for any
        in-progress smart protocol switch to finish before deleting.

        Raises:
            NotFoundError: If the profile is not found.
        """
        self._cancel_smart(profile_id)

        lock = self._acquire_lock(profile_id, blocking=True)
        try:
            profile = ps.get_profile(profile_id)
            if not profile:
                raise NotFoundError("Profile not found")

            # Tear down router resources
            if profile["type"] == PROFILE_TYPE_VPN and profile.get("router_info"):
                self._teardown_tunnel(profile["router_info"])

            log.info(f"Deleted profile '{profile['name']}' (id={profile_id})")
            ps.delete_profile(profile_id)
        finally:
            lock.release()
            self._switch_locks.pop(profile_id, None)

        self._sync_lan_state(sync_noint=True, sync_adblock=True)

    # ── Type Change ─────────────────────────────────────────────────────────

    def change_type(self, profile_id: str, new_type: str,
                    vpn_protocol: str = PROTO_WIREGUARD,
                    server_id: str = None, options: dict = None,
                    kill_switch: bool = True, server_scope: dict = None,
                    ovpn_protocol: str = "udp"):
        """Change a profile's group type (VPN <-> NoVPN <-> NoInternet).

        Three cases:
        - NoVPN <-> NoInternet: metadata + LAN sync only.
        - VPN -> non-VPN: tear down tunnel, clear router fields.
        - Non-VPN -> VPN: create a tunnel (requires server_id + Proton login).

        Returns the updated profile dict.
        """
        self._cancel_smart(profile_id)

        profile = ps.get_profile(profile_id)
        if not profile:
            raise NotFoundError("Profile not found")

        old_type = profile["type"]
        if old_type == new_type:
            raise ValueError(f"Profile is already type '{new_type}'")
        if new_type not in (PROFILE_TYPE_VPN, PROFILE_TYPE_NO_VPN, PROFILE_TYPE_NO_INTERNET):
            raise ValueError(f"Invalid type: {new_type}")

        # ── Case 1: non-VPN <-> non-VPN ────────────────────────────────
        if old_type != PROFILE_TYPE_VPN and new_type != PROFILE_TYPE_VPN:
            ps.update_profile(profile_id, type=new_type)
            log.info(f"Changed type for '{profile['name']}' from {old_type} to {new_type}")
            self._sync_lan_state(sync_noint=True)
            return ps.get_profile(profile_id)

        # ── Case 2: VPN -> non-VPN ─────────────────────────────────────
        if old_type == PROFILE_TYPE_VPN:
            lock = self._acquire_lock(profile_id, blocking=True)
            try:
                # Re-read profile under lock to get current router_info
                profile = ps.get_profile(profile_id)
                ri = (profile.get("router_info") or {}) if profile else {}
                if ri:
                    self._teardown_tunnel(ri)
            finally:
                lock.release()

            # Clear VPN-specific fields
            ps.update_profile(profile_id,
                type=new_type,
                router_info=None,
                server_id=None,
                server=None,
                options=None,
                server_scope=None,
                wg_key=None,
                cert_expiry=None,
            )
            log.info(f"Changed type for '{profile['name']}' from VPN to {new_type}")
            self._sync_lan_state(sync_noint=True)
            return ps.get_profile(profile_id)

        # ── Case 3: non-VPN -> VPN ─────────────────────────────────────
        if not server_id:
            raise ValueError("server_id required when changing to VPN type")
        if not self.proton.is_logged_in:
            raise NotLoggedInError("Not logged into ProtonVPN")

        is_proton_wg = vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)

        # Check limits
        require_protocol_slot(vpn_protocol, exclude_profile_id=profile_id)

        # Create tunnel
        server = self.proton.get_server_by_id(server_id)
        opts = options or {}
        opts["ovpn_protocol"] = ovpn_protocol

        router_info, server_info, wg_key, cert_expiry = self._create_tunnel(
            vpn_protocol, profile["name"], server, opts,
        )

        # Migrate any device assignments from local store to router
        store_data = ps.load()
        local_assignments = store_data.get("device_assignments", {})
        macs_to_move = [mac for mac, pid in local_assignments.items() if pid == profile_id]
        if macs_to_move:
            self._reassign_devices(macs_to_move, router_info)
            for mac in macs_to_move:
                del local_assignments[mac]
            ps.save(store_data)

        # Update profile
        self._persist_tunnel_update(
            profile_id, router_info, server_info, wg_key, cert_expiry, opts,
            server_scope=server_scope,
        )
        # Also set the type
        ps.update_profile(profile_id, type=PROFILE_TYPE_VPN)

        # Apply kill switch
        if router_info and router_info.get("rule_name") and not is_proton_wg and not kill_switch:
            try:
                self.router.policy.set_kill_switch(router_info["rule_name"], False)
            except Exception as e:
                log.warning(f"change_type: set kill_switch failed: {e}")

        log.info(f"Changed type for '{profile['name']}' from {old_type} to VPN ({vpn_protocol})")
        self._sync_lan_state(sync_noint=True, sync_adblock=True)
        return ps.get_profile(profile_id)

    # ── Server Switch ───────────────────────────────────────────────────────

    def switch_server(self, profile_id: str, server_id: str, options: dict = None,
                      server_scope: dict = None) -> dict:
        """Core server-switch logic. Used by API endpoint and auto-optimizer.

        Returns the updated profile dict. Raises on error.
        """
        lock = self._acquire_lock(profile_id, blocking=False)

        try:
            profile = require_vpn_profile(profile_id)

            old_ri = profile.get("router_info", {}) or {}
            rule_name = old_ri.get("rule_name", "")
            vpn_protocol = old_ri.get("vpn_protocol", PROTO_WIREGUARD)
            if not rule_name:
                raise ValueError("Profile has no router_info.rule_name")

            server = self.proton.get_server_by_id(server_id)
            opts = options or profile.get("options", {})

            # If cert-relevant VPN options changed, re-register the persistent
            # certificate BEFORE generating the new config.
            if vpn_protocol.startswith("wireguard") and profile.get("wg_key") and options:
                old_opts = profile.get("options") or {}
                cert_keys = ("netshield", "moderate_nat", "nat_pmp", "vpn_accelerator")
                old_cert = {k: old_opts.get(k) for k in cert_keys}
                new_cert = {k: opts.get(k) for k in cert_keys}
                if old_cert != new_cert:
                    log.info(f"Refreshing WG cert for '{profile['name']}' — options changed: {old_cert} → {new_cert}")
                    cert_expiry_new = self.proton.refresh_wireguard_cert(
                        profile["wg_key"],
                        profile_name=profile.get("name", "Unnamed"),
                        netshield=opts.get("netshield", 0),
                        moderate_nat=opts.get("moderate_nat", False),
                        nat_pmp=opts.get("nat_pmp", False),
                        vpn_accelerator=opts.get("vpn_accelerator", True),
                    )
                    ps.update_profile(profile_id, cert_expiry=cert_expiry_new)

            strategy = get_strategy(vpn_protocol)
            new_ri, server_info, wg_key, cert_expiry = strategy.switch_server(
                self.router, self.proton, profile, server, opts, old_ri,
            )

            # Normalize the new scope
            if server_scope is not None:
                scope = ps.normalize_server_scope(server_scope)
            else:
                scope = ps.normalize_server_scope(profile.get("server_scope"))

            # Persist updated server reference + new scope.
            server_cache = {}
            for k in ("id", "endpoint", "physical_server_domain", "protocol"):
                if server_info.get(k):
                    server_cache[k] = server_info[k]

            update_kwargs = {
                "server_id": server_info.get("id", ""),
                "server": server_cache,
                "options": opts,
                "server_scope": scope,
            }
            # router_info only changes for OVPN (delete+recreate gets a new
            # rule_name/client_uci_id). WG keeps the same router_info.
            if new_ri is not None:
                update_kwargs["router_info"] = new_ri
            if wg_key:
                update_kwargs["wg_key"] = wg_key
            if cert_expiry:
                update_kwargs["cert_expiry"] = cert_expiry
            ps.update_profile(profile_id, **update_kwargs)
            return ps.get_profile(profile_id)

        finally:
            lock.release()

    # ── Protocol Change ─────────────────────────────────────────────────────

    def change_protocol(self, profile_id: str, new_vpn_protocol: str,
                        server_id: str = None, options: dict = None,
                        server_scope: dict = None, ovpn_protocol: str = "udp"):
        """Change a VPN profile's protocol (e.g. WireGuard -> OpenVPN).

        Tears down the old tunnel, creates a new one with the new protocol,
        and re-assigns all devices.

        Raises:
            NotFoundError: If the profile is not found.
            ValueError: If the profile is not VPN or the protocol is unchanged.
            LimitExceededError: If the new protocol's group limit is exceeded.
            RuntimeError: If tunnel creation fails.
        """
        lock = self._acquire_lock(profile_id, blocking=False)

        try:
            profile = require_vpn_profile(profile_id)

            old_ri = profile.get("router_info", {}) or {}
            old_proto = old_ri.get("vpn_protocol", PROTO_WIREGUARD)

            is_new_proton_wg = new_vpn_protocol in (PROTO_WIREGUARD_TCP, PROTO_WIREGUARD_TLS)
            is_old_proton_wg = old_proto.startswith("wireguard-")

            if new_vpn_protocol == old_proto:
                # OpenVPN UDP <-> TCP is allowed (same vpn_protocol, different transport)
                old_ovpn = "tcp" if (profile.get("server") or {}).get("protocol", "").endswith("tcp") else "udp"
                is_ovpn_transport_change = new_vpn_protocol == PROTO_OPENVPN and ovpn_protocol != old_ovpn
                if not is_ovpn_transport_change:
                    raise ValueError("Protocol is already " + old_proto)

            # Check limits for the new protocol
            require_protocol_slot(new_vpn_protocol, exclude_profile_id=profile_id)

            # 1. Capture assigned devices before teardown
            assigned_macs = []
            if is_old_proton_wg:
                ipset_name = old_ri.get("ipset_name", f"src_mac_{old_ri.get('tunnel_id', 0)}")
                try:
                    assigned_macs = [m.lower() for m in self._ipset.list_members(ipset_name)]
                except Exception as e:
                    log.warning(f"change_protocol: failed to read ipset {ipset_name}: {e}")
            elif old_ri.get("rule_name"):
                try:
                    assigned_macs = [t.lower() for t in self.router.policy.from_mac_tokens(old_ri["rule_name"])]
                except Exception as e:
                    log.warning(f"change_protocol: failed to read from_mac: {e}")

            # 2. Tear down old tunnel
            self._teardown_tunnel(old_ri)

            # 3. Resolve server
            effective_server_id = server_id or profile.get("server_id") or (profile.get("server") or {}).get("id")
            if not effective_server_id:
                raise ValueError("No server_id available for new tunnel")
            if not self.proton.is_logged_in:
                raise NotLoggedInError("Not logged into ProtonVPN")
            server = self.proton.get_server_by_id(effective_server_id)
            opts = options or profile.get("options", {})
            opts["ovpn_protocol"] = ovpn_protocol

            # 4. Create new tunnel
            new_ri, server_info, wg_key, cert_expiry = self._create_tunnel(
                new_vpn_protocol, profile["name"], server, opts,
            )

            # 5. Re-assign devices
            if assigned_macs:
                self._reassign_devices(assigned_macs, new_ri)

            # 6. Persist
            self._persist_tunnel_update(
                profile_id, new_ri, server_info, wg_key, cert_expiry, opts,
                server_scope=server_scope,
                clear_wg_key=not new_vpn_protocol.startswith("wireguard") and bool(profile.get("wg_key")),
            )

            log.info(f"Changed protocol for '{profile['name']}' from {old_proto} to {new_vpn_protocol}")
            self._sync_lan_state(sync_noint=True)

            return ps.get_profile(profile_id)

        finally:
            lock.release()

    # ── Profile Ordering ────────────────────────────────────────────────────

    def reorder_profiles(self, profile_ids):
        """Reorder profiles.

        Sets ``display_order`` on ALL profiles (VPN and non-VPN alike) so the
        dashboard can freely interleave them. VPN profiles also get their
        relative order synced to the router via ``uci reorder``.
        """
        if not profile_ids:
            raise ValueError("profile_ids required")

        store_data = ps.load()
        by_id = {p["id"]: p for p in store_data.get("profiles", [])}

        # 1. Set display_order on ALL profiles in the requested order
        vpn_rule_names = []
        for i, pid in enumerate(profile_ids):
            p = by_id.get(pid)
            if not p:
                continue
            p["display_order"] = i
            # Collect VPN rule names (in the requested order) for router sync
            if p.get("type") == PROFILE_TYPE_VPN:
                rn = (p.get("router_info") or {}).get("rule_name")
                if rn:
                    vpn_rule_names.append(rn)

        ps.save(store_data)

        # 2. Sync VPN relative order to router (for routing priority)
        if vpn_rule_names:
            try:
                self.router.policy.reorder_vpn_rules(vpn_rule_names)
            except Exception as e:
                log.warning(f"reorder_vpn_rules failed: {e}")

    # ── Guest Profile ───────────────────────────────────────────────────────

    def set_guest_profile(self, profile_id):
        """Set this profile as the guest profile.

        Raises:
            NotFoundError: If the profile is not found.
        """
        if not ps.set_guest_profile(profile_id):
            raise NotFoundError("Profile not found")

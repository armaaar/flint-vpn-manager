"""Settings blueprint — App settings, server preferences, adblock, credentials."""

from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

import persistence.secrets_manager as sm
from service_registry import registry as _registry
from services.adblock_service import download_and_merge_blocklists
from routes._helpers import require_unlocked, get_service, get_proton, get_router, log

settings_bp = Blueprint("settings", __name__)


# ── General Settings ─────────────────────────────────────────────────────────

@settings_bp.route("/api/settings")
@require_unlocked
def api_get_settings():
    """Get non-sensitive config."""
    return jsonify(sm.get_config())


@settings_bp.route("/api/settings", methods=["PUT"])
@require_unlocked
def api_update_settings():
    """Update non-sensitive config (router_ip etc)."""
    data = request.json
    config = sm.update_config(**data)

    # Apply alternative routing change at runtime
    if "alternative_routing" in data:
        try:
            get_proton().set_alternative_routing(data["alternative_routing"] is not False)
        except Exception as e:
            log.warning(f"Failed to apply alternative routing setting: {e}")

    # Reset router API if IP changed
    if "router_ip" in data:
        _registry.router = None
        if _registry.service is not None:
            _registry.service.router = get_router()

    # Apply global IPv6 setting — cascades to all networks
    if "global_ipv6_enabled" in data:
        try:
            router = get_router()
            if data["global_ipv6_enabled"]:
                router.firewall.ensure_ipv6_router_enabled()
                # Enable IPv6 on all Flint VPN Manager-managed networks
                networks = router.lan_access.get_networks()
                for net in networks:
                    if not net.get("ipv6_enabled"):
                        try:
                            router.lan_access.set_ipv6(net["id"], True)
                        except Exception:
                            pass
            else:
                # Disable IPv6 on all networks first
                networks = router.lan_access.get_networks()
                for net in networks:
                    if net.get("ipv6_enabled"):
                        try:
                            router.lan_access.set_ipv6(net["id"], False)
                        except Exception:
                            pass
                router.firewall.disable_ipv6_router()
        except Exception as e:
            log.warning(f"Failed to apply global IPv6 setting: {e}")

    return jsonify(config)


# ── Server Preferences (Blacklist / Favourites) ─────────────────────────────

@settings_bp.route("/api/settings/server-preferences")
@require_unlocked
def api_get_server_preferences():
    """Get server blacklist and favourites."""
    config = sm.get_config()
    return jsonify({
        "blacklist": config.get("server_blacklist", []),
        "favourites": config.get("server_favourites", []),
    })


@settings_bp.route("/api/settings/server-preferences", methods=["PUT"])
@require_unlocked
def api_update_server_preferences():
    """Replace server blacklist and/or favourites."""
    data = request.json or {}
    updates = {}
    if "blacklist" in data:
        updates["server_blacklist"] = list(data["blacklist"])
    if "favourites" in data:
        updates["server_favourites"] = list(data["favourites"])
    if not updates:
        return jsonify({"error": "Provide blacklist and/or favourites"}), 400
    sm.update_config(**updates)
    config = sm.get_config()
    return jsonify({
        "blacklist": config.get("server_blacklist", []),
        "favourites": config.get("server_favourites", []),
    })


@settings_bp.route("/api/settings/server-preferences/blacklist/<server_id>", methods=["POST"])
@require_unlocked
def api_add_to_blacklist(server_id):
    """Add a server to the blacklist."""
    config = sm.get_config()
    blacklist = config.get("server_blacklist", [])
    # Also remove from favourites if present
    favourites = config.get("server_favourites", [])
    if server_id not in blacklist:
        blacklist.append(server_id)
    favourites = [s for s in favourites if s != server_id]
    sm.update_config(server_blacklist=blacklist, server_favourites=favourites)
    return jsonify({"success": True})


@settings_bp.route("/api/settings/server-preferences/blacklist/<server_id>", methods=["DELETE"])
@require_unlocked
def api_remove_from_blacklist(server_id):
    """Remove a server from the blacklist."""
    config = sm.get_config()
    blacklist = [s for s in config.get("server_blacklist", []) if s != server_id]
    sm.update_config(server_blacklist=blacklist)
    return jsonify({"success": True})


@settings_bp.route("/api/settings/server-preferences/favourites/<server_id>", methods=["POST"])
@require_unlocked
def api_add_to_favourites(server_id):
    """Add a server to favourites."""
    config = sm.get_config()
    favourites = config.get("server_favourites", [])
    # Also remove from blacklist if present
    blacklist = config.get("server_blacklist", [])
    if server_id not in favourites:
        favourites.append(server_id)
    blacklist = [s for s in blacklist if s != server_id]
    sm.update_config(server_blacklist=blacklist, server_favourites=favourites)
    return jsonify({"success": True})


@settings_bp.route("/api/settings/server-preferences/favourites/<server_id>", methods=["DELETE"])
@require_unlocked
def api_remove_from_favourites(server_id):
    """Remove a server from favourites."""
    config = sm.get_config()
    favourites = [s for s in config.get("server_favourites", []) if s != server_id]
    sm.update_config(server_favourites=favourites)
    return jsonify({"success": True})


# ── Adblock ──────────────────────────────────────────────────────────────────

@settings_bp.route("/api/settings/adblock", methods=["GET"])
@require_unlocked
def api_get_adblock_settings():
    """Return adblock configuration + available presets."""
    from consts import BLOCKLIST_PRESETS
    config = sm.get_config()
    adblock = config.get("adblock", {})
    # Migrate legacy single-URL to sources list
    if "blocklist_url" in adblock and "blocklist_sources" not in adblock:
        adblock["blocklist_sources"] = [adblock.pop("blocklist_url")] if adblock["blocklist_url"] else []
        sm.update_config(adblock=adblock)
    return jsonify({**adblock, "presets": BLOCKLIST_PRESETS})


@settings_bp.route("/api/settings/adblock", methods=["PUT"])
@require_unlocked
def api_update_adblock_settings():
    """Update adblock configuration (blocklist_sources)."""
    data = request.json
    config = sm.get_config()
    adblock = config.get("adblock", {})
    if "blocklist_sources" in data:
        adblock["blocklist_sources"] = data["blocklist_sources"]
    if "custom_domains" in data:
        # Validate: each entry should be a domain-like string
        adblock["custom_domains"] = [
            d.strip().lower() for d in data["custom_domains"]
            if d.strip() and "." in d.strip()
        ]
    adblock.pop("blocklist_url", None)  # Remove legacy field
    sm.update_config(adblock=adblock)
    return jsonify(adblock)


@settings_bp.route("/api/settings/adblock/update-now", methods=["POST"])
@require_unlocked
def api_update_blocklist_now():
    """Download all selected blocklists, merge, deduplicate, upload to router."""
    content, count, failed = download_and_merge_blocklists()
    if content is None and not failed:
        return jsonify({"error": "No blocklist sources configured"}), 400
    if content is None and failed:
        return jsonify({"error": f"All sources failed to download: {', '.join(failed)}"}), 502
    try:
        import hashlib
        new_hash = hashlib.sha256(content.encode()).hexdigest()
        config = sm.get_config()
        adblock = config.get("adblock", {})
        old_hash = adblock.get("blocklist_hash")

        if new_hash != old_hash:
            get_service().router.adblock.upload_blocklist(content)
            adblock["blocklist_hash"] = new_hash
        else:
            log.info("Blocklist unchanged (%d domains) — skipping upload", count)

        adblock["last_updated"] = datetime.now(timezone.utc).isoformat()
        adblock["domain_count"] = count
        sm.update_config(adblock=adblock)
        result = {"success": True, "entries": count, "last_updated": adblock["last_updated"]}
        if failed:
            result["failed_sources"] = failed
        return jsonify(result)
    except Exception as e:
        log.error(f"Blocklist update failed: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@settings_bp.route("/api/settings/adblock/domains", methods=["GET"])
@require_unlocked
def api_get_blocked_domains():
    """Return paginated list of blocked domains with optional search.

    All parsing is done on the router via awk/grep to avoid pulling
    140K+ lines over SSH.
    """
    search = request.args.get("search", "").strip().lower()
    page = int(request.args.get("page", 1))
    limit = min(int(request.args.get("limit", 100)), 500)

    try:
        from consts import ADBLOCK_HOSTS_PATH
        router = get_service().router

        # Extract just the domain column, skip comments/localhost, sort unique
        base_cmd = (
            f"awk '!/^#/ && NF>=2 && $2!=\"localhost\" {{print $2}}' {ADBLOCK_HOSTS_PATH} "
            f"2>/dev/null | sort -u"
        )

        if search:
            # Filter + count + paginate all on router
            filter_cmd = f"{base_cmd} | grep -i '{search}'"
            total_str = router.exec(f"{filter_cmd} | wc -l", timeout=15).strip()
            total = int(total_str) if total_str.isdigit() else 0
            start = (page - 1) * limit
            raw = router.exec(
                f"{filter_cmd} | tail -n +{start + 1} | head -n {limit}",
                timeout=15,
            ).strip()
        else:
            # Count + paginate on router
            total_str = router.exec(f"{base_cmd} | wc -l", timeout=15).strip()
            total = int(total_str) if total_str.isdigit() else 0
            start = (page - 1) * limit
            raw = router.exec(
                f"{base_cmd} | tail -n +{start + 1} | head -n {limit}",
                timeout=15,
            ).strip()

        page_domains = [d for d in raw.splitlines() if d.strip()] if raw else []

        return jsonify({
            "domains": page_domains,
            "total": total,
            "page": page,
            "limit": limit,
            "has_more": start + limit < total,
        })
    except Exception as e:
        log.error(f"Failed to read blocked domains: {e}")
        return jsonify({"domains": [], "total": 0, "page": 1, "has_more": False})


# ── Credentials ──────────────────────────────────────────────────────────────

@settings_bp.route("/api/settings/credentials", methods=["PUT"])
@require_unlocked
def api_update_credentials():
    """Update encrypted credentials."""
    data = request.json
    master_password = data.pop("master_password", None)
    if not master_password:
        return jsonify({"error": "master_password required"}), 400

    try:
        sm.update(master_password, **data)
        return jsonify({"success": True})
    except (ValueError, KeyError) as e:
        return jsonify({"error": str(e)}), 400


@settings_bp.route("/api/settings/master-password", methods=["PUT"])
@require_unlocked
def api_change_master_password():
    """Change the master password.

    Body: {old_password, new_password}
    """
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

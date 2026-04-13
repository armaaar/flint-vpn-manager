#!/usr/bin/env python3
"""FlintVPN Manager CLI — terminal interface for managing VPN profiles and devices.

This CLI wraps the same backend as the web dashboard, allowing full control
from the terminal. All options can be passed as flags (non-interactive) or
will be prompted interactively if omitted.

CREDENTIAL MANAGEMENT:
    ./cli.py setup                          First-time setup. Encrypts ProtonVPN
                                            and router credentials with a master
                                            password. Creates secrets.enc and
                                            config.json. All options can be passed
                                            as flags to skip prompts:
                                              --proton-user USER
                                              --proton-pass PASS
                                              --router-pass PASS
                                              --router-ip IP (default: 192.168.8.1)
                                              --master-password PASS

    ./cli.py unlock                         Decrypt credentials into memory for
                                            this CLI session. Required before any
                                            command that talks to ProtonVPN or the
                                            router. Pass --master-password to skip
                                            the prompt.

    ./cli.py change-password                Change the master password used to
                                            encrypt secrets.enc. Requires the
                                            current password to decrypt first.

CONFIGURATION:
    ./cli.py config show                    Print all non-sensitive config values
                                            from config.json (router_ip, etc.)

    ./cli.py config set KEY VALUE           Update a config value. Example:
                                              ./cli.py config set router_ip 10.0.0.1

STATUS:
    ./cli.py status                         Show setup state, session lock state,
                                            and router IP. Will expand to show
                                            profiles, tunnels, and devices as
                                            those modules are built.

Commands added in later sessions:
    profiles list|create|delete|update      Manage VPN/NoVPN/NoInternet profiles
    devices list|assign|unassign            View and assign devices to profiles
    server list|switch                      Browse ProtonVPN servers, switch profile server
    tunnel up|down <profile>                Bring VPN tunnels up or down
    refresh                                 Poll DHCP leases, tunnel handshakes, server list
"""

import click

import persistence.secrets_manager as sm
from consts import PROFILE_TYPE_VPN
from proton_vpn.api import ProtonAPI
from router.api import RouterAPI
from services.vpn_service import VPNService

# Module-level session state (populated by unlock)
_session = {"secrets": None, "unlocked": False}

# Lazy-initialized singletons
_proton_api = None
_router_api = None
_service = None

SSH_KEY_PATH = "/home/armaaar/.ssh/id_ed25519"


def get_proton_api() -> ProtonAPI:
    """Get or create the ProtonAPI singleton."""
    global _proton_api
    if _proton_api is None:
        _proton_api = ProtonAPI()
    return _proton_api


def get_router_api() -> RouterAPI:
    """Get or create the RouterAPI singleton using config.json router_ip."""
    global _router_api
    if _router_api is None:
        config = sm.get_config()
        _router_api = RouterAPI(
            host=config.get("router_ip", "192.168.8.1"),
            key_filename=SSH_KEY_PATH,
        )
    return _router_api


def get_service() -> VPNService:
    """Get the VPNService singleton. Only available after unlock."""
    if _service is None:
        raise RuntimeError("Service not initialized. Run 'unlock' first.")
    return _service


def require_setup(ctx):
    """Exit with error if secrets.enc doesn't exist (setup not done)."""
    if not sm.is_setup():
        click.echo("Error: Not set up yet. Run './cli.py setup' first.")
        ctx.exit(1)


def require_unlock(ctx):
    """Ensure session is unlocked. Auto-prompts for master password if not."""
    require_setup(ctx)
    if not _session["unlocked"]:
        click.echo("Session not unlocked. Unlocking now...")
        ctx.invoke(unlock)


@click.group()
def cli():
    """FlintVPN Manager — manage ProtonVPN WireGuard profiles on GL.iNet Flint 2.

    Terminal interface to the same backend as the web dashboard. Use this to
    manage VPN profiles, assign devices, switch servers, and monitor tunnel
    health — all from the command line.

    Run any command with --help for detailed usage.
    """
    pass


@cli.command()
@click.option("--proton-user", prompt="ProtonVPN username",
              help="ProtonVPN account username (email).")
@click.option("--proton-pass", prompt="ProtonVPN password", hide_input=True,
              help="ProtonVPN account password. Hidden during interactive input.")
@click.option("--router-pass", prompt="Router admin password", hide_input=True,
              help="GL.iNet Flint 2 admin password (used for SSH as root).")
@click.option("--router-ip", prompt="Router IP", default="192.168.8.1",
              help="Router LAN IP address. Default: 192.168.8.1")
@click.option("--master-password", prompt="Master password", hide_input=True,
              confirmation_prompt=True,
              help="Master password to encrypt all credentials. You'll need this every time you start the dashboard.")
def setup(proton_user, proton_pass, router_pass, router_ip, master_password):
    """First-time setup: encrypt and store all credentials.

    Creates secrets.enc (encrypted credentials) and config.json (router IP).
    If credentials already exist, prompts for confirmation before overwriting.

    \b
    Non-interactive example:
      ./cli.py setup --proton-user user@pm.me --proton-pass secret \\
                     --router-pass admin123 --master-password mymaster
    """
    if sm.is_setup():
        if not click.confirm("Credentials already exist. Overwrite?"):
            return
    sm.setup(proton_user, proton_pass, router_pass, master_password, router_ip)
    click.echo("Setup complete. Credentials encrypted and saved.")


@cli.command()
@click.option("--master-password", prompt="Master password", hide_input=True,
              help="The master password set during setup.")
def unlock(master_password):
    """Unlock the session by decrypting credentials into memory.

    Must be called before any command that needs ProtonVPN or router access.
    Credentials stay in memory only for this CLI invocation — they are never
    written to disk in plain text.

    \b
    Non-interactive: ./cli.py unlock --master-password mymaster
    """
    global _service
    require_setup(click.get_current_context())
    try:
        _session["secrets"] = sm.unlock(master_password)
        _session["unlocked"] = True
        _service = VPNService(get_router_api(), get_proton_api())
        click.echo("Session unlocked.")
    except ValueError as e:
        click.echo(f"Error: {e}")
        click.get_current_context().exit(1)


@cli.command()
@click.pass_context
def status(ctx):
    """Show current system status: setup state, session, router IP.

    Outputs a quick summary of whether the system is set up, whether the
    session is unlocked, and the configured router IP. Will be extended
    to show active profiles, tunnel states, and connected devices.
    """
    click.echo(f"Setup: {'yes' if sm.is_setup() else 'no'}")
    click.echo(f"Session: {'unlocked' if _session['unlocked'] else 'locked'}")

    config = sm.get_config()
    click.echo(f"Router IP: {config.get('router_ip', 'not set')}")

    # Future: show profiles, tunnels, devices when those modules exist


@cli.command("reset-local-state")
@click.option("--yes", is_flag=True, help="Skip confirmation")
@click.option("--keep-router", is_flag=True,
              help="Don't wipe fvpn_* sections / ipsets on the router")
def reset_local_state(yes, keep_router):
    """Wipe local profile_store.json AND router backup, optionally also wipe
    all fvpn_* router state.

    Use this to start fresh: deletes all groups, device assignments, LAN
    settings, and the router-side disaster-recovery backup. Without --yes,
    confirms before each step.

    The next unlock will start with an empty store and will NOT auto-restore
    (because the router backup is also gone).

    \b
    Examples:
      ./cli.py reset-local-state                # interactive
      ./cli.py reset-local-state --yes          # full wipe, no prompts
      ./cli.py reset-local-state --keep-router  # only wipe local + backup
    """
    import persistence.profile_store as pstore

    if not yes:
        click.echo("This will permanently delete:")
        click.echo("  - profile_store.json (groups, assignments, LAN settings)")
        click.echo("  - /etc/fvpn/profile_store.bak.json on the router")
        if not keep_router:
            click.echo("  - All fvpn_* UCI sections and ipsets on the router")
        click.echo("It will NOT touch secrets.enc, config.json, or VPN tunnels.")
        if not click.confirm("Continue?"):
            return

    # 1. Wipe local profile_store.json
    if pstore.STORE_FILE.exists():
        pstore.STORE_FILE.unlink()
        click.echo(f"Deleted {pstore.STORE_FILE}")
    else:
        click.echo("Local profile_store.json already absent.")

    # 2. Delete router backup file (best-effort)
    try:
        router = get_router_api()
        router.exec("rm -f /etc/fvpn/profile_store.bak.json 2>/dev/null || true")
        click.echo("Deleted /etc/fvpn/profile_store.bak.json on router")
    except Exception as e:
        click.echo(f"Warning: failed to delete router backup: {e}")

    # 3. Wipe router fvpn_* state (UCI + ipsets)
    if not keep_router:
        try:
            router = get_router_api()
            import router.noint_sync as noint_sync
            noint_sync.wipe_noint(router)
            click.echo("Wiped NoInternet router state (UCI sections + ipsets)")
        except Exception as e:
            click.echo(f"Warning: router wipe failed: {e}")

    click.echo("Done. Restart the app and unlock to start fresh.")


@cli.group()
def config():
    """View or update non-sensitive configuration (config.json).

    Config values are stored in plain text (not encrypted) since they
    contain no secrets. Currently stores: router_ip.
    """
    pass


@config.command("show")
def config_show():
    """Print all config key-value pairs from config.json."""
    cfg = sm.get_config()
    for key, value in cfg.items():
        click.echo(f"  {key}: {value}")


@config.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set a config value in config.json.

    \b
    Examples:
      ./cli.py config set router_ip 10.0.0.1
      ./cli.py config set router_ip 192.168.8.1
    """
    sm.update_config(**{key: value})
    click.echo(f"Updated {key} = {value}")


@cli.command("change-password")
@click.option("--old-password", prompt="Current master password", hide_input=True,
              help="Your current master password (to decrypt existing secrets).")
@click.option("--new-password", prompt="New master password", hide_input=True,
              confirmation_prompt=True,
              help="The new master password to re-encrypt secrets with.")
def change_password(old_password, new_password):
    """Change the master password for secrets.enc.

    Decrypts all credentials with the old password and re-encrypts them
    with the new password using a fresh random salt.

    \b
    Non-interactive:
      ./cli.py change-password --old-password old123 --new-password new456
    """
    require_setup(click.get_current_context())
    try:
        sm.change_master_password(old_password, new_password)
        click.echo("Master password changed successfully.")
    except ValueError as e:
        click.echo(f"Error: {e}")


# ── ProtonVPN Commands ────────────────────────────────────────────────────────

@cli.group()
def server():
    """Browse and search ProtonVPN servers.

    Requires an active ProtonVPN session (either from the GTK app or
    by logging in via the web dashboard). The server list is cached
    and refreshed automatically.
    """
    pass


@server.command("list")
@click.option("--country", "-c", default=None,
              help="Filter by 2-letter country code (e.g. US, UK, CH, DE).")
@click.option("--city", default=None,
              help="Filter by city name (e.g. London, 'New York', Zurich).")
@click.option("--feature", "-f", default=None,
              type=click.Choice(["streaming", "p2p", "secure_core", "tor"]),
              help="Filter by server feature.")
@click.option("--limit", "-n", default=20, show_default=True,
              help="Max number of servers to display.")
@click.option("--sort", "-s", default="load",
              type=click.Choice(["load", "score", "name"]),
              help="Sort order for results.")
def server_list(country, city, feature, limit, sort):
    """List ProtonVPN servers with optional filters.

    Shows server name, country, city, load percentage, and features.
    Servers are sorted by load (lowest first) by default.

    \b
    Examples:
      ./cli.py server list                        All servers (first 20)
      ./cli.py server list -c US                  US servers
      ./cli.py server list -c UK -f streaming     UK streaming servers
      ./cli.py server list --city London -n 10    London servers, top 10
      ./cli.py server list -f p2p -s score        P2P servers by score
    """
    api = get_proton_api()
    if not api.is_logged_in:
        click.echo("Error: Not logged into ProtonVPN. Log in via the GTK app or web dashboard first.")
        return

    try:
        servers = api.get_servers(country=country, city=city, feature=feature)
    except RuntimeError as e:
        click.echo(f"Error: {e}")
        return

    if not servers:
        click.echo("No servers found matching your filters.")
        return

    # Sort
    if sort == "load":
        servers.sort(key=lambda s: s["load"])
    elif sort == "score":
        servers.sort(key=lambda s: s["score"])
    elif sort == "name":
        servers.sort(key=lambda s: s["name"])

    # Display
    click.echo(f"{'Name':<12} {'Country':<20} {'City':<18} {'Load':>5} {'Features'}")
    click.echo("-" * 80)
    for s in servers[:limit]:
        features = ", ".join(s["features"]) if s["features"] else "-"
        click.echo(
            f"{s['name']:<12} {s['country']:<20} {s['city']:<18} {s['load']:>4}% {features}"
        )
    if len(servers) > limit:
        click.echo(f"\n... and {len(servers) - limit} more. Use -n to show more.")
    click.echo(f"\nTotal: {len(servers)} servers")


@server.command("countries")
@click.option("--limit", "-n", default=50, show_default=True,
              help="Max number of countries to display.")
def server_countries(limit):
    """List all available countries with server counts.

    Shows country code, name, number of servers, and available cities.

    \b
    Examples:
      ./cli.py server countries                   All countries
      ./cli.py server countries -n 10             Top 10
    """
    api = get_proton_api()
    if not api.is_logged_in:
        click.echo("Error: Not logged into ProtonVPN.")
        return

    try:
        countries = api.get_countries()
    except RuntimeError as e:
        click.echo(f"Error: {e}")
        return

    click.echo(f"{'Code':<6} {'Country':<25} {'Servers':>8} {'Cities'}")
    click.echo("-" * 75)
    for c in countries[:limit]:
        cities = ", ".join(ci["name"] for ci in c["cities"][:5])
        if len(c["cities"]) > 5:
            cities += f" (+{len(c['cities']) - 5})"
        click.echo(f"{c['code']:<6} {c['name']:<25} {c['server_count']:>8} {cities}")
    click.echo(f"\nTotal: {len(countries)} countries")


@server.command("info")
@click.argument("name")
def server_info(name):
    """Show detailed info for a specific server by name.

    \b
    Examples:
      ./cli.py server info 'CH#10'
      ./cli.py server info 'UK#1'
      ./cli.py server info 'US-NY#5'
    """
    api = get_proton_api()
    if not api.is_logged_in:
        click.echo("Error: Not logged into ProtonVPN.")
        return

    try:
        server = api.get_server_by_name(name)
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    info = api._server_to_dict(server)
    click.echo(f"Name:           {info['name']}")
    click.echo(f"Country:        {info['country']} ({info['country_code']})")
    click.echo(f"Entry Country:  {info['entry_country_code']}")
    click.echo(f"City:           {info['city']}")
    click.echo(f"Load:           {info['load']}%")
    click.echo(f"Score:          {info['score']:.4f}")
    click.echo(f"Tier:           {info['tier']}")
    click.echo(f"Enabled:        {info['enabled']}")
    click.echo(f"Features:       {', '.join(info['features']) or 'none'}")
    click.echo(f"Secure Core:    {info['secure_core']}")
    click.echo(f"Streaming:      {info['streaming']}")
    click.echo(f"P2P:            {info['p2p']}")


@server.command("generate-config")
@click.argument("name")
@click.option("--netshield", type=click.Choice(["0", "1", "2"]), default="0",
              help="NetShield level: 0=off, 1=malware, 2=malware+ads")
@click.option("--output", "-o", default=None,
              help="Write config to file instead of stdout.")
def server_generate_config(name, netshield, output):
    """Generate a WireGuard .conf file for a specific server.

    The config has IPv6 stripped (required for GL.iNet compatibility).
    Output goes to stdout unless --output is specified.

    \b
    Examples:
      ./cli.py server generate-config 'UK#1'
      ./cli.py server generate-config 'US-NY#5' --netshield 2
      ./cli.py server generate-config 'CH#10' -o streaming.conf
    """
    api = get_proton_api()
    if not api.is_logged_in:
        click.echo("Error: Not logged into ProtonVPN.")
        return

    try:
        server = api.get_server_by_name(name)
        config, info, _wg_key, _cert_expiry = api.generate_wireguard_config(
            server, profile_name=name, netshield=int(netshield)
        )
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    if output:
        with open(output, "w") as f:
            f.write(config)
        click.echo(f"Config written to {output}")
        click.echo(f"Server: {info['name']} ({info['country']}, {info['city']})")
        click.echo(f"Endpoint: {info['endpoint']}")
    else:
        click.echo(config)


@cli.command("vpn-status")
def vpn_status():
    """Show ProtonVPN session status: logged in, tier, server count.

    Uses the system keyring session (shared with ProtonVPN GTK app).
    Does not require ./cli.py unlock — ProtonVPN session is separate
    from the FlintVPN master password session.
    """
    api = get_proton_api()
    click.echo(f"ProtonVPN logged in: {api.is_logged_in}")
    if api.is_logged_in:
        click.echo(f"Account: {api.account_name}")
        click.echo(f"Tier: {api.user_tier} ({'Plus' if api.user_tier >= 2 else 'Free'})")
        sl = api.server_list
        if sl:
            click.echo(f"Servers loaded: {len(sl)}")
            click.echo(f"Server list expired: {sl.expired}")
            click.echo(f"Loads expired: {sl.loads_expired}")


# ── Router Commands ───────────────────────────────────────────────────────────

@cli.group()
def router():
    """Manage the GL.iNet Flint 2 router via SSH.

    Commands to view devices, manage WireGuard tunnels, and control
    device routing policies. Connects to the router using SSH key auth
    at the IP configured in config.json.
    """
    pass


@router.command("devices")
def router_devices():
    """List all devices on the network from DHCP leases.

    Shows MAC address, IP, hostname, and lease expiry. Devices with
    randomized MACs (2nd hex char is 2/6/A/E) are flagged.

    \b
    Example: ./cli.py router devices
    """
    r = get_router_api()
    try:
        leases = r.devices.get_dhcp_leases()
    except Exception as e:
        click.echo(f"Error connecting to router: {e}")
        return

    if not leases:
        click.echo("No DHCP leases found.")
        return

    click.echo(f"{'MAC':<20} {'IP':<16} {'Hostname':<20} {'Note'}")
    click.echo("-" * 70)
    for l in leases:
        note = ""
        # Check for randomized MAC (2nd hex char is 2, 6, A, or E)
        if len(l["mac"]) >= 2:
            second_char = l["mac"][1].lower()
            if second_char in ("2", "6", "a", "e"):
                note = "random MAC"
        click.echo(
            f"{l['mac']:<20} {l['ip']:<16} {l['hostname'] or '-':<20} {note}"
        )
    click.echo(f"\nTotal: {len(leases)} devices")


@router.command("tunnels")
def router_tunnels():
    """Show all FlintVPN WireGuard tunnels and their status.

    Lists tunnel interface names, associated profile names, health
    (green/amber/red), and whether kill switch is enabled.

    \b
    Example: ./cli.py router tunnels
    """
    r = get_router_api()
    try:
        rules = r.policy.get_flint_vpn_rules()
        peers = r.policy.get_flint_vpn_peers()
    except Exception as e:
        click.echo(f"Error connecting to router: {e}")
        return

    if not rules:
        click.echo("No FlintVPN tunnels configured.")
        return

    click.echo(f"{'Interface':<14} {'Profile':<20} {'Enabled':<9} {'Kill SW':<9} {'Health'}")
    click.echo("-" * 65)
    for rule in rules:
        iface = rule.get("via", "?")
        name = rule.get("name", "?")
        enabled = rule.get("enabled", "0") == "1"
        ks = rule.get("killswitch", "0") == "1"

        if enabled:
            try:
                health = r.tunnel.get_tunnel_health(iface)
            except Exception:
                health = "unknown"
        else:
            health = "off"

        click.echo(
            f"{iface:<14} {name:<20} {'yes' if enabled else 'no':<9} "
            f"{'on' if ks else 'off':<9} {health}"
        )

    click.echo(f"\nTotal: {len(rules)} tunnels")


@router.command("status")
def router_status():
    """Show router connection status and basic info.

    \b
    Example: ./cli.py router status
    """
    r = get_router_api()
    config = sm.get_config()
    click.echo(f"Router IP: {config.get('router_ip', 'not set')}")

    try:
        r.connect()
        click.echo("SSH connection: OK")
        leases = r.devices.get_dhcp_leases()
        click.echo(f"Devices on network: {len(leases)}")
        rules = r.policy.get_flint_vpn_rules()
        click.echo(f"FlintVPN tunnels: {len(rules)}")
        active = r.policy.get_active_interfaces()
        click.echo(f"Active WG interfaces: {', '.join(active) if active else 'none'}")
    except Exception as e:
        click.echo(f"SSH connection: FAILED ({e})")


# ── Profile Commands ──────────────────────────────────────────────────────────

@cli.group("profiles")
def profiles():
    """Manage VPN profiles (VPN, No VPN, No Internet).

    Create, list, update, and delete profiles that control how
    device traffic is routed through the router.
    """
    pass


@profiles.command("list")
def profiles_list():
    """List all profiles with their type, device count, and status.

    \b
    Example: ./cli.py profiles list
    """
    import persistence.profile_store as pstore
    data = pstore.load()
    profs = data["profiles"]

    if not profs:
        click.echo("No profiles configured.")
        return

    click.echo(f"{'Name':<20} {'Type':<14} {'Guest':<7} {'Devices':<9} {'Status'}")
    click.echo("-" * 65)
    for p in profs:
        devices = len(pstore.get_devices_for_profile(p["id"], data))
        status = p.get("status", "-")
        guest = "yes" if p.get("is_guest") else ""
        click.echo(
            f"{p['icon']} {p['name']:<18} {p['type']:<14} {guest:<7} {devices:<9} {status}"
        )
    click.echo(f"\nTotal: {len(profs)} profiles")


@profiles.command("create")
@click.option("--name", "-n", prompt="Profile name", help="Display name for the profile.")
@click.option("--type", "-t", "profile_type", prompt="Type (vpn/no_vpn/no_internet)",
              type=click.Choice(["vpn", "no_vpn", "no_internet"]),
              help="Profile type.")
@click.option("--color", default="#3498db", help="Hex color for the UI card.")
@click.option("--icon", default="🔒", help="Emoji icon.")
@click.option("--guest/--no-guest", default=False, help="Set as guest profile.")
def profiles_create(name, profile_type, color, icon, guest):
    """Create a new profile.

    For VPN profiles, you'll need to assign a server separately using
    the web dashboard or future CLI commands.

    \b
    Examples:
      ./cli.py profiles create -n "Streaming" -t no_vpn
      ./cli.py profiles create -n "Printers" -t no_internet --icon "🖨️"
      ./cli.py profiles create -n "Guest WiFi" -t no_vpn --guest
    """
    if profile_type == PROFILE_TYPE_VPN:
        click.echo("Error: VPN profiles require a server selection. Use the web dashboard.")
        return

    try:
        service = get_service()
        profile = service.create_profile(
            name=name, profile_type=profile_type,
            color=color, icon=icon, is_guest=guest,
        )
    except Exception as e:
        click.echo(f"Error: {e}")
        return

    click.echo(f"Created profile: {profile['icon']} {profile['name']} ({profile['type']})")
    click.echo(f"ID: {profile['id']}")
    if guest:
        click.echo("Set as guest profile.")


@profiles.command("delete")
@click.argument("profile_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
def profiles_delete(profile_id, yes):
    """Delete a profile by ID.

    Devices assigned to this profile will become unassigned.
    VPN tunnels will be torn down.

    \b
    Example: ./cli.py profiles delete <profile-id>
    """
    import persistence.profile_store as pstore
    from services.vpn_service import NotFoundError

    profile = pstore.get_profile(profile_id)
    if not profile:
        click.echo(f"Error: Profile {profile_id} not found.")
        return

    if not yes:
        if not click.confirm(f"Delete '{profile['name']}'?"):
            return

    try:
        service = get_service()
        service.delete_profile(profile_id)
    except NotFoundError:
        click.echo(f"Error: Profile {profile_id} not found.")
        return
    except Exception as e:
        click.echo(f"Warning: Deletion had issues: {e}")

    click.echo(f"Deleted profile: {profile['name']}")


# ── Device Assignment Commands ────────────────────────────────────────────────

@cli.group("devices")
def devices():
    """View and manage device assignments.

    Assign devices to profiles to control their routing.
    Devices are identified by MAC address.
    """
    pass


@devices.command("list")
def devices_list():
    """List all known devices with their profile assignment.

    Device data is fetched live from the router (DHCP leases +
    gl-clients tracking). Requires the session to be unlocked so the router
    SSH connection is available.

    \b
    Example: ./cli.py devices list
    """
    import persistence.profile_store as pstore

    if not _session["unlocked"]:
        click.echo("Session locked. Run `unlock` first or use the dashboard.")
        return

    service = get_service()
    devs = service.build_devices_live()

    if not devs:
        click.echo("No devices known yet.")
        return

    data = pstore.load()
    prof_names = {p["id"]: f"{p['icon']} {p['name']}" for p in data["profiles"]}

    click.echo(f"{'MAC':<20} {'IP':<16} {'Hostname':<18} {'Profile'}")
    click.echo("-" * 75)
    for d in devs:
        prof = prof_names.get(d["profile_id"], "Unassigned") if d["profile_id"] else "Unassigned"
        click.echo(
            f"{d['mac']:<20} {d.get('ip', '-'):<16} {d['hostname'] or '-':<18} {prof}"
        )
    click.echo(f"\nTotal: {len(devs)} devices")


@devices.command("assign")
@click.argument("mac")
@click.argument("profile_id")
def devices_assign(mac, profile_id):
    """Assign a device to a profile by MAC address and profile ID.

    Also updates the router's route policy so the device's traffic
    is routed through the correct tunnel.

    \b
    Examples:
      ./cli.py devices assign aa:bb:cc:dd:ee:ff <profile-id>
    """
    import persistence.profile_store as pstore
    from services.vpn_service import NotFoundError

    profile = pstore.get_profile(profile_id)
    if not profile:
        click.echo(f"Error: Profile {profile_id} not found.")
        return

    try:
        service = get_service()
        service.assign_device(mac, profile_id)
    except NotFoundError as e:
        click.echo(f"Error: {e}")
        return
    except Exception as e:
        click.echo(f"Warning: Assignment had issues: {e}")

    click.echo(f"Assigned {mac} → {profile['icon']} {profile['name']}")


@devices.command("unassign")
@click.argument("mac")
def devices_unassign(mac):
    """Unassign a device (returns to raw WAN / unassigned state).

    \b
    Example: ./cli.py devices unassign aa:bb:cc:dd:ee:ff
    """
    try:
        service = get_service()
        service.assign_device(mac, None)
    except Exception as e:
        click.echo(f"Warning: Unassignment had issues: {e}")

    click.echo(f"Unassigned {mac}")


if __name__ == "__main__":
    cli()

"""Adblock Service — Blocklist download and merge logic.

Extracted from app.py. No Flask dependency.
"""

import logging

import persistence.secrets_manager as sm
from consts import BLOCKLIST_PRESETS

log = logging.getLogger("flintvpn")


def download_and_merge_blocklists():
    """Download all selected blocklists, merge and deduplicate.

    Returns (hosts_content, domain_count, failed_sources) or (None, 0, []) if no sources.
    """
    import requests as http_requests

    config = sm.get_config()
    adblock = config.get("adblock", {})
    sources = adblock.get("blocklist_sources", [])
    custom_domains = adblock.get("custom_domains", [])
    if not sources and not custom_domains:
        return None, 0, []

    all_domains = set()
    # Add user's custom domains first
    for d in custom_domains:
        d = d.strip().lower()
        if d and "." in d:
            all_domains.add(d)

    failed = []
    for source in sources:
        url = BLOCKLIST_PRESETS.get(source, {}).get("url", source)
        try:
            resp = http_requests.get(url, timeout=120)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].lower()
                    if domain and domain != "localhost":
                        all_domains.add(domain)
                elif len(parts) == 1 and "." in parts[0]:
                    all_domains.add(parts[0].lower())
            log.info(f"Blocklist: downloaded {url} — running total {len(all_domains)} domains")
        except Exception as e:
            log.warning(f"Blocklist: failed to download {url}: {e}")
            failed.append(source)

    if not all_domains:
        return None, 0, failed

    sorted_domains = sorted(all_domains)
    content = "# Flint VPN Manager merged blocklist\n"
    content += f"# Sources: {', '.join(sources)}\n"
    content += f"# Domains: {len(sorted_domains)}\n\n"
    for d in sorted_domains:
        content += f"0.0.0.0 {d}\n:: {d}\n"

    return content, len(sorted_domains), failed

"""UCI (Unified Configuration Interface) tool wrapper.

Handles consistent quoting, error suppression, and batch operations
for OpenWrt's UCI configuration system.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router.tools import SshExecutor

# Temp file for batch operations (cleaned up after each batch).
_BATCH_TMP = "/tmp/fvpn_uci_batch.txt"


def _quote(value: str) -> str:
    """Escape a value for safe embedding in a single-quoted UCI argument.

    UCI values are wrapped in single quotes. Internal single quotes are
    escaped as ``'\\''`` (end quote, escaped quote, restart quote).
    """
    return value.replace("'", "'\\''")


class Uci:
    """Typed wrapper around the ``uci`` CLI on an OpenWrt router."""

    def __init__(self, ssh: SshExecutor):
        self._ssh = ssh

    # ── Single-command operations ───────────────────────────────────────

    def get(self, path: str, default: str = "") -> str:
        """Read a single UCI value, returning *default* if unset."""
        return self._ssh.exec(
            f"uci -q get {path} 2>/dev/null || echo '{_quote(default)}'"
        )

    def set(self, path: str, value: str) -> None:
        """Set a single UCI field with proper quoting."""
        self._ssh.exec(f"uci set {path}='{_quote(value)}'")

    def set_type(self, section: str, section_type: str) -> None:
        """Create or change a UCI section's type (no value quoting)."""
        self._ssh.exec(f"uci set {section}={section_type}")

    def delete(self, path: str) -> None:
        """Delete a UCI section or field (idempotent)."""
        self._ssh.exec(f"uci -q delete {path} 2>/dev/null; true")

    def add_list(self, path: str, value: str) -> None:
        """Append a value to a UCI list field."""
        self._ssh.exec(f"uci add_list {path}='{_quote(value)}'")

    def del_list(self, path: str, value: str) -> None:
        """Remove a value from a UCI list field (exact-match)."""
        self._ssh.exec(f"uci del_list {path}='{_quote(value)}'")

    def commit(self, *configs: str) -> None:
        """Commit one or more UCI configs."""
        cmd = " && ".join(f"uci commit {c}" for c in configs)
        self._ssh.exec(cmd)

    def add(self, config: str, section_type: str) -> str:
        """Add an anonymous section, returning its identifier."""
        return self._ssh.exec(f"uci add {config} {section_type}")

    def reorder(self, section: str, index: int) -> None:
        """Set the order of a UCI section."""
        self._ssh.exec(f"uci reorder {section}={index}")

    def rename(self, section: str, name: str) -> None:
        """Rename a UCI section (e.g. heal anonymous @rule[N])."""
        self._ssh.exec(f"uci rename {section}={name} && uci commit {section.split('.')[0]}")

    # ── Show / parse ────────────────────────────────────────────────────

    def show(self, config: str) -> dict:
        """Run ``uci show <config>`` and return parsed sections dict."""
        raw = self._ssh.exec(f"uci show {config} 2>/dev/null || echo ''")
        return self.parse_show(raw, config)

    @staticmethod
    def parse_show(raw: str, prefix: str) -> dict:
        """Parse ``uci show`` output into ``{section: {field: value}}``.

        Ported from ``RouterAPI._parse_uci_show()``.

        The ``_type`` key holds the section type. Fields that appear
        multiple times become lists.
        """
        sections: dict = {}
        dot_prefix = prefix + "."
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip("'")
            if not key.startswith(dot_prefix):
                continue
            after = key[len(dot_prefix):]
            if "." in after:
                section, field = after.split(".", 1)
            else:
                section = after
                field = None
            entry = sections.setdefault(section, {})
            if field is None:
                entry["_type"] = val
            elif field in entry:
                cur = entry[field]
                if isinstance(cur, list):
                    cur.append(val)
                else:
                    entry[field] = [cur, val]
            else:
                entry[field] = val
        return sections

    # ── Multi-command / batch operations ────────────────────────────────

    def ensure_firewall_include(
        self, name: str, script_path: str, reload: str = "1"
    ) -> None:
        """Register a firewall include script if not already present.

        Creates a ``firewall.<name>=include`` section with ``path`` and
        ``reload`` fields. Idempotent — skips if the section exists.
        """
        self._ssh.exec(
            f"uci -q get firewall.{name} >/dev/null 2>&1 || ("
            f"uci set firewall.{name}=include && "
            f"uci set firewall.{name}.type='script' && "
            f"uci set firewall.{name}.path='{script_path}' && "
            f"uci set firewall.{name}.reload='{reload}' && "
            f"uci commit firewall)"
        )

    def multi(self, cmds: list[str]) -> None:
        """Execute multiple UCI commands chained with ``&&``."""
        if cmds:
            self._ssh.exec(" && ".join(cmds))

    def batch_sections(
        self,
        sections: list[tuple[str, dict]],
        *commit_configs: str,
    ) -> None:
        """Build a UCI batch from structured section data and execute it.

        Each entry is ``(section_path, fields_dict)`` where ``fields_dict``
        uses the same conventions as ``batch_set``: key ``"_type"`` emits
        ``set section=value``, other keys emit ``set section.key='value'``.

        All values are properly quoted via ``_quote()``.  This is safer
        than building raw batch strings manually.

        Example::

            uci.batch_sections([
                ("wireless.fvpn_net_2g", {
                    "_type": "wifi-iface",
                    "ssid": "O'Brien's WiFi",
                    "encryption": "psk2",
                }),
                ("network.fvpn_net", {
                    "_type": "interface",
                    "ipaddr": "192.168.9.1",
                }),
            ], "wireless", "network")
        """
        lines = []
        for section, fields in sections:
            for key, val in fields.items():
                if key == "_type":
                    lines.append(f"set {section}={val}")
                else:
                    lines.append(f"set {section}.{key}='{_quote(str(val))}'")
        if lines:
            self.batch("\n".join(lines) + "\n", *commit_configs)

    def batch(self, lines: str, *commit_configs: str) -> None:
        """Write UCI commands to a temp file and execute via ``uci batch``.

        Args:
            lines: Newline-separated UCI commands (one per line).
            commit_configs: Configs to commit after the batch.
        """
        self._ssh.write_file(_BATCH_TMP, lines)
        commit_part = " && ".join(f"uci commit {c}" for c in commit_configs)
        cmd = f"uci batch < {_BATCH_TMP}"
        if commit_part:
            cmd += f" && {commit_part}"
        cmd += f" && rm -f {_BATCH_TMP}"
        self._ssh.exec(cmd)

    def batch_set(
        self,
        section: str,
        fields: dict,
        commit: str,
        add_lists: dict | None = None,
    ) -> None:
        """Build and execute a batch of ``uci set`` + ``uci add_list``.

        Ported from ``RouterAPI._uci_batch()``.

        Args:
            section: Full UCI section path (e.g. ``"wireguard.peer_9001"``).
            fields: ``{field: value}`` dict. Key ``"_type"`` emits
                ``uci set section=value`` (section type assignment).
            commit: UCI config to commit.
            add_lists: Optional ``{field: value}`` for ``add_list`` ops.
        """
        cmds = []
        for key, val in fields.items():
            if key == "_type":
                cmds.append(f"uci set {section}={val}")
            else:
                cmds.append(f"uci set {section}.{key}='{_quote(str(val))}'")
        for key, val in (add_lists or {}).items():
            cmds.append(f"uci add_list {section}.{key}='{_quote(str(val))}'")
        cmds.append(f"uci commit {commit}")
        self._ssh.exec(" && ".join(cmds))

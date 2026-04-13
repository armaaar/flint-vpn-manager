"""Router Tools — low-level CLI tool wrappers for the GL.iNet Flint 2.

Provides typed, consistent interfaces for UCI, ipset, iptables, iproute2,
and service control. Each tool class takes an SSH executor (anything with
exec/write_file/read_file methods — typically RouterAPI) and produces
properly quoted, idempotent shell commands.

Usage from a facade::

    class RouterPolicy:
        def __init__(self, ssh):
            self._uci = ssh.uci        # Uci instance on RouterAPI
            ...

Or standalone::

    from router.tools import Uci, Ipset
    uci = Uci(router)
    ipset = Ipset(router)
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class SshExecutor(Protocol):
    """Protocol matching RouterAPI's SSH primitives."""

    def exec(self, command: str, timeout: int = 30) -> str: ...

    def write_file(self, remote_path: str, content: str) -> None: ...

    def read_file(self, remote_path: str) -> Optional[str]: ...


from router.tools.uci import Uci
from router.tools.ipset import Ipset
from router.tools.iptables import Iptables
from router.tools.iproute import Iproute
from router.tools.service_ctl import ServiceCtl

__all__ = [
    "SshExecutor",
    "Uci",
    "Ipset",
    "Iptables",
    "Iproute",
    "ServiceCtl",
]

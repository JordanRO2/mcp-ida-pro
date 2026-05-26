"""Compatibility shim. Canonical module: infrastructure.trace.

Kept so existing imports (`from . import trace`) keep working until the
tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.trace`` path.
"""

from .infrastructure.trace import *  # noqa: F401,F403
from .infrastructure.trace import (  # noqa: F401
    configure_idb,
    install_tracer,
    shutdown,
    iter_idb_records,
    IDB_NETNODE_NAME,
)

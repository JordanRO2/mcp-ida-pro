"""Compatibility shim. Canonical module: infrastructure.sync.sync.

Kept so existing intra-package imports (`from .sync import idasync`, etc.)
keep working until the tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.sync.sync`` path.
"""

from .infrastructure.sync.sync import *  # noqa: F401,F403
from .infrastructure.sync.sync import (  # noqa: F401
    idasync,
    keep_batch,
    get_pre_call_batch,
    sync_wrapper,
    tool_timeout,
    IDAError,
    IDASyncError,
    CancelledError,
    is_window_active,
    ida_major,
    ida_minor,
)

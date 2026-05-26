"""Compatibility shim. Canonical module: infrastructure.http.handler.

Kept so existing imports (`from .http import IdaMcpHttpRequestHandler`) keep
working until the tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.http.handler`` path.
"""

from .infrastructure.http.handler import *  # noqa: F401,F403
from .infrastructure.http.handler import (  # noqa: F401
    IdaMcpHttpRequestHandler,
    config_json_get,
    config_json_set,
    handle_enabled_tools,
    get_cors_policy,
    DEFAULT_CORS_POLICY,
    ORIGINAL_TOOLS,
)

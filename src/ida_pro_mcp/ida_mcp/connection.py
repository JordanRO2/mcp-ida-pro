"""Compatibility shim. Canonical module: infrastructure.connection.

Kept so existing imports (`from .ida_mcp.connection import ...`,
`from ida_mcp.connection import ...`) keep working until the tool-migration
phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.connection`` path.
"""

from .infrastructure.connection import *  # noqa: F401,F403
from .infrastructure.connection import (  # noqa: F401
    connection_file_path,
    generate_token,
    write_connection_file,
    read_connection_file,
    remove_connection_file,
    tokens_match,
)

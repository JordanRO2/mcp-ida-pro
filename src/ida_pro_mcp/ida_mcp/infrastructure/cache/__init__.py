"""Infrastructure-level caches for the IDA Pro MCP server.

Canonical home of the strings cache and the ``init_caches`` plugin-startup
entry point (relocated from the legacy flat ``api_core`` module).
"""

from .strings_cache import (
    get_strings_cache,
    invalidate_strings_cache,
    is_strings_cache_ready,
    strings_cache_size,
    server_started_at,
    init_caches,
)

__all__ = [
    "get_strings_cache",
    "invalidate_strings_cache",
    "is_strings_cache_ready",
    "strings_cache_size",
    "server_started_at",
    "init_caches",
]

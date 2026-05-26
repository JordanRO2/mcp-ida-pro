"""Strings cache for the IDA Pro MCP server.

Caches the IDB strings list ``[(ea, text), ...]`` so repeated string queries
(``find_regex``, ``entity_query`` kind=strings) do not rebuild it each call.

Relocated verbatim from the legacy flat ``api_core`` module. ``init_caches`` is
the plugin-startup entry point (called from the Ctrl+M handler and from
``server_warmup``). Its canonical import path is now
``ida_pro_mcp.ida_mcp.infrastructure.cache``.
"""

from __future__ import annotations

import time

import idautils

# Cached strings list: [(ea, text), ...]
_strings_cache: list[tuple[int, str]] | None = None
_server_started_at = time.time()


def get_strings_cache() -> list[tuple[int, str]]:
    """Get cached strings, building cache on first access."""
    global _strings_cache
    if _strings_cache is None:
        _strings_cache = [(s.ea, str(s)) for s in idautils.Strings() if s is not None]
    return _strings_cache


def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache
    _strings_cache = None


def is_strings_cache_ready() -> bool:
    """Return whether the strings cache has been built."""
    return _strings_cache is not None


def strings_cache_size() -> int:
    """Return the number of cached strings (0 when not built)."""
    return len(_strings_cache) if _strings_cache is not None else 0


def server_started_at() -> float:
    """Return the monotonic-ish wall-clock time the server module loaded."""
    return _server_started_at


def init_caches():
    """Build caches on plugin startup (called from Ctrl+M)."""
    t0 = time.perf_counter()
    strings = get_strings_cache()
    t1 = time.perf_counter()
    print(f"[MCP] Cached {len(strings)} strings in {(t1 - t0) * 1000:.0f}ms")

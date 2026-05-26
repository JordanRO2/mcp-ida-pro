"""IDA Pro MCP Plugin - Modular Package Version

This package provides MCP (Model Context Protocol) integration for IDA Pro,
enabling AI assistants to interact with IDA's disassembler and decompiler.

Architecture:
- rpc.py: JSON-RPC infrastructure and registry
- mcp.py: MCP protocol server (HTTP/SSE)
- sync.py: IDA synchronization decorator (@idasync)
- utils.py: Shared helpers and TypedDict definitions
- api_*.py: Modular API implementations (71 tools + 24 resources)
"""

# Ignore SIGPIPE to prevent IDA from being killed when an MCP client
# disconnects while the HTTP server is writing a response. IDA's embedded
# Python may not preserve CPython's default SIG_IGN for SIGPIPE.
import signal

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

# Import infrastructure modules
from . import rpc
from . import container
from .infrastructure.sync import sync as sync
from . import utils

# Import all API modules to register @tool functions and @resource functions
from . import api_core
from . import api_analysis
from . import api_memory
from . import api_types
from . import api_modify
from . import api_stack
from . import api_debug
from . import api_python
from . import api_resources
from . import api_survey
from . import api_composite
from . import api_security
from . import api_sigmaker
from .infrastructure import trace as trace

# Re-export key components for external use
from .infrastructure.sync.sync import (
    idasync,
    IDAError,
    IDASyncError,
    CancelledError,
)
from .rpc import MCP_SERVER, MCP_UNSAFE, tool, unsafe, resource, ext
from .infrastructure.http.handler import IdaMcpHttpRequestHandler
from .api_core import init_caches

# Tracing is always on: every tools/call is recorded into the IDB netnode.
trace.configure_idb()

# Optional tool profile (whitelist) via the IDA_MCP_PROFILE environment variable.
# Points at a profile file (e.g. profiles/readonly.txt). When set, only the
# whitelisted tools — plus the protected infrastructure tools below — are
# exposed in tools/list and callable. Configured by the user, never via MCP.
import os as _os

_profile_path = _os.environ.get("IDA_MCP_PROFILE")
if _profile_path:
    import logging as _logging
    from .application.profile import load_profile as _load_profile

    try:
        _whitelist = _load_profile(_profile_path)
        MCP_SERVER.set_tool_profile(
            _whitelist, protected={"server_health", "server_warmup"}
        )
        _logging.getLogger(__name__).info(
            "IDA_MCP_PROFILE applied: %d whitelisted tool(s) from %s",
            len(_whitelist),
            _profile_path,
        )
    except Exception as _exc:
        _logging.getLogger(__name__).warning(
            "Failed to load IDA_MCP_PROFILE '%s': %s", _profile_path, _exc
        )

__all__ = [
    # Infrastructure modules
    "rpc",
    "container",
    "sync",
    "utils",
    # API modules
    "api_core",
    "api_analysis",
    "api_memory",
    "api_types",
    "api_modify",
    "api_stack",
    "api_debug",
    "api_python",
    "api_resources",
    "api_survey",
    "api_composite",
    "api_security",
    "api_sigmaker",
    "trace",
    # Re-exported components
    "idasync",
    "IDAError",
    "IDASyncError",
    "CancelledError",
    "MCP_SERVER",
    "MCP_UNSAFE",
    "tool",
    "unsafe",
    "resource",
    "ext",
    "IdaMcpHttpRequestHandler",
    "init_caches",
]

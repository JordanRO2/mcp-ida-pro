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

# Import all interface modules to register @tool / @resource functions
from .interface.tools import core_tools as core_tools
from .interface.tools import analysis_tools as analysis_tools
from .interface.tools import composite_tools as composite_tools
from .interface.tools import survey_tools as survey_tools
from .interface.tools import memory_tools as memory_tools
from .interface.tools import types_tools as types_tools
from .interface.tools import modify_tools as modify_tools
from .interface.tools import stack_tools as stack_tools
from .interface.tools import debug_tools as debug_tools
from .interface.tools import python_exec_tools as python_exec_tools
from .interface.tools import security_tools as security_tools
from .interface.tools import sigmaker_tools as sigmaker_tools
from .interface.resources import resources_resources as resources_resources
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
from .infrastructure.cache import init_caches

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
    # Interface modules (tools/resources)
    "core_tools",
    "analysis_tools",
    "composite_tools",
    "survey_tools",
    "memory_tools",
    "types_tools",
    "modify_tools",
    "stack_tools",
    "debug_tools",
    "python_exec_tools",
    "security_tools",
    "sigmaker_tools",
    "resources_resources",
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

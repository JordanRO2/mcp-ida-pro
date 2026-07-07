"""MCP tools for code analysis, decompilation, xrefs, search and call graphs."""

from __future__ import annotations

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync, tool_timeout
from ...container import get_analysis_service
from ...domain.entities import (
    StructFieldQuery,
    XrefQuery,
    FuncProfileQuery,
    AnalyzeBatchQuery,
)
from ...domain.value_objects import InsnPattern


# ============================================================================
# Code Analysis & Decompilation
# ============================================================================


@tool
@idasync
@tool_timeout(90.0)
def decompile(
    addr: Annotated[str, "Function address or name to decompile"],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 90)"] = None,
) -> dict:
    """Decompile function(s) at address(es); returns pseudocode and per-item errors."""
    return get_analysis_service().decompile(addr, timeout)


@tool
@idasync
@tool_timeout(90.0)
def disasm(
    addr: Annotated[str, "Function address or name to disassemble"],
    max_instructions: Annotated[
        int, "Max instructions per function (default: 5000, max: 50000)"
    ] = 5000,
    offset: Annotated[int, "Skip first N instructions (default: 0)"] = 0,
    include_total: Annotated[
        bool, "Compute total instruction count (default: false)"
    ] = False,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 90)"] = None,
) -> dict:
    """Disassemble function with offset/max_instructions pagination and optional total count."""
    return get_analysis_service().disasm(
        addr, max_instructions, offset, include_total, timeout
    )


# ============================================================================
# Batch Analysis & Profiling
# ============================================================================


@tool
@idasync
@tool_timeout(120.0)
def func_profile(
    queries: Annotated[
        list[FuncProfileQuery] | FuncProfileQuery | str,
        "Function profiling query (supports name/address filters + pagination)",
    ],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> list[dict]:
    """Profile functions with summary metrics and optional sampled details."""
    return get_analysis_service().func_profile(queries, timeout)


@tool
@idasync
@tool_timeout(120.0)
def analyze_batch(
    queries: Annotated[
        list[AnalyzeBatchQuery] | AnalyzeBatchQuery | str,
        "Comprehensive per-function analysis with selectable sections",
    ],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> list[dict]:
    """Run comprehensive analysis over one or more target functions."""
    return get_analysis_service().analyze_batch(queries, timeout)


# ============================================================================
# Cross-Reference Analysis
# ============================================================================


@tool
@idasync
def xrefs_to(
    addrs: Annotated[
        list[str] | str,
        "Addresses or function names to find cross-references to (e.g. '0x11a9', 'check_pw', 'main')",
    ],
    limit: Annotated[int, "Max xrefs per address (default: 100, max: 1000)"] = 100,
) -> list[dict]:
    """Return xrefs to address(es) or named symbols, capped per target with truncation flag."""
    return get_analysis_service().xrefs_to(addrs, limit)


@tool
@idasync
def xref_query(
    queries: Annotated[
        list[XrefQuery] | XrefQuery | str,
        "Generic xref query with direction/type filters and pagination",
    ],
) -> list[dict]:
    """Query xrefs with direction/type filters and pagination."""
    return get_analysis_service().xref_query(queries)


@tool
@idasync
def xrefs_to_field(queries: list[StructFieldQuery] | StructFieldQuery) -> list[dict]:
    """Get cross-references to structure fields"""
    return get_analysis_service().xrefs_to_field(queries)


# ============================================================================
# Call Graph Analysis
# ============================================================================


@tool
@idasync
def callees(
    addrs: Annotated[
        list[str] | str, "Function addresses or names to get callees for (e.g. '0x123e', 'main')"
    ],
    limit: Annotated[int, "Max callees per function (default: 200, max: 500)"] = 200,
) -> list[dict]:
    """Return unique callees per function, capped by limit."""
    return get_analysis_service().callees(addrs, limit)


# ============================================================================
# Pattern Matching & Signature Tools
# ============================================================================


@tool
@idasync
@tool_timeout(120)
def find_bytes(
    patterns: Annotated[
        list[str] | str, "Byte patterns to search for (e.g. '48 8B ?? ??')"
    ],
    limit: Annotated[int, "Max matches per pattern (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> list[dict]:
    """Search byte patterns (supports ??) with offset/limit pagination."""
    return get_analysis_service().find_bytes(patterns, limit, offset, timeout)


# ============================================================================
# Control Flow Analysis
# ============================================================================


@tool
@idasync
def basic_blocks(
    addrs: Annotated[
        list[str] | str,
        "Function addresses or names to get basic blocks for (e.g. '0x123e', 'main')",
    ],
    max_blocks: Annotated[
        int, "Max basic blocks per function (default: 1000, max: 10000)"
    ] = 1000,
    offset: Annotated[int, "Skip first N blocks (default: 0)"] = 0,
) -> list[dict]:
    """Return function CFG blocks with offset/max_blocks pagination."""
    return get_analysis_service().basic_blocks(addrs, max_blocks, offset)


# ============================================================================
# Search Operations
# ============================================================================


@tool
@idasync
@tool_timeout(120)
def find(
    type: Annotated[
        str, "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'"
    ],
    targets: Annotated[
        list[str | int] | str | int, "Search targets (strings, integers, or addresses)"
    ],
    limit: Annotated[int, "Max matches per target (default: 1000, max: 10000)"] = 1000,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> list[dict]:
    """Search strings/immediates/refs for targets with offset/limit pagination."""
    return get_analysis_service().find(type, targets, limit, offset, timeout)


@tool
@idasync
@tool_timeout(120)
def insn_query(
    queries: Annotated[
        list[InsnPattern] | InsnPattern | str,
        "Instruction query with mnemonic/operand filters and scoped scan",
    ],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> list[dict]:
    """Query instructions with mnemonic/operand filters and scoped scans."""
    return get_analysis_service().insn_query(queries, timeout)


# ============================================================================
# Export Operations
# ============================================================================


@tool
@idasync
def export_funcs(
    addrs: Annotated[
        list[str] | str, "Function addresses or names to export (e.g. '0x123e', 'main')"
    ],
    format: Annotated[
        str, "Export format: json (default), c_header, or prototypes"
    ] = "json",
) -> dict:
    """Export function data for addresses in json/c_header/prototypes formats."""
    return get_analysis_service().export_funcs(addrs, format)


# ============================================================================
# Graph Operations
# ============================================================================


@tool
@idasync
def callgraph(
    roots: Annotated[
        list[str] | str, "Root function addresses to start call graph traversal from"
    ],
    max_depth: Annotated[int, "Maximum depth for call graph traversal"] = 5,
    max_nodes: Annotated[
        int, "Max nodes across the graph (default: 1000, max: 100000)"
    ] = 1000,
    max_edges: Annotated[
        int, "Max edges across the graph (default: 5000, max: 200000)"
    ] = 5000,
    max_edges_per_func: Annotated[
        int, "Max edges per function (default: 200, max: 5000)"
    ] = 200,
) -> list[dict]:
    """Build bounded callgraph from roots with depth/node/edge limits."""
    return get_analysis_service().callgraph(
        roots, max_depth, max_nodes, max_edges, max_edges_per_func
    )

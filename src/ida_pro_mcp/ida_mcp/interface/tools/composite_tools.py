"""Composite analysis tools that aggregate multiple data sources."""

from __future__ import annotations

from typing import Annotated

from ...rpc import tool, unsafe
from ...infrastructure.sync.sync import idasync, tool_timeout
from ...container import get_composite_service


@tool
@idasync
@tool_timeout(120.0)
def analyze_function(
    addr: Annotated[str, "Function address or name"],
    include_asm: Annotated[bool, "Include full disassembly (default: false, saves tokens)"] = False,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Get a compact analysis of a single function: decompiled pseudocode (capped
    at 100 lines), top 10 strings as values, top 10 non-trivial constants, caller
    and callee names, cross-references, and basic block metrics. Disassembly is
    excluded by default to save context tokens — set include_asm=true only when
    you need raw instructions (crypto analysis, shellcode, decompiler failure).
    Use this instead of calling decompile, disasm, callees, xrefs_to, stack_frame,
    and basic_blocks separately."""
    return get_composite_service().analyze_function(addr, include_asm=include_asm)


@tool
@idasync
@tool_timeout(180.0)
def analyze_component(
    addrs: Annotated[list[str] | str, "Function addresses (comma-separated or list)"],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 180)"] = None,
) -> dict:
    """Analyze a group of related functions as one logical unit. Returns a COMPACT
    summary of each function (name, prototype, size, callee names, top 5 strings,
    block count) plus relationship data: internal call graph, shared globals,
    interface vs internal classification, and strings used by multiple functions.
    Use analyze_function on individual addresses if you need full decompilation.
    Use this when you see a cluster of sub_* functions called from the same parent
    or when callees/callers overlap suggests a module."""
    return get_composite_service().analyze_component(addrs)


@tool
@unsafe
@idasync
@tool_timeout(120.0)
def diff_before_after(
    addr: Annotated[str, "Function address"],
    action: Annotated[str, "Action: 'rename_func', 'set_type', 'set_comment'"],
    action_args: Annotated[dict, "Arguments for the action"],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Rename a function, set its type, or add a comment, and immediately see the
    before/after decompilation side by side. Use this instead of calling rename
    then decompile separately when you want to verify that a rename or type change
    actually improved readability. Actions: 'rename_func' (action_args: {name: str}),
    'set_type' (action_args: {type: str}), 'set_comment' (action_args: {comment: str}).
    Returns {before, after, action_applied, changes_detected}. Especially useful
    during batch renaming to confirm each change had the intended effect."""
    return get_composite_service().diff_before_after(addr, action, action_args)


@tool
@idasync
@tool_timeout(120.0)
def trace_data_flow(
    addr: Annotated[str, "Starting address"],
    direction: Annotated[str, "'forward' (xrefs from) or 'backward' (xrefs to)"] = "forward",
    max_depth: Annotated[int, "Maximum traversal depth"] = 5,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Follow cross-references from or to an address, automatically traversing
    multiple hops. Use 'forward' to see where data flows TO (xrefs-from), or
    'backward' to see where data flows FROM (xrefs-to). At each node in the
    traversal, returns the function name, instruction, and whether it's code or
    data. Use this when you find an interesting string, constant, or global and
    want to understand every code path that touches it without manually chaining
    xrefs_to calls. Do not use for call graph traversal — use callgraph for that.
    max_depth controls how many hops to follow (default 5, max 20)."""
    return get_composite_service().trace_data_flow(addr, direction, max_depth)

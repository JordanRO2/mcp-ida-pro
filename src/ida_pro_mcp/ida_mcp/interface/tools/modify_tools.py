"""MCP tools for IDB-mutating operations (api_modify domain).

Thin ``@tool`` / ``@idasync`` wrappers that preserve the exact public names,
signatures, decorators and docstrings of the original flat ``api_modify``
module and delegate to ``ModifyService`` resolved from the DI container. These
tools MUTATE the IDB (set comments, patch asm, rename, define/undefine, etc.).
"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...container import get_modify_service
from ...domain.entities import (
    CommentOp,
    CommentAppendOp,
    AsmPatchOp,
    RenameBatch,
    DefineOp,
    UndefineOp,
)

# ForceRecompileOp / SetOpTypeOp / MakeDataOp live in utils.py (the canonical
# TypedDict home). They are imported directly here rather than re-exported via
# domain.entities because domain/entities/__init__.py is owned by another agent.
from ...utils import (
    ForceRecompileOp,
    SetOpTypeOp,
    MakeDataOp,
)


# ============================================================================
# Modification Operations
# ============================================================================


@tool
@idasync
def set_comments(items: list[CommentOp] | CommentOp):
    """Set comments at addresses (both disassembly and decompiler views)"""
    return get_modify_service().set_comments(items)


@tool
@idasync
def append_comments(items: list[CommentAppendOp] | CommentAppendOp):
    """Append comments at addresses, deduping exact text by default."""
    return get_modify_service().append_comments(items)


@tool
@idasync
def patch_asm(items: list[AsmPatchOp] | AsmPatchOp) -> list[dict]:
    """Patch assembly instructions at addresses"""
    return get_modify_service().patch_asm(items)


@tool
@idasync
def rename(batch: RenameBatch | dict) -> dict:
    """Batch-rename funcs/globals/locals/stack vars with dry-run options."""
    return get_modify_service().rename(batch)


@tool
@idasync
def define_func(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Define functions; IDA infers bounds unless end is provided."""
    return get_modify_service().define_func(items)


@tool
@idasync
def define_code(items: list[DefineOp] | DefineOp) -> list[dict]:
    """Convert bytes to code instruction(s) at address(es)."""
    return get_modify_service().define_code(items)


@tool
@idasync
def undefine(items: list[UndefineOp] | UndefineOp) -> list[dict]:
    """Undefine item(s) at address(es), converting back to raw bytes."""
    return get_modify_service().undefine(items)


@tool
@idasync
def force_recompile(
    items: Annotated[
        list[ForceRecompileOp] | ForceRecompileOp,
        "List of {addr: function-entry-EA} ops, or a single op. Omit / pass empty list to recompile every function.",
    ] = None,
) -> dict:
    """Invalidate the Hex-Rays decompile cache for one or more functions.

    Use after `set_type`, `rename` (especially of locals), `set_op_type`, or
    `make_data` so the next `decompile` call regenerates fresh pseudocode
    instead of returning a cached, stale view.
    """
    return get_modify_service().force_recompile(items)


@tool
@idasync
def set_op_type(
    items: Annotated[
        list[SetOpTypeOp] | SetOpTypeOp,
        "Operand-typing ops. Equivalent to GUI 'Y' (struct offset) or 'O' (offset) operations.",
    ],
) -> list[dict]:
    """Set the type of an instruction operand. GUI 'Y' / 'O' / '#' equivalent.

    Tags an operand at a specific instruction with a desired interpretation.
    Useful when the decompiler picks an awkward expression form (e.g., the
    "earlier-named-symbol + offset" form for contiguous globals).

    `kind` values:
    - `"stroff"`: struct-offset reference. Requires `struct`, optional `delta`.
    - `"offset"`: absolute offset / pointer. Optional `target_addr`.
    - `"hex" | "dec" | "char" | "binary" | "octal"`: numeric format.
    - `"stkvar"`: stack-variable reference (function-local).
    """
    return get_modify_service().set_op_type(items)


@tool
@idasync
def make_data(
    items: Annotated[
        list[MakeDataOp] | MakeDataOp,
        "Data-creation ops. Each {addr, type, name?} replaces existing data items at addr with a fresh symbol of the given type.",
    ],
) -> list[dict]:
    """Create a typed data symbol at an address, replacing any prior items.

    Use to harden a symbol boundary the decompiler expresses through a
    neighboring global plus offset. `set_type` alone leaves the byte items
    unchanged; this deletes them, re-creates at the right size and type, then
    optionally renames and flushes the decompiler cache.
    """
    return get_modify_service().make_data(items)


@tool
@idasync
def add_bookmark(
    addr: Annotated[str, "Address to bookmark"],
    name: Annotated[str, "Bookmark label text after the prefix"],
    prefix: Annotated[
        str,
        "Optional title prefix. Defaults to 'idaMCP: '; pass '' for no prefix.",
    ] = "idaMCP: ",
) -> dict:
    """Add or replace the IDA bookmark at an address. Set prefix="" for no prefix."""
    return get_modify_service().add_bookmark(addr, name, prefix)

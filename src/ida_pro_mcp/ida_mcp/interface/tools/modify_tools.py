"""MCP tools for IDB-mutating operations (api_modify domain).

Thin ``@tool`` / ``@idasync`` wrappers that preserve the exact public names,
signatures, decorators and docstrings of the original flat ``api_modify``
module and delegate to ``ModifyService`` resolved from the DI container. These
tools MUTATE the IDB (set comments, patch asm, rename, define/undefine, etc.).
"""

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

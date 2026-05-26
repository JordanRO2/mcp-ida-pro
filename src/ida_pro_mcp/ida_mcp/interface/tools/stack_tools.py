"""Stack frame operations for IDA Pro MCP.

This module provides batch operations for managing stack frame variables,
including reading, creating, and deleting stack variables in functions.
"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...container import get_stack_service
from ...domain.entities import StackVarDecl, StackVarDelete


# ============================================================================
# Stack Frame Operations
# ============================================================================


@tool
@idasync
def stack_frame(addrs: Annotated[list[str] | str, "Address(es)"]) -> list[dict]:
    """Return stack variables for function address(es)."""
    return get_stack_service().stack_frame(addrs)


@tool
@idasync
def declare_stack(
    items: list[StackVarDecl] | StackVarDecl,
):
    """Create stack variables from typed stack declarations."""
    return get_stack_service().declare_stack(items)


@tool
@idasync
def delete_stack(
    items: list[StackVarDelete] | StackVarDelete,
):
    """Delete stack variables by name or offset."""
    return get_stack_service().delete_stack(items)

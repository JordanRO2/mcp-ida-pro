"""Debugger operations for IDA Pro MCP.

This module provides comprehensive debugging functionality including:
- Debugger control (start, exit, continue, step, run_to)
- Breakpoint management (add, delete, enable/disable, conditions, list)
- Register inspection (all registers, GP registers, specific registers)
- Memory operations (read/write debugger memory)
- Call stack inspection
"""

from typing import Annotated

from ...rpc import tool, unsafe, ext
from ...infrastructure.sync.sync import idasync, keep_batch
from ...container import get_debug_service
from ...domain.entities import (
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
)
from ...utils import BreakpointConditionOp
from ...application.services.debug_service import (
    DebugControlResult,
    BreakpointResult,
    ThreadRegistersResult,
    StackFrameInfo,
    DebugMemoryReadResult,
    DebugMemoryWriteResult,
)


# ============================================================================
# Debugger Control Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
@keep_batch
def dbg_start() -> DebugControlResult:
    """Start debugger session for current target.

    Requires the user to have selected a debugger (Debugger -> Select debugger)
    and configured the target (executable path, arguments, attach process,
    remote host, etc.). If this call fails, do not retry repeatedly. Stop,
    explain to the user that debugging is not yet configured, and ask them
    to set up the debugger and dismiss any IDA dialogs (e.g. "matching
    executable names") before trying again.
    """
    return get_debug_service().start()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_status() -> DebugControlResult:
    """Return debugger lifecycle state and current IP if suspended."""
    return get_debug_service().status()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_exit() -> DebugControlResult:
    """Terminate active debugger session."""
    return get_debug_service().exit()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_continue() -> DebugControlResult:
    """Resume execution in active debugger session."""
    return get_debug_service().continue_()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_run_to(
    addr: Annotated[str, "Target execution address (hex or decimal)"],
) -> DebugControlResult:
    """Run debuggee until target address is reached."""
    return get_debug_service().run_to(addr)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_into() -> DebugControlResult:
    """Execute one instruction, stepping into calls."""
    return get_debug_service().step_into()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_step_over() -> DebugControlResult:
    """Execute one instruction, stepping over calls."""
    return get_debug_service().step_over()


# ============================================================================
# Breakpoint Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_bps() -> list[Breakpoint]:
    """List breakpoints with address, enabled status, condition, and language."""
    return get_debug_service().list_bps()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_add_bp(
    addrs: Annotated[list[str] | str, "Address(es) to add breakpoints at"],
) -> list[BreakpointResult]:
    """Add breakpoints at one or more addresses."""
    return get_debug_service().add_bp(addrs)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_delete_bp(
    addrs: Annotated[list[str] | str, "Address(es) to delete breakpoints from"],
) -> list[BreakpointResult]:
    """Delete breakpoints at one or more addresses."""
    return get_debug_service().delete_bp(addrs)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_toggle_bp(
    items: list[BreakpointOp] | BreakpointOp,
) -> list[BreakpointResult]:
    """Enable or disable existing breakpoints in batch."""
    return get_debug_service().toggle_bp(items)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_set_bp_condition(
    items: list[BreakpointConditionOp] | BreakpointConditionOp,
) -> list[BreakpointResult]:
    """Set or clear breakpoint conditions in batch."""
    return get_debug_service().set_bp_condition(items)


# ============================================================================
# Register Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_all() -> list[ThreadRegisters]:
    """Return full register sets for all debugger threads."""
    return get_debug_service().regs_all()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get registers for"],
) -> list[ThreadRegistersResult]:
    """Return full register sets for specified thread IDs."""
    return get_debug_service().regs_remote(tids)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs() -> ThreadRegisters:
    """Return full registers for current debugger thread."""
    return get_debug_service().regs()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs_remote(
    tids: Annotated[list[int] | int, "Thread ID(s) to get GP registers for"],
) -> list[ThreadRegistersResult]:
    """Get GP registers for threads"""
    return get_debug_service().gpregs_remote(tids)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_gpregs() -> ThreadRegisters:
    """Get current thread GP registers"""
    return get_debug_service().gpregs()


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named_remote(
    thread_id: Annotated[int, "Thread ID"],
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Return selected registers for a specific thread ID."""
    return get_debug_service().regs_named_remote(thread_id, register_names)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_regs_named(
    register_names: Annotated[
        str, "Comma-separated register names (e.g., 'RAX, RBX, RCX')"
    ],
) -> ThreadRegisters:
    """Get specific current thread registers"""
    return get_debug_service().regs_named(register_names)


# ============================================================================
# Call Stack Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_stacktrace() -> list[StackFrameInfo]:
    """Return current call stack with module and symbol context."""
    return get_debug_service().stacktrace()


# ============================================================================
# Debugger Memory Operations
# ============================================================================


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_read(
    regions: list[MemoryRead] | MemoryRead,
) -> list[DebugMemoryReadResult]:
    """Read debuggee memory from one or more regions."""
    return get_debug_service().read(regions)


@ext("dbg")
@unsafe
@tool
@idasync
def dbg_write(
    regions: list[MemoryPatch] | MemoryPatch,
) -> list[DebugMemoryWriteResult]:
    """Write bytes to debuggee memory regions."""
    return get_debug_service().write(regions)

"""Application service for IDA debugger operations.

Orchestration logic moved faithfully from the former ``api_debug.py`` tool
bodies. Raw SDK access is delegated to ``DebugAdapter``. The batch-mode
lifecycle around ``dbg_start`` (DBG_Hooks restore + register_timer fallback,
``get_pre_call_batch`` capture) is preserved exactly; the ``@keep_batch``
decorator remains on the tool function in the interface layer.

``idaapi`` / ``ida_dbg`` / ``ida_kernwin`` / ``idc`` are imported lazily so the
module can be imported (and py_compiled) outside of IDA. The ``_DbgStartBatchHook``
class is built lazily inside the service because it subclasses
``ida_dbg.DBG_Hooks``.
"""

from __future__ import annotations

from typing import TypedDict, NotRequired

from ...infrastructure.sync.sync import IDAError, get_pre_call_batch
from ...infrastructure.adapters.debug_adapter import DebugAdapter
from ...domain.entities import (
    ThreadRegisters,
    Breakpoint,
    BreakpointOp,
    MemoryRead,
    MemoryPatch,
)
from ...utils import (
    BreakpointConditionOp,
    normalize_list_input,
    normalize_dict_list,
    parse_address,
)


class DebugControlResult(TypedDict, total=False):
    ip: str
    started: bool
    continued: bool
    running: bool
    suspended: bool
    exited: bool
    state: str
    error: str


class BreakpointResult(TypedDict, total=False):
    addr: str
    ok: bool
    condition: str | None
    language: str | None
    error: str


class ThreadRegistersResult(TypedDict, total=False):
    tid: int
    regs: ThreadRegisters | None
    error: str


class StackFrameInfo(TypedDict):
    addr: str
    module: str
    symbol: str


class DebugMemoryReadResult(TypedDict):
    addr: str | None
    size: int
    data: str | None
    error: NotRequired[str | None]


class DebugMemoryWriteResult(TypedDict, total=False):
    addr: str | None
    size: int
    ok: bool
    error: str | None


# Batch-mode lifecycle for dbg_start.
#
# start_process schedules work that runs on the IDA main thread *after* our
# execute_sync returns. That work can show modal dialogs (e.g. "matching
# executable names"), so we need batch mode to remain on across the
# execute_sync boundary, and we need to be sure to turn it back off once the
# debugger has actually come up (or failed to). _DbgStartBatchHook does both.
_DBG_START_BATCH_FALLBACK_MS = 30_000  # absolute ceiling on stuck-in-batch state
_DBG_START_WAIT_TIMEOUT_SEC = 10.0
_DBG_START_WAIT_POLL_MS = 100
_DBG_START_IP_GRACE_POLL_COUNT = 5


_DbgStartBatchHook_cls = None


def _get_dbg_start_batch_hook_cls():
    """Lazily build the DBG_Hooks subclass (needs ida_dbg at import time)."""
    global _DbgStartBatchHook_cls
    if _DbgStartBatchHook_cls is not None:
        return _DbgStartBatchHook_cls

    import ida_dbg
    import idc

    class _DbgStartBatchHook(ida_dbg.DBG_Hooks):
        """Restore batch mode as soon as the debugger has finished STARTUP.

        "Startup" ends at dbg_process_start / dbg_process_attach — by then any
        startup dialogs (e.g. "matching executable names") are done, but the
        user is still inside an active debug session and should see normal
        dialogs from here on. dbg_process_exit / dbg_process_detach also
        restore so we don't get stuck if the process dies before fully coming
        up.
        """

        def __init__(self, restore_batch: int):
            super().__init__()
            self._restore_batch = restore_batch
            self._done = False

        def dbg_process_start(self, pid, tid, ea, name, base, size):
            self._restore()

        def dbg_process_attach(self, pid, tid, ea, name, base, size):
            self._restore()

        def dbg_process_exit(self, pid, tid, ea, exit_code):
            self._restore()

        def dbg_process_detach(self, pid, tid, ea):
            self._restore()

        def fallback_restore(self):
            """Called by the safety timer if no debugger event ever arrives."""
            self._restore()

        def _restore(self):
            if self._done:
                return
            self._done = True
            try:
                self.unhook()
            except Exception:
                pass
            idc.batch(self._restore_batch)

    _DbgStartBatchHook_cls = _DbgStartBatchHook
    return _DbgStartBatchHook_cls


def _normalize_breakpoint_language(language: object) -> str | None:
    if language is None:
        return None
    text = str(language).strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered == "idc":
        return "IDC"
    if lowered == "python":
        return "Python"
    return text


class DebugService:
    """High-level service for IDA debugger operations."""

    def __init__(self, adapter: DebugAdapter):
        self.adapter = adapter
        self._dbg_start_batch_hook = None

    # =========================================================================
    # Internal state helpers
    # =========================================================================

    def _get_debug_state_result(self) -> DebugControlResult:
        state = self.adapter.get_process_state_name()
        result: DebugControlResult = {"state": state}
        if state == "running":
            result["running"] = True
        elif state == "suspended":
            result["suspended"] = True
            ip = self.adapter.get_ip_val()
            if ip is not None:
                result["ip"] = hex(ip)
        return result

    def _get_debug_start_result(self) -> DebugControlResult | None:
        if not self.adapter.is_debugger_on():
            return None
        result = self._get_debug_state_result()
        result["started"] = True
        return result

    def _arm_dbg_start_batch_hook(self, restore_batch: int) -> None:
        """Install the batch-restore hook before start_process is invoked."""
        import ida_kernwin

        if self._dbg_start_batch_hook is not None:
            self._dbg_start_batch_hook.fallback_restore()
        hook_cls = _get_dbg_start_batch_hook_cls()
        hook = hook_cls(restore_batch)
        hook.hook()
        self._dbg_start_batch_hook = hook

        def _fallback():
            if self._dbg_start_batch_hook is hook and not hook._done:
                hook.fallback_restore()
            return -1  # don't repeat

        ida_kernwin.register_timer(_DBG_START_BATCH_FALLBACK_MS, _fallback)

    # =========================================================================
    # Debugger Control Operations
    # =========================================================================

    def start(self) -> DebugControlResult:
        if len(self.adapter.list_breakpoints()) == 0:
            for addr in self.adapter.get_entry_addresses():
                self.adapter.add_bpt_soft(addr)

        # Arm a DBG_Hooks instance to switch IDA back to its pre-call batch
        # state once the debugger has actually started. Combined with
        # @keep_batch on the tool function, batch mode stays on across the
        # execute_sync boundary so dialogs the debugger plugin shows during
        # initialization (e.g. "matching executable names") are auto-handled.
        # The hook restores on dbg_process_start / _attach / _exit / _detach,
        # with a register_timer fallback so we never get stuck in batch mode.
        # Capture the pre-call batch (what the caller had set before the
        # sync wrapper bumped it to 1) so headless / batch-mode workflows
        # aren't silently flipped to interactive after dbg_start.
        pre_call_batch = get_pre_call_batch()
        if pre_call_batch is None:
            pre_call_batch = 0
        self._arm_dbg_start_batch_hook(restore_batch=pre_call_batch)

        # start_process is documented as asynchronous; when invoked from the
        # IDA main thread inside execute_sync the return code is unreliable
        # (often -1 even on success, because the dbg_process_start event has
        # not yet been dispatched). Trust the actual debugger state instead,
        # and only consult the return code as a tiebreaker for the error
        # message when nothing ever comes up.
        start_result = self.adapter.start_process()

        started = self._get_debug_start_result()
        if started is not None:
            if started.get("running") and "ip" not in started:
                for _ in range(_DBG_START_IP_GRACE_POLL_COUNT):
                    self.adapter.wait_for_next_event(_DBG_START_WAIT_POLL_MS)
                    waited = self._get_debug_start_result()
                    if waited is None:
                        continue
                    started = waited
                    if started.get("suspended") or "ip" in started:
                        break
            return started

        for _ in range(
            int(_DBG_START_WAIT_TIMEOUT_SEC * 1000 / _DBG_START_WAIT_POLL_MS)
        ):
            self.adapter.wait_for_next_event(_DBG_START_WAIT_POLL_MS)
            started = self._get_debug_start_result()
            if started is not None:
                return started

        if start_result == 0:
            raise IDAError(
                "Debugger start was cancelled. Stop and ask the user to configure "
                "the debugger (Debugger -> Select debugger, set the target path / "
                "arguments) and dismiss any IDA dialogs before retrying."
            )
        raise IDAError(
            "Failed to start debugger. Stop and ask the user to verify that a "
            "debugger is selected (Debugger -> Select debugger), the target is "
            "configured (executable path / arguments / remote host), and any "
            "pending IDA dialogs (e.g. \"matching executable names\") have been "
            "dismissed before retrying."
        )

    def status(self) -> DebugControlResult:
        return self._get_debug_state_result()

    def exit(self) -> DebugControlResult:
        self.adapter.ensure_active()
        if self.adapter.exit_process():
            return {"exited": True, "state": "not_running"}
        raise IDAError("Failed to exit debugger")

    def continue_(self) -> DebugControlResult:
        self.adapter.ensure_suspended()
        if self.adapter.continue_process():
            result = self._get_debug_state_result()
            result["continued"] = True
            return result
        raise IDAError("Failed to continue debugger")

    def run_to(self, addr: str) -> DebugControlResult:
        self.adapter.ensure_suspended()
        ea = parse_address(addr)
        if self.adapter.run_to(ea):
            result = self._get_debug_state_result()
            result["continued"] = True
            return result
        raise IDAError(f"Failed to run to address {hex(ea)}")

    def step_into(self) -> DebugControlResult:
        self.adapter.ensure_suspended()
        if self.adapter.step_into():
            result = self._get_debug_state_result()
            result["continued"] = True
            return result
        raise IDAError("Failed to step into")

    def step_over(self) -> DebugControlResult:
        self.adapter.ensure_suspended()
        if self.adapter.step_over():
            result = self._get_debug_state_result()
            result["continued"] = True
            return result
        raise IDAError("Failed to step over")

    # =========================================================================
    # Breakpoint Operations
    # =========================================================================

    def list_bps(self) -> list[Breakpoint]:
        return self.adapter.list_breakpoints()

    def add_bp(self, addrs) -> list[BreakpointResult]:
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                if self.adapter.add_bpt_soft(ea):
                    results.append({"addr": addr, "ok": True})
                else:
                    breakpoints = self.adapter.list_breakpoints()
                    for bpt in breakpoints:
                        if bpt["addr"] == hex(ea):
                            results.append({"addr": addr, "ok": True})
                            break
                    else:
                        results.append(
                            {"addr": addr, "error": "Failed to set breakpoint"}
                        )
            except Exception as e:
                results.append({"addr": addr, "error": str(e)})

        return results

    def delete_bp(self, addrs) -> list[BreakpointResult]:
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                if self.adapter.del_bpt(ea):
                    results.append({"addr": addr, "ok": True})
                else:
                    results.append(
                        {"addr": addr, "error": "Failed to delete breakpoint"}
                    )
            except Exception as e:
                results.append({"addr": addr, "error": str(e)})

        return results

    def toggle_bp(self, items) -> list[BreakpointResult]:
        items = normalize_dict_list(items)

        results = []
        for item in items:
            addr = item.get("addr", "")
            enable = item.get("enabled", True)

            try:
                ea = parse_address(addr)
                if self.adapter.enable_bpt(ea, enable):
                    results.append({"addr": addr, "ok": True})
                else:
                    results.append(
                        {
                            "addr": addr,
                            "error": f"Failed to {'enable' if enable else 'disable'} breakpoint",
                        }
                    )
            except Exception as e:
                results.append({"addr": addr, "error": str(e)})

        return results

    def set_bp_condition(self, items) -> list[BreakpointResult]:
        items = normalize_dict_list(items)

        results = []
        for item in items:
            addr = item.get("addr", "")
            condition = item.get("condition")
            language = _normalize_breakpoint_language(item.get("language"))
            low_level = bool(item.get("low_level", False))

            try:
                ea = parse_address(addr)
                bpt = self.adapter.new_bpt()
                if not self.adapter.get_bpt(ea, bpt):
                    results.append({"addr": addr, "error": "Breakpoint not found"})
                    continue

                condition_text = "" if condition is None else str(condition)
                current_language = self.adapter.get_breakpoint_language(bpt)
                current_condition = str(bpt.condition) if bpt.condition else None

                if language is not None and language != current_language:
                    if current_condition and condition_text:
                        if not self.adapter.set_bpt_cond(
                            ea, "", 1 if low_level else 0
                        ):
                            results.append(
                                {
                                    "addr": addr,
                                    "error": "Failed to clear existing breakpoint condition before changing its language",
                                }
                            )
                            continue
                        if not self.adapter.get_bpt(ea, bpt):
                            results.append(
                                {
                                    "addr": addr,
                                    "error": "Breakpoint condition was cleared, but breakpoint could not be reloaded to update its language",
                                }
                            )
                            continue

                    self.adapter.set_breakpoint_language(bpt, language)
                    if not self.adapter.update_bpt(bpt):
                        results.append(
                            {
                                "addr": addr,
                                "error": f"Failed to apply breakpoint condition language {language}",
                            }
                        )
                        continue

                if not self.adapter.set_bpt_cond(
                    ea, condition_text, 1 if low_level else 0
                ):
                    results.append(
                        {"addr": addr, "error": "Failed to set breakpoint condition"}
                    )
                    continue

                updated = self.adapter.new_bpt()
                if not self.adapter.get_bpt(ea, updated):
                    results.append(
                        {
                            "addr": addr,
                            "error": "Breakpoint condition was set, but breakpoint could not be reloaded for validation",
                        }
                    )
                    continue

                updated_condition = (
                    str(updated.condition) if updated.condition else None
                )
                updated_language = self.adapter.get_breakpoint_language(updated)
                is_compiled = getattr(updated, "is_compiled", None)
                if condition_text and callable(is_compiled) and not is_compiled():
                    results.append(
                        {
                            "addr": addr,
                            "error": "Breakpoint condition was stored but did not compile successfully",
                        }
                    )
                    continue

                results.append(
                    {
                        "addr": addr,
                        "ok": True,
                        "condition": updated_condition,
                        "language": updated_language,
                    }
                )
            except Exception as e:
                results.append({"addr": addr, "error": str(e)})

        return results

    # =========================================================================
    # Register Operations
    # =========================================================================

    def regs_all(self) -> list[ThreadRegisters]:
        result: list[ThreadRegisters] = []
        dbg = self.adapter.ensure_suspended()
        for thread_index in range(self.adapter.get_thread_qty()):
            tid = self.adapter.getn_thread(thread_index)
            result.append(self.adapter.get_registers_for_thread(dbg, tid))
        return result

    def regs_remote(self, tids) -> list[ThreadRegistersResult]:
        if isinstance(tids, int):
            tids = [tids]

        dbg = self.adapter.ensure_suspended()
        available_tids = [
            self.adapter.getn_thread(i)
            for i in range(self.adapter.get_thread_qty())
        ]
        results = []

        for tid in tids:
            try:
                if tid not in available_tids:
                    results.append(
                        {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                    )
                    continue
                regs = self.adapter.get_registers_for_thread(dbg, tid)
                results.append({"tid": tid, "regs": regs})
            except Exception as e:
                results.append({"tid": tid, "regs": None, "error": str(e)})

        return results

    def regs(self) -> ThreadRegisters:
        dbg = self.adapter.ensure_suspended()
        tid = self.adapter.get_current_thread()
        return self.adapter.get_registers_for_thread(dbg, tid)

    def gpregs_remote(self, tids) -> list[ThreadRegistersResult]:
        if isinstance(tids, int):
            tids = [tids]

        dbg = self.adapter.ensure_suspended()
        available_tids = [
            self.adapter.getn_thread(i)
            for i in range(self.adapter.get_thread_qty())
        ]
        results = []

        for tid in tids:
            try:
                if tid not in available_tids:
                    results.append(
                        {"tid": tid, "regs": None, "error": f"Thread {tid} not found"}
                    )
                    continue
                regs = self.adapter.get_registers_general_for_thread(dbg, tid)
                results.append({"tid": tid, "regs": regs})
            except Exception as e:
                results.append({"tid": tid, "regs": None, "error": str(e)})

        return results

    def gpregs(self) -> ThreadRegisters:
        dbg = self.adapter.ensure_suspended()
        tid = self.adapter.get_current_thread()
        return self.adapter.get_registers_general_for_thread(dbg, tid)

    def regs_named_remote(
        self, thread_id: int, register_names: str
    ) -> ThreadRegisters:
        dbg = self.adapter.ensure_suspended()
        if thread_id not in [
            self.adapter.getn_thread(i)
            for i in range(self.adapter.get_thread_qty())
        ]:
            raise IDAError(f"Thread with ID {thread_id} not found")
        names = [name.strip() for name in register_names.split(",")]
        return self.adapter.get_registers_specific_for_thread(dbg, thread_id, names)

    def regs_named(self, register_names: str) -> ThreadRegisters:
        dbg = self.adapter.ensure_suspended()
        tid = self.adapter.get_current_thread()
        names = [name.strip() for name in register_names.split(",")]
        return self.adapter.get_registers_specific_for_thread(dbg, tid, names)

    # =========================================================================
    # Call Stack Operations
    # =========================================================================

    def stacktrace(self) -> list[StackFrameInfo]:
        try:
            return self.adapter.collect_stack_trace()
        except Exception:
            return []

    # =========================================================================
    # Debugger Memory Operations
    # =========================================================================

    def read(self, regions) -> list[DebugMemoryReadResult]:
        regions = normalize_dict_list(regions)
        self.adapter.ensure_active()
        results = []

        for region in regions:
            try:
                addr = parse_address(region["addr"])
                size = min(region["size"], 1024 * 1024)  # Cap at 1MB per read

                data = self.adapter.dbg_read_memory(addr, size)
                if data:
                    results.append(
                        {
                            "addr": region["addr"],
                            "size": len(data),
                            "data": data.hex(),
                            "error": None,
                        }
                    )
                else:
                    results.append(
                        {
                            "addr": region["addr"],
                            "size": 0,
                            "data": None,
                            "error": "Failed to read memory",
                        }
                    )

            except Exception as e:
                results.append(
                    {
                        "addr": region.get("addr"),
                        "size": 0,
                        "data": None,
                        "error": str(e),
                    }
                )

        return results

    def write(self, regions) -> list[DebugMemoryWriteResult]:
        regions = normalize_dict_list(regions)
        self.adapter.ensure_active()
        results = []

        for region in regions:
            try:
                addr = parse_address(region["addr"])
                data = bytes.fromhex(region["data"])

                success = self.adapter.dbg_write_memory(addr, data)
                results.append(
                    {
                        "addr": region["addr"],
                        "size": len(data) if success else 0,
                        "ok": success,
                        "error": None if success else "Write failed",
                    }
                )

            except Exception as e:
                results.append(
                    {"addr": region.get("addr"), "size": 0, "error": str(e)}
                )

        return results

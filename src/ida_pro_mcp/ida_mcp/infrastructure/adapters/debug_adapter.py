"""Infrastructure adapter for IDA debugger SDK operations.

Wraps the ``idaapi`` / ``ida_dbg`` / ``ida_idd`` / ``ida_entry`` / ``ida_name``
SDK calls used by the debugger tools. Behavior is preserved exactly from the
former ``api_debug.py`` module; this layer only isolates the raw SDK access so
the application service can orchestrate without importing ``idaapi`` directly.

``idaapi`` and friends are imported lazily inside methods so this module can be
imported (and py_compiled) outside of IDA.
"""

from __future__ import annotations

import os
from typing import Any

from ...infrastructure.sync.sync import IDAError
from ...domain.entities import (
    RegisterValue,
    ThreadRegisters,
    Breakpoint,
)


GENERAL_PURPOSE_REGISTERS = {
    "EAX",
    "EBX",
    "ECX",
    "EDX",
    "ESI",
    "EDI",
    "EBP",
    "ESP",
    "EIP",
    "RAX",
    "RBX",
    "RCX",
    "RDX",
    "RSI",
    "RDI",
    "RBP",
    "RSP",
    "RIP",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
}


class DebugAdapter:
    """Adapter for IDA debugger SDK access (in-process)."""

    # =========================================================================
    # Process / lifecycle state
    # =========================================================================

    def is_debugger_on(self) -> bool:
        import ida_dbg

        return ida_dbg.is_debugger_on()

    def get_process_state(self) -> int:
        import ida_dbg

        return ida_dbg.get_process_state()

    def get_process_state_name(self) -> str:
        import ida_dbg

        if not ida_dbg.is_debugger_on():
            return "not_running"

        state = ida_dbg.get_process_state()
        if state == ida_dbg.DSTATE_SUSP:
            return "suspended"
        if state == ida_dbg.DSTATE_RUN:
            return "running"
        if state == ida_dbg.DSTATE_NOTASK:
            return "not_running"
        return f"unknown({state})"

    def get_ip_val(self):
        import ida_dbg

        return ida_dbg.get_ip_val()

    def get_dbg(self):
        import ida_idd

        return ida_idd.get_dbg()

    def ensure_active(self):
        import ida_dbg
        import ida_idd

        dbg = ida_idd.get_dbg()
        if not dbg or not ida_dbg.is_debugger_on():
            raise IDAError(
                "Debugger not running. Stop and ask the user to start a debugger "
                "session (call dbg_start, or have them launch from IDA) before "
                "retrying. If dbg_start has already been attempted and failed, "
                "the user must first configure the debugger and target."
            )
        return dbg

    def ensure_suspended(self):
        import ida_dbg

        dbg = self.ensure_active()
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            raise IDAError(
                "Debugger is running; wait until it suspends before inspecting state"
            )
        return dbg

    # =========================================================================
    # Debugger control
    # =========================================================================

    def start_process(self) -> int:
        import idaapi

        return idaapi.start_process("", "", "")

    def wait_for_next_event(self, poll_ms: int) -> None:
        import ida_dbg

        ida_dbg.wait_for_next_event(
            ida_dbg.WFNE_ANY | ida_dbg.WFNE_SUSP | ida_dbg.WFNE_SILENT,
            poll_ms,
        )

    def exit_process(self) -> bool:
        import idaapi

        return idaapi.exit_process()

    def continue_process(self) -> bool:
        import idaapi

        return idaapi.continue_process()

    def run_to(self, ea: int) -> bool:
        import idaapi

        return idaapi.run_to(ea)

    def step_into(self) -> bool:
        import idaapi

        return idaapi.step_into()

    def step_over(self) -> bool:
        import idaapi

        return idaapi.step_over()

    # =========================================================================
    # Breakpoints
    # =========================================================================

    def get_entry_addresses(self) -> list[int]:
        import ida_entry
        import ida_idaapi

        addrs: list[int] = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            addr = ida_entry.get_entry(ordinal)
            if addr != ida_idaapi.BADADDR:
                addrs.append(addr)
        return addrs

    def add_bpt_soft(self, ea: int) -> bool:
        import idaapi

        return idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT)

    def del_bpt(self, ea: int) -> bool:
        import idaapi

        return idaapi.del_bpt(ea)

    def enable_bpt(self, ea: int, enable: bool) -> bool:
        import idaapi

        return idaapi.enable_bpt(ea, enable)

    def get_breakpoint_language(self, bpt) -> str | None:
        language = getattr(bpt, "elang", None)
        if language is None:
            return None
        text = str(language).strip()
        return text or None

    def set_breakpoint_language(self, bpt, language: str) -> None:
        setter = getattr(bpt, "set_cnd_elang", None)
        if callable(setter):
            if not setter(language):
                raise IDAError(
                    f"Failed to set breakpoint condition language to {language}"
                )
            return
        try:
            setattr(bpt, "elang", language)
        except Exception as exc:
            raise IDAError(
                f"Failed to set breakpoint condition language to {language}"
            ) from exc

    def list_breakpoints(self) -> list[Breakpoint]:
        import ida_dbg

        breakpoints: list[Breakpoint] = []
        for i in range(ida_dbg.get_bpt_qty()):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(i, bpt):
                breakpoints.append(
                    Breakpoint(
                        addr=hex(bpt.ea),
                        enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
                        condition=str(bpt.condition) if bpt.condition else None,
                        language=self.get_breakpoint_language(bpt),
                    )
                )
        return breakpoints

    def new_bpt(self):
        import ida_dbg

        return ida_dbg.bpt_t()

    def get_bpt(self, ea: int, bpt) -> bool:
        import ida_dbg

        return ida_dbg.get_bpt(ea, bpt)

    def update_bpt(self, bpt) -> bool:
        import ida_dbg

        return ida_dbg.update_bpt(bpt)

    def set_bpt_cond(self, ea: int, condition_text: str, low_level: int) -> bool:
        import idc

        return idc.set_bpt_cond(ea, condition_text, low_level)

    # =========================================================================
    # Registers
    # =========================================================================

    def get_thread_qty(self) -> int:
        import ida_dbg

        return ida_dbg.get_thread_qty()

    def getn_thread(self, index: int) -> int:
        import ida_dbg

        return ida_dbg.getn_thread(index)

    def get_current_thread(self) -> int:
        import ida_dbg

        return ida_dbg.get_current_thread()

    def get_registers_for_thread(self, dbg, tid: int) -> ThreadRegisters:
        """Get registers for a specific thread."""
        import ida_dbg
        import ida_idaapi

        regs = []
        regvals = ida_dbg.get_reg_vals(tid)
        for reg_index, rv in enumerate(regvals):
            reg_info = dbg.regs(reg_index)

            try:
                reg_value = rv.pyval(reg_info.dtype)
            except ValueError:
                reg_value = ida_idaapi.BADADDR

            if isinstance(reg_value, int):
                reg_value = hex(reg_value)
            if isinstance(reg_value, bytes):
                reg_value = reg_value.hex(" ")
            else:
                reg_value = str(reg_value)
            regs.append(
                RegisterValue(
                    name=reg_info.name,
                    value=reg_value,
                )
            )
        return ThreadRegisters(
            thread_id=tid,
            registers=regs,
        )

    def get_registers_general_for_thread(self, dbg, tid: int) -> ThreadRegisters:
        """Get general-purpose registers for a specific thread."""
        all_registers = self.get_registers_for_thread(dbg, tid)
        general_registers = [
            reg
            for reg in all_registers["registers"]
            if reg["name"] in GENERAL_PURPOSE_REGISTERS
        ]
        return ThreadRegisters(
            thread_id=tid,
            registers=general_registers,
        )

    def get_registers_specific_for_thread(
        self, dbg, tid: int, register_names: list[str]
    ) -> ThreadRegisters:
        """Get specific registers for a given thread."""
        all_registers = self.get_registers_for_thread(dbg, tid)
        specific_registers = [
            reg
            for reg in all_registers["registers"]
            if reg["name"] in register_names
        ]
        return ThreadRegisters(
            thread_id=tid,
            registers=specific_registers,
        )

    # =========================================================================
    # Call stack
    # =========================================================================

    def collect_stack_trace(self) -> list[dict]:
        import ida_dbg
        import ida_idd
        import ida_name

        callstack: list[dict] = []
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()

        if not ida_dbg.collect_stack_trace(tid, trace):
            return []
        for frame in trace:
            frame_info = {
                "addr": hex(frame.callea),
            }
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"

                name = (
                    ida_name.get_nice_colored_name(
                        frame.callea,
                        ida_name.GNCN_NOCOLOR
                        | ida_name.GNCN_NOLABEL
                        | ida_name.GNCN_NOSEG
                        | ida_name.GNCN_PREFDBG,
                    )
                    or "<unnamed>"
                )
                frame_info["symbol"] = name

            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)

            callstack.append(frame_info)

        return callstack

    # =========================================================================
    # Memory
    # =========================================================================

    def dbg_read_memory(self, addr: int, size: int) -> Any:
        import idaapi

        return idaapi.dbg_read_memory(addr, size)

    def dbg_write_memory(self, addr: int, data: bytes) -> bool:
        import idaapi

        return idaapi.dbg_write_memory(addr, data)

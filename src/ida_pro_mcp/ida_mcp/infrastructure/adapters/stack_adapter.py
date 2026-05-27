"""Infrastructure adapter for IDA stack-frame SDK operations.

Wraps the ``idaapi`` / ``ida_frame`` / ``ida_typeinf`` SDK calls used by the
stack-frame tools. Behavior is preserved exactly from the former
``api_stack.py`` module; this layer only isolates the raw SDK access so the
application service can orchestrate without importing ``idaapi`` directly.

SDK modules are imported lazily inside methods so this module can be imported
(and py_compiled) outside of IDA.
"""

from __future__ import annotations

from ...utils import get_stack_frame_variables_internal


class StackAdapter:
    """Adapter for IDA stack-frame SDK access (in-process)."""

    def get_func(self, ea: int):
        import idaapi

        return idaapi.get_func(ea)

    def get_func_frame(self, frame_tif, func) -> bool:
        import ida_frame

        return ida_frame.get_func_frame(frame_tif, func)

    def new_tinfo(self):
        import ida_typeinf

        return ida_typeinf.tinfo_t()

    def define_stkvar(self, func, var_name: str, ea: int, tif) -> bool:
        import ida_frame

        return ida_frame.define_stkvar(func, var_name, ea, tif)

    def get_stack_frame_variables(self, ea: int, arg: bool):
        return get_stack_frame_variables_internal(ea, arg)

    def get_udm(self, frame_tif, var_name: str):
        return frame_tif.get_udm(var_name)

    def get_udm_tid(self, frame_tif, idx: int):
        return frame_tif.get_udm_tid(idx)

    def is_special_frame_member(self, tid) -> bool:
        import ida_frame

        return ida_frame.is_special_frame_member(tid)

    def new_udm(self):
        import ida_typeinf

        return ida_typeinf.udm_t()

    def get_udm_by_tid(self, frame_tif, udm, tid) -> None:
        frame_tif.get_udm_by_tid(udm, tid)

    def is_funcarg_off(self, func, offset: int) -> bool:
        import ida_frame

        return ida_frame.is_funcarg_off(func, offset)

    def delete_frame_members(self, func, start: int, end: int) -> bool:
        import ida_frame

        return ida_frame.delete_frame_members(func, start, end)

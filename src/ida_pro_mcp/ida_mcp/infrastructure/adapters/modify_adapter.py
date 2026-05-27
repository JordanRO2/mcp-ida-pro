"""Infrastructure adapter for IDB-mutating IDA operations (api_modify domain).

Wraps the lower-level ``idaapi`` / ``idautils`` / ``idc`` / ``ida_bytes`` /
``ida_funcs`` / ``ida_ua`` / Hex-Rays calls used by the mutation tools. These
operations MUTATE the IDB. Behavior preservation OUTRANKS layering purity: the
``rename`` orchestration keeps its IDA calls in the service because its control
flow is tightly interleaved with them; the standalone primitives that are
cleanly wrappable are extracted here.

``idaapi`` and friends are imported lazily inside methods so the file compiles
outside IDA (py_compile / AST checks).
"""

from __future__ import annotations

from typing import Any


class ModifyAdapter:
    """Adapter over IDB-mutating IDA primitives."""

    # -- comments ----------------------------------------------------------

    def set_cmt(self, ea: int, comment: str, rptble: bool) -> bool:
        import idaapi

        return idaapi.set_cmt(ea, comment, rptble)

    def get_cmt(self, ea: int, rptble: bool):
        import idaapi

        return idaapi.get_cmt(ea, rptble)

    def get_func(self, ea: int) -> Any:
        import idaapi

        return idaapi.get_func(ea)

    def init_hexrays_plugin(self) -> bool:
        import ida_hexrays

        return ida_hexrays.init_hexrays_plugin()

    # -- assembly patching -------------------------------------------------

    def assemble(self, ea: int, instruction: str):
        import idautils

        return idautils.Assemble(ea, instruction)

    def patch_bytes(self, ea: int, data) -> None:
        import ida_bytes

        ida_bytes.patch_bytes(ea, data)

    # -- function / code definition ---------------------------------------

    def add_func(self, start_ea: int, end_ea: int) -> bool:
        import ida_funcs

        return ida_funcs.add_func(start_ea, end_ea)

    def create_insn(self, ea: int) -> int:
        import ida_ua

        return ida_ua.create_insn(ea)

    def del_items(self, ea: int, flags: int, nbytes: int) -> bool:
        import ida_bytes

        return ida_bytes.del_items(ea, flags, nbytes)

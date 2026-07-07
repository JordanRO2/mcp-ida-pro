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

    # -- hex-rays cache + function enumeration ----------------------------

    def functions(self) -> list[int]:
        import idautils

        return list(idautils.Functions())

    def func_start_ea(self, ea: int):
        import ida_funcs

        func = ida_funcs.get_func(ea)
        return func.start_ea if func is not None else None

    def func_name(self, ea: int) -> str:
        import ida_funcs

        return ida_funcs.get_func_name(ea) or ""

    def mark_cfunc_dirty(self, ea: int) -> None:
        import ida_hexrays

        ida_hexrays.mark_cfunc_dirty(ea)

    def clear_cached_cfuncs(self) -> None:
        # Best-effort: decompiler may be unavailable (headless idalib w/o Hex-Rays);
        # never let a cache flush fail the caller's mutation.
        try:
            import ida_hexrays

            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

    # -- operand typing ---------------------------------------------------

    def op_stroff_by_struct(self, ea: int, op_n: int, struct_name: str, delta: int):
        """Convert an operand to a struct-offset ref (GUI 'Y'). IDA 9.x path.

        idaapi.get_struc_id was removed in 9.x; resolve the struct tid via the
        local type library (tinfo_t.get_named_type + get_tid). Returns (ok, err).
        """
        import idaapi
        import ida_bytes
        import ida_typeinf

        til = ida_typeinf.get_idati()
        sti = ida_typeinf.tinfo_t()
        if not sti.get_named_type(til, struct_name):
            return False, f"struct not found: {struct_name}"
        tid = sti.get_tid()
        if tid == idaapi.BADADDR:
            return False, f"struct {struct_name} has no tid"
        path = idaapi.tid_array(1)
        path[0] = tid
        ok = bool(ida_bytes.op_stroff(ea, op_n, path.cast(), 1, delta))
        return ok, None

    def op_plain_offset(self, ea: int, op_n: int, target_ea: int) -> bool:
        import idc

        return bool(idc.op_plain_offset(ea, op_n, target_ea))

    def op_stkvar(self, ea: int, op_n: int) -> bool:
        import idc

        return bool(idc.op_stkvar(ea, op_n))

    def set_op_format(self, ea: int, op_n: int, kind: str) -> bool:
        """Apply a numeric/char display format to an operand (GUI '#')."""
        import ida_bytes

        flags = {
            "hex": ida_bytes.FF_0NUMH,
            "dec": ida_bytes.FF_0NUMD,
            "char": ida_bytes.FF_0CHAR,
            "binary": ida_bytes.FF_0NUMB,
            "octal": ida_bytes.FF_0NUMO,
        }
        return bool(ida_bytes.set_op_type(ea, flags[kind], op_n))

    # -- typed data creation ----------------------------------------------

    def set_type(self, ea: int, decl: str) -> bool:
        import idc

        return bool(idc.SetType(ea, decl))

    def guess_size(self, ea: int) -> int:
        import ida_typeinf
        from ..compat import guess_tinfo

        tif = ida_typeinf.tinfo_t()
        if guess_tinfo(tif, ea):
            return tif.get_size()
        return 0

    def del_items_expand(self, ea: int, nbytes: int) -> bool:
        import ida_bytes

        return bool(ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, nbytes))

    def set_name(self, ea: int, name: str) -> bool:
        import ida_name

        return bool(ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE))

    def get_name(self, ea: int) -> str:
        import ida_name

        return ida_name.get_name(ea) or ""

    def get_type(self, ea: int) -> str:
        import idc

        return idc.get_type(ea) or ""

    # -- bookmarks --------------------------------------------------------

    def get_bookmark(self, slot: int) -> int:
        import idc

        return idc.get_bookmark(slot)

    def put_bookmark(self, ea: int, x: int, y: int, flags: int, slot: int, text: str) -> None:
        import idc

        idc.put_bookmark(ea, x, y, flags, slot, text)

    @property
    def BADADDR(self) -> int:
        import idc

        return idc.BADADDR

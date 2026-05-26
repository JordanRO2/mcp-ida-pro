"""Adapter for composite-analysis SDK access (idaapi / idautils / idc / ida_typeinf).

Extracts the lowest-level IDA SDK calls used by the composite tools. Nothing
here imports ``idaapi`` at module load: every method imports the SDK lazily so
the file imports cleanly outside IDA.
"""

from __future__ import annotations

from ...infrastructure.sync.sync import IDAError
from ...utils import parse_address


class CompositeAdapter:
    """Lowest-level IDA SDK access for composite analysis tools."""

    def resolve_addr(self, addr: str) -> int:
        """Resolve address or name to ea. Raises IDAError on failure."""
        import idaapi

        try:
            return parse_address(addr)
        except IDAError:
            ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
            if ea == idaapi.BADADDR:
                raise IDAError(f"Address/name not found: {addr!r}")
            return ea

    def get_func(self, ea: int):
        import idaapi

        return idaapi.get_func(ea)

    def get_func_name(self, ea: int) -> str:
        import idaapi

        return idaapi.get_func_name(ea) or ""

    def get_name(self, ea: int):
        import idaapi

        return idaapi.get_name(ea)

    def basic_block_info(self, ea: int) -> dict:
        """Return block count and cyclomatic complexity for the function at *ea*."""
        import idaapi

        func = idaapi.get_func(ea)
        if func is None:
            return {"count": 0, "cyclomatic_complexity": 0}

        fc = idaapi.FlowChart(func)
        nodes = 0
        edges = 0
        for block in fc:
            nodes += 1
            for _ in block.succs():
                edges += 1

        return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}

    def collect_function_globals(self, ea: int) -> set[int]:
        """Return the set of global/data addresses referenced from a function."""
        import idaapi
        import idautils

        globals_accessed: set[int] = set()
        func = idaapi.get_func(ea)
        if func is None:
            return globals_accessed
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.iscode:
                    continue
                ref_func = idaapi.get_func(xref.to)
                if ref_func is None and idaapi.is_loaded(xref.to):
                    globals_accessed.add(xref.to)
        return globals_accessed

    # --- diff_before_after mutations ---

    def set_name(self, ea: int, name: str) -> bool:
        import idaapi

        return idaapi.set_name(ea, name, idaapi.SN_CHECK)

    def apply_type(self, ea: int, type_str: str) -> tuple[bool, str | None]:
        """Parse and apply a C type declaration to *ea*.

        Returns (ok, error). ``error`` is non-None when parsing/applying failed.
        """
        import ida_typeinf

        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        parsed = ida_typeinf.parse_decl(tif, til, type_str, ida_typeinf.PT_SIL)
        if parsed is None:
            return False, f"Failed to parse type: {type_str!r}"
        ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        if not ok:
            return False, f"apply_tinfo failed for {type_str!r}"
        return True, None

    def set_comment(self, ea: int, comment: str) -> None:
        import idaapi

        idaapi.set_cmt(ea, comment, False)

    # --- trace_data_flow primitives ---

    def is_loaded(self, ea: int) -> bool:
        import idaapi

        return idaapi.is_loaded(ea)

    def get_disasm(self, ea: int) -> str:
        import idc

        return idc.GetDisasm(ea)

    def xrefs_from(self, ea: int) -> list:
        import idautils

        return list(idautils.XrefsFrom(ea, 0))

    def xrefs_to(self, ea: int) -> list:
        import idautils

        return list(idautils.XrefsTo(ea, 0))

"""Infrastructure adapter for in-IDA Python evaluation.

Owns the IDA SDK module surface exposed to ``py_eval``'d code. The eager
``import ida_*`` set and the ``lazy_import`` fallback are preserved verbatim
from the legacy flat ``api_python`` module, so executed code sees the exact same
globals namespace as before.
"""

from __future__ import annotations

import idaapi
import idc
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_segment
import ida_typeinf
import ida_xref

from ...utils import parse_address, get_function

# Track which modules failed to import so we only warn once (not per py_eval call)
_lazy_import_warned: set[str] = set()


class PythonExecAdapter:
    """Builds the IDA SDK globals namespace for ``py_eval``."""

    @staticmethod
    def _lazy_import(module_name):
        try:
            return __import__(module_name)
        except Exception:
            if module_name not in _lazy_import_warned:
                _lazy_import_warned.add(module_name)
            return None

    def build_exec_globals(self) -> dict:
        """Create execution context with IDA modules (lazy import to avoid errors)."""
        lazy_import = self._lazy_import

        return {
            "__builtins__": __builtins__,
            "idaapi": idaapi,
            "idc": idc,
            "idautils": lazy_import("idautils"),
            "ida_allins": lazy_import("ida_allins"),
            "ida_auto": lazy_import("ida_auto"),
            "ida_bitrange": lazy_import("ida_bitrange"),
            "ida_bytes": ida_bytes,
            "ida_dbg": ida_dbg,
            "ida_dirtree": lazy_import("ida_dirtree"),
            "ida_diskio": lazy_import("ida_diskio"),
            "ida_entry": ida_entry,
            "ida_expr": lazy_import("ida_expr"),
            "ida_fixup": lazy_import("ida_fixup"),
            "ida_fpro": lazy_import("ida_fpro"),
            "ida_frame": ida_frame,
            "ida_funcs": ida_funcs,
            "ida_gdl": lazy_import("ida_gdl"),
            "ida_graph": lazy_import("ida_graph"),
            "ida_hexrays": ida_hexrays,
            "ida_ida": ida_ida,
            "ida_idd": lazy_import("ida_idd"),
            "ida_idp": lazy_import("ida_idp"),
            "ida_ieee": lazy_import("ida_ieee"),
            "ida_kernwin": ida_kernwin,
            "ida_lines": ida_lines,
            "ida_loader": lazy_import("ida_loader"),
            "ida_merge": lazy_import("ida_merge"),
            "ida_mergemod": lazy_import("ida_mergemod"),
            "ida_moves": lazy_import("ida_moves"),
            "ida_nalt": ida_nalt,
            "ida_name": ida_name,
            "ida_netnode": lazy_import("ida_netnode"),
            "ida_offset": lazy_import("ida_offset"),
            "ida_pro": lazy_import("ida_pro"),
            "ida_problems": lazy_import("ida_problems"),
            "ida_range": lazy_import("ida_range"),
            "ida_regfinder": lazy_import("ida_regfinder"),
            "ida_registry": lazy_import("ida_registry"),
            "ida_search": lazy_import("ida_search"),
            "ida_segment": ida_segment,
            "ida_segregs": lazy_import("ida_segregs"),
            "ida_srclang": lazy_import("ida_srclang"),
            "ida_strlist": lazy_import("ida_strlist"),
            "ida_tryblks": lazy_import("ida_tryblks"),
            "ida_typeinf": ida_typeinf,
            "ida_ua": lazy_import("ida_ua"),
            "ida_undo": lazy_import("ida_undo"),
            "ida_xref": ida_xref,
            "parse_address": parse_address,
            "get_function": get_function,
        }

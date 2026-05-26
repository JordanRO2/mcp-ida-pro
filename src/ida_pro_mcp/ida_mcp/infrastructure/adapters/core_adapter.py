"""Infrastructure adapter for core IDB metadata and basic queries.

Holds the raw ``idaapi`` / ``ida_*`` / ``idc`` / ``idautils`` calls extracted
from the legacy flat ``api_core`` module. Behavior is preserved verbatim; this
layer only isolates the IDA SDK surface so the application service can stay
SDK-agnostic where practical.
"""

from __future__ import annotations

import time

import ida_auto
import idaapi
import ida_funcs
import ida_hexrays
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc

from ..cache.strings_cache import (
    get_strings_cache,
    is_strings_cache_ready,
    strings_cache_size,
    server_started_at,
)
from ...domain.entities import Import


class CoreAdapter:
    """Raw IDA SDK access for core metadata/query tools."""

    # -- imports ---------------------------------------------------------

    def collect_imports(self) -> list[Import]:
        """Collect all imports in the current database."""
        all_imports: list[Import] = []
        nimps = ida_nalt.get_import_module_qty()

        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                module_name = "<unnamed>"

            def imp_cb(ea, symbol_name, ordinal, acc):
                if not symbol_name:
                    symbol_name = f"#{ordinal}"
                acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
                return True

            def imp_cb_w_context(ea, symbol_name, ordinal):
                return imp_cb(ea, symbol_name, ordinal, all_imports)

            ida_nalt.enum_import_names(i, imp_cb_w_context)

        return all_imports

    # -- segments --------------------------------------------------------

    def segment_name_for_ea(self, ea: int) -> str | None:
        seg = idaapi.getseg(ea)
        if not seg:
            return None
        try:
            return idaapi.get_segm_name(seg)
        except Exception:
            return None

    # -- entity rows -----------------------------------------------------

    def collect_function_rows(self) -> list[dict]:
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append(
                {
                    "kind": "function",
                    "addr": hex(fn.start_ea),
                    "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
                    "size": hex(size_int),
                    "size_int": size_int,
                    "segment": self.segment_name_for_ea(fn.start_ea),
                    "has_type": bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)),
                }
            )
        return rows

    def collect_global_rows(self) -> list[dict]:
        rows: list[dict] = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append(
                {
                    "kind": "global",
                    "addr": hex(ea),
                    "name": name,
                    "size": idc.get_item_size(ea),
                    "segment": self.segment_name_for_ea(ea),
                }
            )
        return rows

    def collect_import_rows(self) -> list[dict]:
        rows: list[dict] = []
        for imp in self.collect_imports():
            rows.append(
                {
                    "kind": "import",
                    "addr": imp["addr"],
                    "name": imp["imported_name"],
                    "module": imp["module"],
                }
            )
        return rows

    def collect_string_rows(self) -> list[dict]:
        rows: list[dict] = []
        for ea, text in get_strings_cache():
            rows.append(
                {
                    "kind": "string",
                    "addr": hex(ea),
                    "text": text,
                    "length": len(text),
                    "segment": self.segment_name_for_ea(ea),
                }
            )
        return rows

    def collect_name_rows(self) -> list[dict]:
        rows: list[dict] = []
        imports_by_ea = {int(imp["addr"], 16): imp for imp in self.collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append(
                {
                    "kind": "name",
                    "addr": hex(ea),
                    "name": name,
                    "segment": self.segment_name_for_ea(ea),
                    "is_function": is_function,
                    "is_import": is_import,
                }
            )
        return rows

    # -- function enumeration for queries --------------------------------

    def iter_function_addrs(self):
        """Yield every function start ea (idautils.Functions())."""
        return idautils.Functions()

    def collect_func_query_rows(self) -> list[dict]:
        all_functions: list[dict] = []
        for addr in idautils.Functions():
            fn = idaapi.get_func(addr)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            fn_name = ida_funcs.get_func_name(fn.start_ea) or "<unnamed>"
            has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
            all_functions.append(
                {
                    "addr": hex(fn.start_ea),
                    "name": fn_name,
                    "size": hex(size_int),
                    "size_int": size_int,
                    "has_type": has_type,
                }
            )
        return all_functions

    def names(self):
        """Yield (ea, name) pairs (idautils.Names())."""
        return idautils.Names()

    def get_func(self, ea: int):
        return idaapi.get_func(ea)

    def get_name_ea(self, query: str) -> int:
        return idaapi.get_name_ea(idaapi.BADADDR, query)

    @property
    def BADADDR(self) -> int:
        return idaapi.BADADDR

    # -- health ----------------------------------------------------------

    def build_health_payload(self) -> dict:
        auto_is_ok = getattr(ida_auto, "auto_is_ok", None)
        auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None

        hexrays_ready = False
        try:
            hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            hexrays_ready = False

        idb_path = None
        try:
            idb_path = idc.get_idb_path()
        except Exception:
            idb_path = None

        return {
            "status": "ok",
            "uptime_sec": round(time.time() - server_started_at(), 3),
            "idb_path": idb_path,
            "module": ida_nalt.get_root_filename(),
            "input_path": ida_nalt.get_input_file_path(),
            "imagebase": hex(idaapi.get_imagebase()),
            "auto_analysis_ready": auto_analysis_ready,
            "hexrays_ready": hexrays_ready,
            "strings_cache_ready": is_strings_cache_ready(),
            "strings_cache_size": strings_cache_size(),
        }

    # -- warmup ----------------------------------------------------------

    def auto_wait(self) -> None:
        ida_auto.auto_wait()

    def init_hexrays(self) -> bool:
        return bool(ida_hexrays.init_hexrays_plugin())

    # -- save ------------------------------------------------------------

    def get_idb_path(self) -> str:
        return ida_loader.get_path(ida_loader.PATH_TYPE_IDB)

    def save_database(self, save_path: str) -> bool:
        return bool(ida_loader.save_database(save_path, 0))

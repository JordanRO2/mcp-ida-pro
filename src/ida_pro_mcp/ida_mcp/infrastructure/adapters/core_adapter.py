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
import ida_kernwin  # is_idaq() GUI detection
import ida_lines  # rendered-listing search (search_text)
import ida_segment
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc

# Listing lines carrying any of these SCOLOR tags are comments (search_text).
_COMMENT_SCOLORS = (
    ida_lines.SCOLOR_REGCMT,
    ida_lines.SCOLOR_RPTCMT,
    ida_lines.SCOLOR_AUTOCMT,
    ida_lines.SCOLOR_COLLAPSED,
)


def _line_is_comment(tagged: str) -> bool:
    """A rendered listing line is a comment if it carries a comment SCOLOR tag."""
    if not tagged:
        return False
    return any(ida_lines.COLOR_ON + sc in tagged for sc in _COMMENT_SCOLORS)

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

    def is_gui(self) -> bool:
        """True under the IDA Qt GUI (idaq); False in headless idalib/text mode."""
        try:
            return bool(ida_kernwin.is_idaq())
        except Exception:
            return False

    def save_database_native(self) -> bool:
        """GUI in-place save (equivalent to Ctrl+W): save_database(None, 0).

        Preserves the live loose working files; never packs/kills them.
        """
        return bool(ida_loader.save_database(None, 0))

    def save_database_copy(self, save_path: str) -> bool:
        """GUI save-as: compressed snapshot to a new path WITHOUT DBFL_KILL, so
        the live .id0/.id1/.id2/.nam/.til of the open database stay intact.
        """
        return bool(ida_loader.save_database(save_path, ida_loader.DBFL_COMP))

    def save_database_pack(self, save_path: str) -> bool:
        """Headless idalib: pack into a single compressed .i64/.idb, removing the
        loose working files.
        """
        flags = ida_loader.DBFL_KILL | ida_loader.DBFL_COMP
        return bool(ida_loader.save_database(save_path, flags))

    # -- rendered-listing search (search_text) ---------------------------------

    @staticmethod
    def exec_segments() -> "list[tuple[int, int]]":
        """[(start, end)] for executable segments, in address order."""
        ranges: "list[tuple[int, int]]" = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg and (seg.perm & idaapi.SEGPERM_EXEC):
                ranges.append((seg.start_ea, seg.end_ea))
        return ranges

    @staticmethod
    def all_segments() -> "list[tuple[int, int]]":
        ranges: "list[tuple[int, int]]" = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg:
                ranges.append((seg.start_ea, seg.end_ea))
        return ranges

    @staticmethod
    def heads(start: int, end: int):
        """Yield head addresses in [start, end) (idautils.Heads)."""
        return idautils.Heads(start, end)

    @staticmethod
    def get_item_size(ea: int) -> int:
        return int(idaapi.get_item_size(ea))

    @staticmethod
    def user_cancelled() -> bool:
        return bool(ida_kernwin.user_cancelled())

    @staticmethod
    def hit_function_name(ea: int) -> "str | None":
        func = idaapi.get_func(ea)
        if func is None:
            return None
        return ida_funcs.get_func_name(func.start_ea) or None

    @staticmethod
    def hit_segment_name(ea: int) -> "str | None":
        seg = idaapi.getseg(ea)
        if seg is None:
            return None
        return ida_segment.get_segm_name(seg) or None

    @staticmethod
    def classify_hit_lines(
        ea: int, matcher, want_disasm: bool, want_comments: bool, max_lines: int = 32
    ) -> "list[dict]":
        """Render the listing for `ea`, classify each line, return matching lines."""
        out: "list[dict]" = []
        try:
            result = ida_lines.generate_disassembly(ea, max_lines, False, False)
        except Exception:
            return out
        # Bindings vary: (n, lineno, lines) or (lines, lineno).
        lines = None
        if isinstance(result, tuple):
            for item in result:
                if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                    lines = list(item)
                    break
        if lines is None:
            return out
        for tagged in lines:
            text = ida_lines.tag_remove(tagged) or ""
            if not text or not matcher(text):
                continue
            kind = "comment" if _line_is_comment(tagged) else "disasm"
            if kind == "disasm" and not want_disasm:
                continue
            if kind == "comment" and not want_comments:
                continue
            out.append({"kind": kind, "text": text})
        return out

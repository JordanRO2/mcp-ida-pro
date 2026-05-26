"""Adapter for binary-survey SDK access (idaapi / idautils / idc / ida_nalt).

Extracts the lowest-level IDA SDK calls used by the survey tool. Nothing here
imports ``idaapi`` at module load: every method imports the SDK lazily so the
file imports cleanly outside IDA (py_compile / unit checks).
"""

from __future__ import annotations

import hashlib
import re
from itertools import islice

from ..compat import (
    inf_is_64bit,
    get_entry_qty,
    get_entry_ordinal,
    get_entry,
    get_entry_name,
)
from ...utils import get_image_size
from ...infrastructure.cache.strings_cache import get_strings_cache as _get_strings_cache

# Max functions to iterate for xref counting on large binaries.
_MAX_FUNC_ITER = 10_000

# Max strings to process in build_interesting_strings (perf cap).
_MAX_STRING_ITER = 5_000

# Max xrefs to materialize per string.
_MAX_XREFS_PER_STRING = 200

# Import category rules: keyword -> category name.
# Order matters: first match wins.
_IMPORT_CATEGORIES: list[tuple[str, "re.Pattern[str]"]] = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE)),
    ("process", re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE)),
    ("registry", re.compile(r"reg|registry|hkey", re.IGNORECASE)),
    ("file_io", re.compile(r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile|deletefile|createfile", re.IGNORECASE)),
]


class SurveyAdapter:
    """Lowest-level IDA SDK access for the binary survey."""

    # Re-expose perf caps so the service can read them.
    MAX_FUNC_ITER = _MAX_FUNC_ITER

    def get_strings_cache(self) -> list[tuple[int, str]]:
        return _get_strings_cache()

    def list_functions(self) -> list[int]:
        import idautils

        return list(idautils.Functions())

    def classify_import(self, name: str) -> str:
        for category, pattern in _IMPORT_CATEGORIES:
            if pattern.search(name):
                return category
        return "other"

    def build_metadata(self) -> dict:
        import idaapi
        import idc
        import ida_nalt

        path = idc.get_idb_path()
        module = ida_nalt.get_root_filename()
        base = hex(idaapi.get_imagebase())
        size = hex(get_image_size())
        is_64 = inf_is_64bit()

        input_path = ida_nalt.get_input_file_path()
        try:
            with open(input_path, "rb") as f:
                data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        except Exception:
            md5 = sha256 = "unavailable"

        return {
            "path": path,
            "module": module,
            "arch": "64" if is_64 else "32",
            "base_address": base,
            "image_size": size,
            "md5": md5,
            "sha256": sha256,
        }

    def build_segments(self) -> list[dict]:
        import idaapi
        import idautils
        import ida_segment

        segments = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            perms = []
            if seg.perm & idaapi.SEGPERM_READ:
                perms.append("r")
            if seg.perm & idaapi.SEGPERM_WRITE:
                perms.append("w")
            if seg.perm & idaapi.SEGPERM_EXEC:
                perms.append("x")
            segments.append({
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.size()),
                "permissions": "".join(perms) or "---",
            })
        return segments

    def build_entrypoints(self) -> list[dict]:
        entrypoints = []
        entry_count = get_entry_qty()
        for i in range(entry_count):
            ordinal = get_entry_ordinal(i)
            ea = get_entry(ordinal)
            name = get_entry_name(ordinal)
            entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
        return entrypoints

    def build_statistics(self, func_eas: list[int], string_count: int, segment_count: int) -> dict:
        import idaapi
        import idc

        total = len(func_eas)
        named = 0
        library = 0
        unnamed = 0

        for ea in func_eas:
            name = idc.get_name(ea, 0) or ""
            func = idaapi.get_func(ea)
            flags = func.flags if func else 0

            if name.startswith("sub_"):
                unnamed += 1
            elif flags & idaapi.FUNC_LIB:
                library += 1
            else:
                named += 1

        return {
            "total_functions": total,
            "named_functions": named,
            "library_functions": library,
            "unnamed_functions": unnamed,
            "total_strings": string_count,
            "total_segments": segment_count,
        }

    def build_interesting_strings(self) -> list[dict]:
        import idautils

        strings = _get_strings_cache()

        if len(strings) > _MAX_STRING_ITER:
            strings = strings[:_MAX_STRING_ITER]

        scored: list[tuple[int, int, str]] = []

        for ea, s in strings:
            count = sum(1 for _ in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_STRING))
            if count == 0:
                continue
            scored.append((count, ea, s))

        scored.sort(key=lambda t: t[0], reverse=True)
        # Top 15 only — compact: string value + xref count, no referencing function lists.
        return [
            {"addr": hex(ea), "string": s, "xref_count": xref_count}
            for xref_count, ea, s in scored[:15]
        ]

    def _is_library_func(self, ea: int, name: str, flags: int) -> bool:
        """A function is 'library' if it has a FLIRT signature."""
        import idaapi

        return bool(flags & idaapi.FUNC_LIB)

    def _classify_func(self, ea: int, func, name: str, callee_count: int) -> str:
        """Classify function as thunk/wrapper/leaf/dispatcher/complex."""
        import idaapi

        flags = func.flags
        size = func.end_ea - func.start_ea
        if flags & idaapi.FUNC_THUNK or size <= 8:
            return "thunk"
        if callee_count == 1 and size < 100:
            return "wrapper"
        if callee_count == 0:
            return "leaf"
        if callee_count > 10:
            return "dispatcher"
        return "complex"

    def build_interesting_functions(self, func_eas: list[int], truncated: bool) -> list[dict]:
        import idaapi
        import idautils
        import idc

        candidates: list[tuple[int, int, str, int, int]] = []

        for ea in func_eas:
            func = idaapi.get_func(ea)
            if not func:
                continue
            name = idc.get_name(ea, 0) or ""
            flags = func.flags

            if self._is_library_func(ea, name, flags):
                continue

            xref_count = len(list(idautils.XrefsTo(ea, 0)))
            size = func.size()
            candidates.append((xref_count, ea, name, size, flags))

        candidates.sort(key=lambda t: t[0], reverse=True)
        # Top 15 with classification hints.
        top = candidates[:15]

        result = []
        for xref_count, ea, name, size, _flags in top:
            func = idaapi.get_func(ea)
            callee_count = 0
            for item_ea in idautils.FuncItems(ea):
                for xref in idautils.XrefsFrom(item_ea, 0):
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                        callee_count += 1

            classification = self._classify_func(ea, func, name, callee_count)
            result.append({
                "addr": hex(ea),
                "name": name,
                "size": size,
                "xref_count": xref_count,
                "callee_count": callee_count,
                "type": classification,
            })
        return result

    def build_imports_by_category(self) -> dict[str, list[dict]]:
        import ida_nalt

        categories: dict[str, list[dict]] = {
            "crypto": [],
            "network": [],
            "file_io": [],
            "process": [],
            "registry": [],
            "other": [],
        }

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

            collected: list[tuple[int, str]] = []

            def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
                name = symbol_name if symbol_name else f"#{ordinal}"
                collected.append((ea, name))
                return True

            ida_nalt.enum_import_names(i, imp_cb)

            for ea, name in collected:
                cat = self.classify_import(name)
                categories[cat].append({
                    "addr": hex(ea),
                    "name": name,
                    "module": module_name,
                })

        return categories

    def build_call_graph_summary(self, func_eas: list[int]) -> dict:
        import idaapi
        import idautils

        total_edges = 0
        root_functions: list[str] = []
        leaf_count = 0

        for ea in func_eas:
            has_callers = False
            has_callees = False

            # Check incoming xrefs (callers)
            for xref in idautils.XrefsTo(ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    has_callers = True
                    break

            # Check outgoing code refs (callees)
            for item_ea in idautils.FuncItems(ea):
                for xref in idautils.XrefsFrom(item_ea, 0):
                    if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                        total_edges += 1
                        has_callees = True

            if not has_callers:
                name = idaapi.get_name(ea) or hex(ea)
                root_functions.append(name)
            if not has_callees:
                leaf_count += 1

        return {
            "total_edges": total_edges,
            "max_depth_estimate": None,  # would require full DFS; omitted for performance
            "root_functions": root_functions[:100],  # cap to avoid massive output
            "leaf_functions_count": leaf_count,
        }

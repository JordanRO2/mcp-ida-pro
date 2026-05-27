"""Infrastructure adapter for browsable IDB resources.

Wraps the ``idaapi``/``ida_*`` calls used by the resources service so the
orchestration layer stays free of direct IDA SDK access. Behavior is a faithful
extraction of the original ``api_resources`` handlers.
"""

from __future__ import annotations

import hashlib
import zlib

import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils
import idc
import ida_funcs
import ida_bytes

from .. import compat
from ...utils import (
    get_image_size,
    parse_address,
    get_prototype,
)


class ResourcesAdapter:
    """Low-level IDA SDK access for browsable resources."""

    # ---- core IDB state --------------------------------------------------

    @staticmethod
    def idb_path() -> str:
        return idc.get_idb_path()

    @staticmethod
    def root_filename() -> str:
        return ida_nalt.get_root_filename()

    @staticmethod
    def imagebase_hex() -> str:
        return hex(idaapi.get_imagebase())

    @staticmethod
    def image_size_hex() -> str:
        return hex(get_image_size())

    @staticmethod
    def input_file_hashes() -> dict:
        """Return md5/sha256/crc32/filesize of the input file (or 'unavailable')."""
        input_path = ida_nalt.get_input_file_path()
        try:
            with open(input_path, "rb") as f:
                data = f.read()
            return {
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "crc32": hex(zlib.crc32(data) & 0xFFFFFFFF),
                "filesize": hex(len(data)),
            }
        except Exception:
            return {
                "md5": "unavailable",
                "sha256": "unavailable",
                "crc32": "unavailable",
                "filesize": "unavailable",
            }

    @staticmethod
    def iter_segments():
        """Yield dicts describing each segment with permissions."""
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
            yield {
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": hex(seg.size()),
                "permissions": "".join(perms) if perms else "---",
            }

    @staticmethod
    def iter_entrypoints():
        """Yield (ea, name, ordinal) for all entry points."""
        entry_count = compat.get_entry_qty()
        for i in range(entry_count):
            ordinal = compat.get_entry_ordinal(i)
            ea = compat.get_entry(ordinal)
            name = compat.get_entry_name(ordinal)
            yield ea, name, ordinal

    # ---- UI state --------------------------------------------------------

    @staticmethod
    def screen_ea() -> int:
        import ida_kernwin
        return ida_kernwin.get_screen_ea()

    @staticmethod
    def get_func(ea: int):
        return idaapi.get_func(ea)

    @staticmethod
    def func_name(func) -> str:
        return compat.get_func_name(func)

    @staticmethod
    def read_range_selection():
        import ida_kernwin
        return ida_kernwin.read_range_selection(None)

    # ---- function / global ----------------------------------------------

    @staticmethod
    def parse_address(addr: str) -> int:
        return parse_address(addr)

    @staticmethod
    def get_func_strict(ea: int):
        return ida_funcs.get_func(ea)

    @staticmethod
    def get_name(ea: int) -> str:
        return idc.get_name(ea, 0) or ""

    @staticmethod
    def get_prototype(func):
        return get_prototype(func)

    @staticmethod
    def func_flag_names(flags) -> list[str]:
        names = []
        for fname, fval in [
            ("FUNC_LIB", idaapi.FUNC_LIB),
            ("FUNC_THUNK", idaapi.FUNC_THUNK),
            ("FUNC_FRAME", idaapi.FUNC_FRAME),
        ]:
            if flags & fval:
                names.append(fname)
        return names

    @staticmethod
    def global_info(ea: int) -> dict:
        flags = ida_bytes.get_flags(ea)
        size = ida_bytes.get_item_size(ea)

        tif = ida_typeinf.tinfo_t()
        type_str = None
        if ida_nalt.get_tinfo(tif, ea):
            type_str = str(tif)

        kind = "unknown"
        if ida_bytes.is_code(flags):
            kind = "code"
        elif ida_bytes.is_data(flags):
            kind = "data"

        return {"size": size, "type": type_str, "kind": kind}

    # ---- types -----------------------------------------------------------

    @staticmethod
    def iter_local_types():
        """Yield (ordinal, name, type_str) for all numbered local types."""
        for ordinal in range(1, compat.get_ordinal_limit(None)):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal):
                yield ordinal, tif.get_type_name(), str(tif)

    @staticmethod
    def iter_structs():
        """Yield dicts for all UDT (struct/union) numbered types."""
        limit = compat.get_ordinal_limit()
        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal) and tif.is_udt():
                udt_data = ida_typeinf.udt_type_data_t()
                is_union = False
                if tif.get_udt_details(udt_data):
                    is_union = udt_data.is_union
                yield {
                    "name": tif.get_type_name(),
                    "size": hex(tif.get_size()),
                    "is_union": is_union,
                }

    @staticmethod
    def struct_definition(name: str):
        """Return (error_str | None, dict | None) for a struct by name.

        On success returns (None, {"size": ..., "members": [...]}); on failure
        returns (error_message, None).
        """
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return f"Structure not found: {name}", None

        if not tif.is_udt():
            return f"'{name}' is not a structure/union", None

        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return f"Failed to get struct details for '{name}'", None

        members = []
        for member in udt_data:
            members.append({
                "name": member.name,
                "offset": hex(member.offset // 8),
                "size": hex(member.size // 8),
                "type": str(member.type),
            })

        return None, {"size": hex(tif.get_size()), "members": members}

    @staticmethod
    def type_definition(name: str):
        """Return (error_str | None, dict | None) for a type by name."""
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, name):
            return f"Type not found: {name}", None

        result = {
            "name": name,
            "size": tif.get_size(),
            "declaration": str(tif),
        }

        if tif.is_udt():
            udt_data = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt_data):
                result["kind"] = "union" if udt_data.is_union else "struct"
                result["members"] = [
                    {
                        "name": member.name,
                        "offset": hex(member.offset // 8),
                        "size": hex(member.size // 8),
                        "type": str(member.type),
                    }
                    for member in udt_data
                ]
        elif tif.is_enum():
            result["kind"] = "enum"
        elif tif.is_ptr():
            result["kind"] = "pointer"
        else:
            result["kind"] = "typedef"

        return None, result

    # ---- imports / exports ----------------------------------------------

    @staticmethod
    def find_import(name: str):
        """Return import dict matching name (or {"error": ...})."""
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module = ida_nalt.get_import_module_name(i)
            result = {}

            def callback(ea, imp_name, ordinal):
                if imp_name == name or f"ord_{ordinal}" == name:
                    result.update({
                        "addr": hex(ea),
                        "name": imp_name or f"ord_{ordinal}",
                        "module": module,
                        "ordinal": ordinal,
                    })
                    return False  # Stop enumeration
                return True

            ida_nalt.enum_import_names(i, callback)
            if result:
                return result

        return {"error": f"Import not found: {name}"}

    @staticmethod
    def find_export(name: str):
        """Return export dict matching name (or {"error": ...})."""
        entry_count = compat.get_entry_qty()
        for i in range(entry_count):
            ordinal = compat.get_entry_ordinal(i)
            ea = compat.get_entry(ordinal)
            entry_name = compat.get_entry_name(ordinal)

            if entry_name == name:
                return {
                    "addr": hex(ea),
                    "name": entry_name,
                    "ordinal": ordinal,
                }

        return {"error": f"Export not found: {name}"}

    # ---- xrefs -----------------------------------------------------------

    @staticmethod
    def xrefs_from(ea: int) -> list[dict]:
        xrefs = []
        for xref in idautils.XrefsFrom(ea, 0):
            xrefs.append({
                "addr": hex(xref.to),
                "type": "code" if xref.iscode else "data",
            })
        return xrefs

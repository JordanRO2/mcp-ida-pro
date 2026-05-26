"""Application service for browsable IDB resources.

Faithful move of the original ``api_resources`` handler bodies. All IDA SDK
access is delegated to ``ResourcesAdapter``. Return shapes (including the
``Metadata`` / ``Segment`` / ``StructureDefinition`` TypedDicts) are preserved
exactly.
"""

from __future__ import annotations

from typing import Annotated

from ...domain.entities import (
    Metadata,
    Segment,
    StructureDefinition,
    StructureMember,
)


class ResourcesService:
    def __init__(self, adapter) -> None:
        self._adapter = adapter

    # ---- core IDB state --------------------------------------------------

    def idb_metadata(self) -> Metadata:
        a = self._adapter
        path = a.idb_path()
        module = a.root_filename()
        base = a.imagebase_hex()
        size = a.image_size_hex()
        h = a.input_file_hashes()
        return Metadata(
            path=path,
            module=module,
            base=base,
            size=size,
            md5=h["md5"],
            sha256=h["sha256"],
            crc32=h["crc32"],
            filesize=h["filesize"],
        )

    def idb_segments(self) -> list[Segment]:
        a = self._adapter
        segments = []
        for s in a.iter_segments():
            segments.append(
                Segment(
                    name=s["name"],
                    start=s["start"],
                    end=s["end"],
                    size=s["size"],
                    permissions=s["permissions"],
                )
            )
        return segments

    def idb_entrypoints(self) -> list[dict]:
        a = self._adapter
        entrypoints = []
        for ea, name, ordinal in a.iter_entrypoints():
            entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
        return entrypoints

    # ---- UI state --------------------------------------------------------

    def cursor(self) -> dict:
        a = self._adapter
        ea = a.screen_ea()
        func = a.get_func(ea)

        result = {"addr": hex(ea)}
        if func:
            func_name = a.func_name(func)
            result["function"] = {
                "addr": hex(func.start_ea),
                "name": func_name,
            }
        return result

    def selection(self) -> dict:
        a = self._adapter
        start = a.read_range_selection()
        if start:
            return {"start": hex(start[0]), "end": hex(start[1]) if start[1] else None}
        return {"selection": None}

    # ---- function / global ----------------------------------------------

    def function(self, addr: str) -> dict:
        a = self._adapter
        ea = a.parse_address(addr)
        func = a.get_func_strict(ea)
        if not func:
            return {"error": f"No function at {addr}"}

        name = a.get_name(func.start_ea)
        proto = a.get_prototype(func)
        flags = func.flags
        size = func.end_ea - func.start_ea
        flag_names = a.func_flag_names(flags)

        return {
            "name": name,
            "addr": hex(func.start_ea),
            "end": hex(func.end_ea),
            "size": size,
            "prototype": proto,
            "flags": flag_names,
        }

    def global_(self, addr: str) -> dict:
        a = self._adapter
        ea = a.parse_address(addr)
        name = a.get_name(ea)
        info = a.global_info(ea)
        return {
            "name": name,
            "addr": hex(ea),
            "size": info["size"],
            "type": info["type"],
            "kind": info["kind"],
        }

    # ---- types -----------------------------------------------------------

    def types(self) -> list[dict]:
        a = self._adapter
        types = []
        for ordinal, name, type_str in a.iter_local_types():
            types.append({"ordinal": ordinal, "name": name, "type": type_str})
        return types

    def structs(self) -> list[dict]:
        a = self._adapter
        return list(a.iter_structs())

    def struct_by_name(self, name: str) -> dict:
        a = self._adapter
        error, data = a.struct_definition(name)
        if error is not None:
            return {"error": error}
        members = [
            StructureMember(
                name=m["name"],
                offset=m["offset"],
                size=m["size"],
                type=m["type"],
            )
            for m in data["members"]
        ]
        return StructureDefinition(name=name, size=data["size"], members=members)

    def type_by_name(self, name: str) -> dict:
        a = self._adapter
        error, data = a.type_definition(name)
        if error is not None:
            return {"error": error}
        return data

    # ---- imports / exports ----------------------------------------------

    def import_by_name(self, name: str) -> dict:
        return self._adapter.find_import(name)

    def export_by_name(self, name: str) -> dict:
        return self._adapter.find_export(name)

    # ---- xrefs -----------------------------------------------------------

    def xrefs_from(self, addr: str) -> list[dict]:
        a = self._adapter
        ea = a.parse_address(addr)
        return a.xrefs_from(ea)

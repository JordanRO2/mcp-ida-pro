"""Application service for core IDB metadata and basic queries.

Orchestration logic moved verbatim from the legacy flat ``api_core`` module.
The 12 core tools delegate here; raw IDA SDK access lives in
``CoreAdapter``. ``idaapi`` is still touched directly for a couple of constant
look-ups (``BADADDR``) and the function fast-path, where pushing it into the
adapter would not improve clarity — behavior preservation outranks purity.
"""

from __future__ import annotations

import re
import time

import idaapi

from ...infrastructure.adapters.core_adapter import CoreAdapter
from ...infrastructure.cache.strings_cache import get_strings_cache, init_caches
from ...domain.entities import (
    Function,
    Global,
    Import,
)
from ...domain.value_objects import ConvertedNumber
from ...utils import (
    get_function,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    paginate,
    pattern_filter,
)


class CoreService:
    """High-level service for core metadata/query tools."""

    def __init__(self, adapter: CoreAdapter):
        self.adapter = adapter

    # -- internal helpers (moved verbatim) -------------------------------

    @staticmethod
    def _parse_func_query(query: str) -> int:
        """Fast path for common function query patterns. Returns ea or BADADDR."""
        q = query.strip()

        # 0x<hex> - direct address
        if q.startswith("0x") or q.startswith("0X"):
            try:
                return int(q, 16)
            except ValueError:
                pass

        # sub_<hex> - IDA auto-named function
        if q.startswith("sub_"):
            try:
                return int(q[4:], 16)
            except ValueError:
                pass

        return idaapi.BADADDR

    @staticmethod
    def _coerce_sort_number(value, default: int = 0) -> int:
        """Parse decimal or prefixed string numbers used by generic entity rows."""
        if value in (None, ""):
            return default
        if isinstance(value, int):
            return value
        try:
            return int(str(value), 0)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _primary_text_key(kind: str) -> str:
        if kind == "strings":
            return "text"
        return "name"

    def _collect_entities(self, kind: str) -> list[dict]:
        if kind == "functions":
            return self.adapter.collect_function_rows()
        if kind == "globals":
            return self.adapter.collect_global_rows()
        if kind == "imports":
            return self.adapter.collect_import_rows()
        if kind == "strings":
            return self.adapter.collect_string_rows()
        if kind == "names":
            return self.adapter.collect_name_rows()
        return []

    @staticmethod
    def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
        if not fields:
            return items
        normalized = [str(f).strip() for f in fields if str(f).strip()]
        if not normalized:
            return items
        keep = set(normalized)
        keep.add("kind")
        projected = []
        for item in items:
            projected.append({k: v for k, v in item.items() if k in keep})
        return projected

    # -- tool orchestration ----------------------------------------------

    def server_health(self) -> dict:
        return self.adapter.build_health_payload()

    def server_warmup(
        self,
        wait_auto_analysis: bool = True,
        build_caches: bool = True,
        init_hexrays: bool = True,
    ) -> dict:
        steps = []

        if wait_auto_analysis:
            t0 = time.perf_counter()
            self.adapter.auto_wait()
            steps.append({"step": "auto_wait", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 2)})

        if build_caches:
            t0 = time.perf_counter()
            init_caches()
            steps.append({"step": "init_caches", "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 2)})

        if init_hexrays:
            t0 = time.perf_counter()
            ok = self.adapter.init_hexrays()
            steps.append(
                {
                    "step": "init_hexrays",
                    "ok": ok,
                    "ms": round((time.perf_counter() - t0) * 1000, 2),
                    "error": None if ok else "Hex-Rays unavailable",
                }
            )

        return {
            "ok": all(bool(step.get("ok")) for step in steps),
            "steps": steps,
            "health": self.adapter.build_health_payload(),
        }

    def lookup_funcs(self, queries) -> list[dict]:
        queries = normalize_list_input(queries)

        # Treat empty/"*" as "all functions" - but add limit
        if not queries or (len(queries) == 1 and queries[0] in ("*", "")):
            all_funcs = []
            for addr in self.adapter.iter_function_addrs():
                all_funcs.append(get_function(addr))
                if len(all_funcs) >= 1000:
                    break
            return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

        results = []
        for query in queries:
            try:
                # Fast path: 0x<ea> or sub_<ea>
                ea = self._parse_func_query(query)

                # Slow path: name lookup
                if ea == idaapi.BADADDR:
                    ea = self.adapter.get_name_ea(query)

                if ea != idaapi.BADADDR:
                    func = get_function(ea, raise_error=False)
                    if func:
                        results.append({"query": query, "fn": func, "error": None})
                    else:
                        results.append(
                            {"query": query, "fn": None, "error": "Not a function"}
                        )
                else:
                    results.append({"query": query, "fn": None, "error": "Not found"})
            except Exception as e:
                results.append({"query": query, "fn": None, "error": str(e)})

        return results

    def int_convert(self, inputs) -> list[dict]:
        inputs = normalize_dict_list(inputs, lambda s: {"text": s, "size": 64})

        results = []
        for item in inputs:
            text = item.get("text", "")
            size = item.get("size")

            try:
                value = int(text, 0)
            except ValueError:
                results.append(
                    {"input": text, "result": None, "error": f"Invalid number: {text}"}
                )
                continue

            if not size:
                size = 0
                n = abs(value)
                while n:
                    size += 1
                    n >>= 1
                size += 7
                size //= 8

            try:
                bytes_data = value.to_bytes(size, "little", signed=True)
            except OverflowError:
                results.append(
                    {
                        "input": text,
                        "result": None,
                        "error": f"Number {text} is too big for {size} bytes",
                    }
                )
                continue

            ascii_str = ""
            for byte in bytes_data.rstrip(b"\x00"):
                if byte >= 32 and byte <= 126:
                    ascii_str += chr(byte)
                else:
                    ascii_str = None
                    break

            results.append(
                {
                    "input": text,
                    "result": ConvertedNumber(
                        decimal=str(value),
                        hexadecimal=hex(value),
                        bytes=bytes_data.hex(" "),
                        ascii=ascii_str,
                        binary=bin(value),
                    ),
                    "error": None,
                }
            )

        return results

    def list_funcs(self, queries) -> list:
        queries = normalize_dict_list(
            queries, lambda s: {"offset": 0, "count": 50, "filter": s}
        )
        all_functions = [get_function(addr) for addr in self.adapter.iter_function_addrs()]

        results = []
        for query in queries:
            offset = query.get("offset", 0)
            count = query.get("count", 100)
            filter_pattern = query.get("filter", "")

            # Treat empty/"*" filter as "all"
            if filter_pattern in ("", "*"):
                filter_pattern = ""

            filtered = pattern_filter(all_functions, filter_pattern, "name")
            results.append(paginate(filtered, offset, count))

        return results

    def func_query(self, queries) -> list[dict]:
        queries = normalize_dict_list(
            queries,
            lambda s: {
                "filter": s,
                "offset": 0,
                "count": 50,
                "sort_by": "addr",
                "descending": False,
            },
        )

        all_functions = self.adapter.collect_func_query_rows()

        def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
            if not expr:
                return items
            try:
                compiled = re.compile(expr)
            except re.error:
                return []
            return [item for item in items if compiled.search(item["name"])]

        results = []
        for query in queries:
            offset = query.get("offset", 0)
            count = query.get("count", 50)
            sort_by = query.get("sort_by", "addr")
            descending = bool(query.get("descending", False))
            if sort_by not in ("addr", "name", "size"):
                sort_by = "addr"

            filtered = all_functions
            name_filter = query.get("filter", "")
            if name_filter:
                filtered = pattern_filter(filtered, name_filter, "name")

            name_regex = query.get("name_regex", "")
            if name_regex:
                filtered = apply_name_regex(filtered, name_regex)

            min_size = query.get("min_size")
            if min_size is not None:
                filtered = [f for f in filtered if f["size_int"] >= int(min_size)]

            max_size = query.get("max_size")
            if max_size is not None:
                filtered = [f for f in filtered if f["size_int"] <= int(max_size)]

            if "has_type" in query:
                require_type = bool(query.get("has_type"))
                filtered = [f for f in filtered if bool(f["has_type"]) is require_type]

            if sort_by == "name":
                filtered.sort(key=lambda f: f["name"].lower(), reverse=descending)
            elif sort_by == "size":
                filtered.sort(key=lambda f: f["size_int"], reverse=descending)
            else:
                filtered.sort(key=lambda f: int(f["addr"], 16), reverse=descending)

            page = paginate(filtered, offset, count)
            page["data"] = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]
            results.append(page)

        return results

    def list_globals(self, queries) -> list:
        queries = normalize_dict_list(
            queries, lambda s: {"offset": 0, "count": 50, "filter": s}
        )
        all_globals: list[Global] = []
        for addr, name in self.adapter.names():
            if not self.adapter.get_func(addr) and name is not None:
                all_globals.append(Global(addr=hex(addr), name=name))

        results = []
        for query in queries:
            offset = query.get("offset", 0)
            count = query.get("count", 100)
            filter_pattern = query.get("filter", "")

            # Treat empty/"*" filter as "all"
            if filter_pattern in ("", "*"):
                filter_pattern = ""

            filtered = pattern_filter(all_globals, filter_pattern, "name")
            results.append(paginate(filtered, offset, count))

        return results

    def entity_query(self, queries) -> list[dict]:
        queries = normalize_dict_list(
            queries,
            lambda s: {"kind": s, "offset": 0, "count": 100, "sort_by": "addr"},
        )
        results: list[dict] = []

        for query in queries:
            kind = str(query.get("kind", "functions") or "functions").lower()
            if kind not in {"functions", "globals", "imports", "strings", "names"}:
                results.append(
                    {
                        "kind": kind,
                        "data": [],
                        "next_offset": None,
                        "total": 0,
                        "error": f"Unsupported kind: {kind}",
                    }
                )
                continue

            rows = self._collect_entities(kind)
            primary_key = self._primary_text_key(kind)
            filter_pattern = str(query.get("filter", "") or "")
            if filter_pattern:
                rows = pattern_filter(rows, filter_pattern, primary_key)

            regex = str(query.get("regex", "") or "")
            if regex:
                try:
                    compiled = re.compile(regex)
                    rows = [row for row in rows if compiled.search(str(row.get(primary_key, "")))]
                except re.error:
                    rows = []

            segment_filter = str(query.get("segment", "") or "")
            if segment_filter and kind in {"functions", "globals", "strings", "names"}:
                rows = pattern_filter(rows, segment_filter, "segment")

            module_filter = str(query.get("module", "") or "")
            if module_filter and kind == "imports":
                rows = pattern_filter(rows, module_filter, "module")

            min_addr = query.get("min_addr")
            if min_addr not in (None, ""):
                try:
                    min_ea = parse_address(min_addr)
                    rows = [row for row in rows if int(str(row["addr"]), 16) >= min_ea]
                except Exception:
                    rows = []

            max_addr = query.get("max_addr")
            if max_addr not in (None, ""):
                try:
                    max_ea = parse_address(max_addr)
                    rows = [row for row in rows if int(str(row["addr"]), 16) <= max_ea]
                except Exception:
                    rows = []

            sort_by = str(query.get("sort_by", "addr") or "addr")
            descending = bool(query.get("descending", False))
            if sort_by == "addr":
                rows.sort(key=lambda row: int(str(row.get("addr", "0x0")), 16), reverse=descending)
            elif sort_by in {"size", "length"}:
                rows.sort(
                    key=lambda row: row.get("size_int", self._coerce_sort_number(row.get(sort_by, 0))),
                    reverse=descending,
                )
            else:
                rows.sort(key=lambda row: str(row.get(sort_by, "")).lower(), reverse=descending)

            offset = int(query.get("offset", 0) or 0)
            count = int(query.get("count", 100) or 100)
            page = paginate(rows, offset, count)
            data = [{k: v for k, v in item.items() if k != "size_int"} for item in page["data"]]

            fields_raw = query.get("fields")
            fields = None
            if fields_raw is not None:
                if isinstance(fields_raw, str):
                    fields = normalize_list_input(fields_raw)
                elif isinstance(fields_raw, list):
                    fields = [str(f) for f in fields_raw]
                else:
                    fields = [str(fields_raw)]
            data = self._apply_projection(data, fields)

            results.append(
                {
                    "kind": kind,
                    "data": data,
                    "next_offset": page["next_offset"],
                    "total": len(rows),
                    "error": None,
                }
            )

        return results

    def imports(self, offset: int, count: int):
        return paginate(self.adapter.collect_imports(), offset, count)

    def imports_query(self, queries) -> list[dict]:
        queries = normalize_dict_list(
            queries, lambda s: {"filter": s, "offset": 0, "count": 100}
        )
        all_imports = self.adapter.collect_imports()
        results = []

        for query in queries:
            filtered = all_imports
            name_filter = query.get("filter", "")
            module_filter = query.get("module", "")

            if name_filter:
                filtered = pattern_filter(filtered, name_filter, "imported_name")
            if module_filter:
                filtered = pattern_filter(filtered, module_filter, "module")

            results.append(
                paginate(filtered, query.get("offset", 0), query.get("count", 100))
            )

        return results

    def idb_save(self, path: str = "") -> dict:
        try:
            save_path = path.strip() if path else ""
            if not save_path:
                save_path = self.adapter.get_idb_path()
            if not save_path:
                return {"ok": False, "path": None, "error": "Could not resolve IDB path"}

            ok = self.adapter.save_database(save_path)
            return {
                "ok": ok,
                "path": save_path,
                "error": None if ok else "save_database returned false",
            }
        except Exception as e:
            return {"ok": False, "path": path or None, "error": str(e)}

    def find_regex(self, pattern: str, limit: int = 30, offset: int = 0) -> dict:
        if limit <= 0:
            limit = 30
        if limit > 500:
            limit = 500

        matches = []
        regex = re.compile(pattern, re.IGNORECASE)
        strings = get_strings_cache()

        skipped = 0
        more = False
        for ea, text in strings:
            if regex.search(text):
                if skipped < offset:
                    skipped += 1
                    continue
                if len(matches) >= limit:
                    more = True
                    break
                matches.append({"addr": hex(ea), "string": text})

        return {
            "n": len(matches),
            "matches": matches,
            "cursor": {"next": offset + limit} if more else {"done": True},
        }

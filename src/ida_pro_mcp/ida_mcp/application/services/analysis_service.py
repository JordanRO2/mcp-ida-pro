"""Application service for code analysis & decompilation tools."""

from __future__ import annotations

from itertools import islice
from typing import Optional

from ...infrastructure.adapters.analysis_adapter import AnalysisAdapter
from ...infrastructure.sync.sync import IDAError
from ...utils import (
    parse_address,
    normalize_list_input,
    normalize_dict_list,
    get_function,
    get_prototype,
    paginate,
    pattern_filter,
    get_stack_frame_variables_internal,
    decompile_function_safe,
    get_assembly_lines,
    get_all_xrefs,
    get_all_comments,
    get_callers,
    get_callees,
    extract_function_strings,
    extract_function_constants,
)
from ...domain.entities import (
    Argument,
    DisassemblyFunction,
    Xref,
    BasicBlock,
)


def _clamp_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        i = int(value)
    except Exception:
        i = default
    if i < minimum:
        return minimum
    if i > maximum:
        return maximum
    return i


def _parse_optional_int(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 0)
        except Exception as e:
            raise ValueError(f"{field} must be an integer") from e
    try:
        return int(value)
    except Exception as e:
        raise ValueError(f"{field} must be an integer") from e


def _limit_items(items: list, limit: int) -> tuple[list, bool]:
    if limit < 0:
        limit = 0
    if len(items) <= limit:
        return items, False
    return items[:limit], True


class AnalysisService:
    """High-level orchestration for code-analysis tools."""

    def __init__(self, adapter: AnalysisAdapter):
        self.adapter = adapter

    # ------------------------------------------------------------------
    # Internal profiling helper
    # ------------------------------------------------------------------

    def _profile_function(
        self,
        start_ea: int,
        include_lists: bool,
        max_items: int,
        include_prototype: bool,
    ) -> dict:
        func = self.adapter.get_func(start_ea)
        if not func:
            return {"addr": hex(start_ea), "error": "Function not found"}

        name = self.adapter.get_func_name(func.start_ea)
        size_int = func.end_ea - func.start_ea
        has_type = self.adapter.has_type(func.start_ea)

        instruction_count = self.adapter.count_instructions(func.start_ea)
        basic_block_count = self.adapter.count_basic_blocks(func)
        callers = self.adapter.collect_callers_for_function(func)
        callees = self.adapter.collect_callees_for_function(func)
        strings = extract_function_strings(func.start_ea)
        constants = extract_function_constants(func.start_ea)

        out = {
            "addr": hex(func.start_ea),
            "name": name,
            "size": hex(size_int),
            "size_int": size_int,
            "instruction_count": instruction_count,
            "basic_block_count": basic_block_count,
            "caller_count": len(callers),
            "callee_count": len(callees),
            "string_ref_count": len(strings),
            "constant_count": len(constants),
            "has_type": has_type,
            "prototype": None,
            "error": None,
        }

        if include_prototype:
            out["prototype"] = get_prototype(func)

        if include_lists:
            callers_limited, callers_truncated = _limit_items(callers, max_items)
            callees_limited, callees_truncated = _limit_items(callees, max_items)
            strings_limited, strings_truncated = _limit_items(strings, max_items)
            constants_limited, constants_truncated = _limit_items(constants, max_items)

            out["callers"] = callers_limited
            out["callers_truncated"] = callers_truncated
            out["callees"] = callees_limited
            out["callees_truncated"] = callees_truncated
            out["strings"] = strings_limited
            out["strings_truncated"] = strings_truncated
            out["constants"] = constants_limited
            out["constants_truncated"] = constants_truncated

        return out

    # ------------------------------------------------------------------
    # decompile
    # ------------------------------------------------------------------

    def decompile(self, addr: str, include_addresses: bool = True, timeout=None) -> dict:
        try:
            start = parse_address(addr)
            code, err = decompile_function_safe(start, include_addresses)
            if code is None:
                return {"addr": addr, "code": None, "error": err or "Decompilation failed"}
            return {"addr": addr, "code": code}
        except Exception as e:
            return {"addr": addr, "code": None, "error": str(e)}

    # ------------------------------------------------------------------
    # disasm
    # ------------------------------------------------------------------

    def disasm(
        self,
        addr: str,
        max_instructions: int = 5000,
        offset: int = 0,
        include_total: bool = False,
        timeout=None,
    ) -> dict:
        import idaapi

        # Enforce max limit
        if max_instructions <= 0 or max_instructions > 50000:
            max_instructions = 50000
        if offset < 0:
            offset = 0

        try:
            start = parse_address(addr)
            func = self.adapter.get_func(start)

            # Get segment info
            seg = self.adapter.getseg(start)
            if not seg:
                return {
                    "addr": addr,
                    "asm": None,
                    "error": "No segment found",
                    "cursor": {"done": True},
                }

            segment_name = self.adapter.get_segm_name(seg) if seg else "UNKNOWN"

            if func:
                func_name: str = self.adapter.get_func_name(func.start_ea)
                header_addr = start  # Use requested address, not function start
            else:
                func_name = "<no function>"
                header_addr = start

            lines = []
            seen = 0
            total_count = 0
            more = False

            def _maybe_add(ea: int) -> bool:
                nonlocal seen, total_count, more
                if include_total:
                    total_count += 1
                if seen < offset:
                    seen += 1
                    return True
                if len(lines) < max_instructions:
                    instruction = self.adapter.disasm_line(ea)
                    lines.append(f"{ea:x}  {instruction}")
                    seen += 1
                    return True
                more = True
                seen += 1
                return include_total

            if func:
                for ea in self.adapter.func_items(func.start_ea):
                    if ea == idaapi.BADADDR:
                        continue
                    if ea < start:
                        continue
                    if not _maybe_add(ea):
                        break
            else:
                ea = start
                while ea < seg.end_ea:
                    if ea == idaapi.BADADDR:
                        break
                    if self.adapter.decode_insn_at(ea) is None:
                        break
                    if not _maybe_add(ea):
                        break
                    ea = self.adapter.next_head(ea, seg.end_ea)
                    if ea == idaapi.BADADDR:
                        break

            if include_total and not more:
                more = total_count > offset + max_instructions

            lines_str = f"{func_name} ({segment_name} @ {hex(header_addr)}):"
            if lines:
                lines_str += "\n" + "\n".join(lines)

            rettype = None
            args: Optional[list[Argument]] = None
            stack_frame = None

            if func:
                rettype, args = self.adapter.get_func_signature(func)
                stack_frame = get_stack_frame_variables_internal(func.start_ea, False)

            out: DisassemblyFunction = {
                "name": func_name,
                "start_ea": hex(header_addr),
                "lines": lines_str,
            }
            if stack_frame:
                out["stack_frame"] = stack_frame
            if rettype:
                out["return_type"] = rettype
            if args is not None:
                out["arguments"] = args

            return {
                "addr": addr,
                "asm": out,
                "instruction_count": len(lines),
                "total_instructions": total_count if include_total else None,
                "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
            }
        except Exception as e:
            return {
                "addr": addr,
                "asm": None,
                "error": str(e),
                "cursor": {"done": True},
            }

    # ------------------------------------------------------------------
    # func_profile
    # ------------------------------------------------------------------

    def func_profile(self, queries, timeout=None) -> list[dict]:
        queries = normalize_dict_list(
            queries,
            lambda s: {
                "query": s,
                "offset": 0,
                "count": 50,
                "sort_by": "addr",
                "descending": False,
                "include_lists": False,
                "max_items": 25,
                "include_prototype": False,
            },
        )

        results: list[dict] = []
        for query in queries:
            q = str(query.get("query", "*") or "*").strip()
            filter_pattern = str(query.get("filter", "") or "")
            offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
            count = _clamp_int(query.get("count", 50), 50, 0, 1000)
            sort_by = str(query.get("sort_by", "addr") or "addr")
            descending = bool(query.get("descending", False))
            include_lists = bool(query.get("include_lists", False))
            max_items = _clamp_int(query.get("max_items", 25), 25, 0, 1000)
            include_prototype = bool(query.get("include_prototype", False))

            # Resolve candidate function starts.
            candidates: list[dict] = []
            if q not in ("", "*"):
                start_ea, err = self.adapter.resolve_function_start(q)
                if err is not None or start_ea is None:
                    results.append(
                        {
                            "query": q,
                            "data": [],
                            "next_offset": None,
                            "error": err or "Failed to resolve function",
                        }
                    )
                    continue
                fn = self.adapter.get_func(start_ea)
                if fn:
                    candidates.append(self.adapter.func_summary(fn))
            else:
                for start_ea in self.adapter.list_function_starts():
                    fn = self.adapter.get_func(start_ea)
                    if not fn:
                        continue
                    candidates.append(self.adapter.func_summary(fn))

            if filter_pattern:
                candidates = pattern_filter(candidates, filter_pattern, "name")

            if sort_by == "name":
                candidates.sort(key=lambda f: f["name"].lower(), reverse=descending)
            elif sort_by == "size":
                candidates.sort(key=lambda f: f["size_int"], reverse=descending)
            else:
                candidates.sort(key=lambda f: f["start_ea"], reverse=descending)

            page = paginate(candidates, offset, count)
            profiled: list[dict] = []
            for item in page["data"]:
                profiled.append(
                    self._profile_function(
                        int(item["start_ea"]),
                        include_lists=include_lists,
                        max_items=max_items,
                        include_prototype=include_prototype,
                    )
                )

            for item in profiled:
                item.pop("size_int", None)

            results.append(
                {
                    "query": q,
                    "data": profiled,
                    "next_offset": page["next_offset"],
                    "error": None,
                }
            )

        return results

    # ------------------------------------------------------------------
    # analyze_batch
    # ------------------------------------------------------------------

    def analyze_batch(self, queries, timeout=None) -> list[dict]:
        queries = normalize_dict_list(
            queries,
            lambda s: {
                "query": s,
                "include_decompile": True,
                "include_disasm": False,
                "include_xrefs": True,
                "include_callers": True,
                "include_callees": True,
                "include_strings": True,
                "include_constants": True,
                "include_basic_blocks": True,
                "include_proto": True,
                "max_disasm_insns": 300,
                "max_callers": 100,
                "max_callees": 100,
                "max_strings": 100,
                "max_constants": 200,
                "max_blocks": 500,
            },
        )

        results: list[dict] = []
        for query in queries:
            q = str(query.get("query", "") or query.get("addr", "") or "").strip()
            if not q:
                results.append(
                    {
                        "query": q,
                        "addr": None,
                        "name": None,
                        "analysis": None,
                        "error": "Function query is required",
                    }
                )
                continue

            start_ea, err = self.adapter.resolve_function_start(q)
            if err is not None or start_ea is None:
                results.append(
                    {
                        "query": q,
                        "addr": None,
                        "name": None,
                        "analysis": None,
                        "error": err or "Failed to resolve function",
                    }
                )
                continue

            try:
                fn = self.adapter.get_func(start_ea)
                if not fn:
                    raise RuntimeError(f"Function not found: {q}")

                fn_name = self.adapter.get_func_name(fn.start_ea)
                size_int = fn.end_ea - fn.start_ea

                include_decompile = bool(query.get("include_decompile", True))
                include_disasm = bool(query.get("include_disasm", False))
                include_xrefs = bool(query.get("include_xrefs", True))
                include_callers = bool(query.get("include_callers", True))
                include_callees = bool(query.get("include_callees", True))
                include_strings = bool(query.get("include_strings", True))
                include_constants = bool(query.get("include_constants", True))
                include_basic_blocks = bool(query.get("include_basic_blocks", True))
                include_proto = bool(query.get("include_proto", True))

                max_disasm_insns = _clamp_int(
                    query.get("max_disasm_insns", 300), 300, 0, 50_000
                )
                max_callers = _clamp_int(query.get("max_callers", 100), 100, 0, 5000)
                max_callees = _clamp_int(query.get("max_callees", 100), 100, 0, 5000)
                max_strings = _clamp_int(query.get("max_strings", 100), 100, 0, 5000)
                max_constants = _clamp_int(
                    query.get("max_constants", 200), 200, 0, 10000
                )
                max_blocks = _clamp_int(query.get("max_blocks", 500), 500, 0, 10000)

                analysis: dict = {
                    "size": hex(size_int),
                    "prototype": None,
                    "decompile": None,
                    "decompile_error": None,
                    "disasm": None,
                    "xrefs": None,
                    "callers": None,
                    "caller_count": 0,
                    "callers_truncated": False,
                    "callees": None,
                    "callee_count": 0,
                    "callees_truncated": False,
                    "strings": None,
                    "string_ref_count": 0,
                    "strings_truncated": False,
                    "constants": None,
                    "constant_count": 0,
                    "constants_truncated": False,
                    "basic_blocks": None,
                    "basic_block_count": 0,
                    "basic_blocks_truncated": False,
                }

                if include_proto:
                    analysis["prototype"] = get_prototype(fn)

                if include_decompile:
                    code, err = decompile_function_safe(fn.start_ea)
                    analysis["decompile"] = code
                    if code is None:
                        analysis["decompile_error"] = err or "Decompilation failed"

                if include_disasm:
                    lines, disasm_truncated = self.adapter.disasm_lines_limited(
                        fn, max_disasm_insns
                    )
                    analysis["disasm"] = {
                        "lines": lines,
                        "instruction_count": len(lines),
                        "truncated": disasm_truncated,
                    }

                if include_xrefs:
                    xrefs = get_all_xrefs(fn.start_ea)
                    xrefs_to = list(xrefs.get("to", []))
                    xrefs_from = list(xrefs.get("from", []))
                    xrefs_to, xto_trunc = _limit_items(xrefs_to, 200)
                    xrefs_from, xfrom_trunc = _limit_items(xrefs_from, 200)
                    analysis["xrefs"] = {
                        "to": xrefs_to,
                        "from": xrefs_from,
                        "to_truncated": xto_trunc,
                        "from_truncated": xfrom_trunc,
                        "to_count": len(xrefs.get("to", [])),
                        "from_count": len(xrefs.get("from", [])),
                    }
                    if not xrefs.get("to") and not xrefs.get("from"):
                        analysis["xrefs"]["message"] = "No cross-references to this address"

                if include_callers:
                    callers = get_callers(hex(fn.start_ea), limit=max_callers)
                    analysis["caller_count"] = len(callers)
                    analysis["callers"] = callers
                    analysis["callers_truncated"] = (
                        max_callers > 0 and len(callers) >= max_callers
                    )

                if include_callees:
                    all_callees = get_callees(hex(fn.start_ea))
                    limited_callees, callees_truncated = _limit_items(all_callees, max_callees)
                    analysis["callee_count"] = len(all_callees)
                    analysis["callees"] = limited_callees
                    analysis["callees_truncated"] = callees_truncated

                if include_strings:
                    all_strings = extract_function_strings(fn.start_ea)
                    limited_strings, strings_truncated = _limit_items(all_strings, max_strings)
                    analysis["string_ref_count"] = len(all_strings)
                    analysis["strings"] = limited_strings
                    analysis["strings_truncated"] = strings_truncated

                if include_constants:
                    all_constants = extract_function_constants(fn.start_ea)
                    limited_constants, constants_truncated = _limit_items(
                        all_constants, max_constants
                    )
                    analysis["constant_count"] = len(all_constants)
                    analysis["constants"] = limited_constants
                    analysis["constants_truncated"] = constants_truncated

                if include_basic_blocks:
                    blocks, blocks_truncated = self.adapter.collect_basic_blocks_limited(
                        fn, max_blocks
                    )
                    analysis["basic_block_count"] = len(blocks)
                    analysis["basic_blocks"] = blocks
                    analysis["basic_blocks_truncated"] = blocks_truncated

                results.append(
                    {
                        "query": q,
                        "addr": hex(fn.start_ea),
                        "name": fn_name,
                        "analysis": analysis,
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": q,
                        "addr": hex(start_ea),
                        "name": None,
                        "analysis": None,
                        "error": str(e),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # xrefs_to
    # ------------------------------------------------------------------

    def xrefs_to(self, addrs, limit: int = 100) -> list[dict]:
        addrs = normalize_list_input(addrs)

        if limit <= 0 or limit > 1000:
            limit = 1000

        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                if not self.adapter.is_mapped(ea):
                    results.append(
                        {"addr": addr, "xrefs": None, "error": f"Address not mapped: {addr}"}
                    )
                    continue
                xrefs = []
                more = False
                for xref in self.adapter.xrefs_to(ea):
                    if len(xrefs) >= limit:
                        more = True
                        break
                    xrefs.append(
                        Xref(
                            addr=hex(xref.frm),
                            type="code" if xref.iscode else "data",
                            fn=get_function(xref.frm, raise_error=False),
                        )
                    )
                entry = {"addr": addr, "xrefs": xrefs, "more": more, "xref_count": len(xrefs)}
                if not xrefs:
                    entry["message"] = "No cross-references to this address"
                results.append(entry)
            except Exception as e:
                results.append({"addr": addr, "xrefs": None, "error": str(e)})

        return results

    # ------------------------------------------------------------------
    # xref_query
    # ------------------------------------------------------------------

    def xref_query(self, queries) -> list[dict]:
        import idaapi

        queries = normalize_dict_list(
            queries,
            lambda s: {
                "query": s,
                "direction": "both",
                "xref_type": "any",
                "offset": 0,
                "count": 200,
                "include_fn": True,
                "dedup": True,
                "sort_by": "addr",
                "descending": False,
            },
        )

        results: list[dict] = []
        for query in queries:
            q = str(query.get("query", "")).strip()
            direction = str(query.get("direction", "both") or "both").lower()
            xref_type = str(query.get("xref_type", "any") or "any").lower()
            offset = _clamp_int(query.get("offset", 0), 0, 0, 2_000_000_000)
            count = _clamp_int(query.get("count", 200), 200, 0, 5000)
            include_fn = bool(query.get("include_fn", True))
            dedup = bool(query.get("dedup", True))
            sort_by = str(query.get("sort_by", "addr") or "addr")
            descending = bool(query.get("descending", False))

            if direction not in {"to", "from", "both"}:
                direction = "both"
            if xref_type not in {"any", "code", "data"}:
                xref_type = "any"

            try:
                if not q:
                    raise ValueError("query is required")
                try:
                    target = parse_address(q)
                except Exception:
                    target = idaapi.get_name_ea(idaapi.BADADDR, q)
                    if target == idaapi.BADADDR:
                        raise ValueError(f"Failed to resolve address/name: {q}")

                if not self.adapter.is_mapped(target):
                    raise ValueError(f"Address not mapped: {q}")

                rows: list[dict] = []
                if direction in {"to", "both"}:
                    for xr in self.adapter.xrefs_to_flagged(target, 0):
                        kind = "code" if xr.iscode else "data"
                        if xref_type != "any" and kind != xref_type:
                            continue
                        row = {
                            "direction": "to",
                            "addr": hex(xr.frm),
                            "from": hex(xr.frm),
                            "to": hex(target),
                            "type": kind,
                        }
                        if include_fn:
                            row["fn"] = get_function(xr.frm, raise_error=False)
                        rows.append(row)

                if direction in {"from", "both"}:
                    for xr in self.adapter.xrefs_from_flagged(target, 0):
                        kind = "code" if xr.iscode else "data"
                        if xref_type != "any" and kind != xref_type:
                            continue
                        row = {
                            "direction": "from",
                            "addr": hex(xr.to),
                            "from": hex(target),
                            "to": hex(xr.to),
                            "type": kind,
                        }
                        if include_fn:
                            row["fn"] = get_function(xr.to, raise_error=False)
                        rows.append(row)

                if dedup:
                    seen = set()
                    deduped = []
                    for row in rows:
                        key = (row["direction"], row["from"], row["to"], row["type"])
                        if key in seen:
                            continue
                        seen.add(key)
                        deduped.append(row)
                    rows = deduped

                if sort_by == "type":
                    rows.sort(
                        key=lambda r: (str(r.get("type", "")), int(str(r["addr"]), 16)),
                        reverse=descending,
                    )
                else:
                    rows.sort(key=lambda r: int(str(r["addr"]), 16), reverse=descending)

                page = paginate(rows, offset, count)
                page_result = {
                    "query": q,
                    "resolved_addr": hex(target),
                    "direction": direction,
                    "xref_type": xref_type,
                    "data": page["data"],
                    "next_offset": page["next_offset"],
                    "total": len(rows),
                    "error": None,
                }
                if len(rows) == 0:
                    page_result["message"] = "No cross-references to this address"
                results.append(page_result)
            except Exception as e:
                results.append(
                    {
                        "query": q,
                        "resolved_addr": None,
                        "direction": direction,
                        "xref_type": xref_type,
                        "data": [],
                        "next_offset": None,
                        "total": 0,
                        "error": str(e),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # xrefs_to_field
    # ------------------------------------------------------------------

    def xrefs_to_field(self, queries) -> list[dict]:
        import idaapi

        if isinstance(queries, dict):
            queries = [queries]

        results = []
        til = self.adapter.get_idati()
        if not til:
            return [
                {
                    "struct": q.get("struct"),
                    "field": q.get("field"),
                    "xrefs": [],
                    "error": "Failed to retrieve type library",
                }
                for q in queries
            ]

        for query in queries:
            struct_name = query.get("struct", "")
            field_name = query.get("field", "")

            try:
                tid, err = self.adapter.get_struct_field_tid(til, struct_name, field_name)
                if err is not None:
                    results.append(
                        {
                            "struct": struct_name,
                            "field": field_name,
                            "xrefs": [],
                            "error": err,
                        }
                    )
                    continue

                xrefs = []
                for xref in self.adapter.xrefs_to(tid):
                    xrefs += [
                        Xref(
                            addr=hex(xref.frm),
                            type="code" if xref.iscode else "data",
                            fn=get_function(xref.frm, raise_error=False),
                        )
                    ]
                field_result = {"struct": struct_name, "field": field_name, "xrefs": xrefs}
                if not xrefs:
                    field_result["message"] = "No cross-references to this struct field"
                results.append(field_result)
            except Exception as e:
                results.append(
                    {
                        "struct": struct_name,
                        "field": field_name,
                        "xrefs": [],
                        "error": str(e),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # callees
    # ------------------------------------------------------------------

    def callees(self, addrs, limit: int = 200) -> list[dict]:
        import idaapi

        addrs = normalize_list_input(addrs)

        if limit <= 0 or limit > 500:
            limit = 500

        results = []

        for fn_addr in addrs:
            try:
                func_start = parse_address(fn_addr)
                func = self.adapter.get_func(func_start)
                if not func:
                    results.append(
                        {"addr": fn_addr, "callees": None, "error": "No function found"}
                    )
                    continue
                func_end = func.end_ea
                callees_dict = {}
                more = False
                current_ea = func_start
                while current_ea < func_end:
                    if len(callees_dict) >= limit:
                        more = True
                        break
                    insn = self.adapter.decode_insn_at(current_ea)
                    if insn is None:
                        next_ea = self.adapter.next_head(current_ea, func_end)
                        if next_ea == idaapi.BADADDR:
                            break
                        current_ea = next_ea
                        continue
                    if self.adapter.is_call_insn(insn):
                        target = self.adapter.call_target(insn)
                        if target is not None and target not in callees_dict:
                            func_type = (
                                "internal"
                                if self.adapter.get_func(target) is not None
                                else "external"
                            )
                            func_name = self.adapter.name_addr(target)
                            if func_name is not None:
                                callees_dict[target] = {
                                    "addr": hex(target),
                                    "name": func_name,
                                    "type": func_type,
                                }
                    next_ea = self.adapter.next_head(current_ea, func_end)
                    if next_ea == idaapi.BADADDR:
                        break
                    current_ea = next_ea

                results.append(
                    {
                        "addr": fn_addr,
                        "callees": list(callees_dict.values()),
                        "more": more,
                    }
                )
            except Exception as e:
                results.append({"addr": fn_addr, "callees": None, "error": str(e)})

        return results

    # ------------------------------------------------------------------
    # find_bytes
    # ------------------------------------------------------------------

    def find_bytes(self, patterns, limit: int = 1000, offset: int = 0, timeout=None) -> list[dict]:
        import time
        import idaapi
        import ida_kernwin
        from ...infrastructure.sync.sync import get_tool_deadline

        patterns = normalize_list_input(patterns)

        # Enforce max limit
        if limit <= 0 or limit > 10000:
            limit = 10000

        deadline = get_tool_deadline()
        results = []
        for pattern in patterns:
            matches = []
            skipped = 0
            more = False
            cancelled = False
            try:
                searcher, build_err = self.adapter.make_bytes_searcher(pattern)
                if build_err is not None:
                    results.append(
                        {
                            "pattern": pattern,
                            "matches": [],
                            "n": 0,
                            "cursor": {"done": True},
                            "error": build_err,
                        }
                    )
                    continue

                # Search with early exit
                ea = self.adapter.inf_get_min_ea()
                max_ea = self.adapter.inf_get_max_ea()
                while ea != idaapi.BADADDR:
                    if (deadline is not None and time.monotonic() >= deadline) or ida_kernwin.user_cancelled():
                        cancelled = True
                        break
                    ea = searcher(ea, max_ea)
                    if ea == idaapi.BADADDR:
                        break
                    if skipped < offset:
                        skipped += 1
                    else:
                        matches.append(hex(ea))
                        if len(matches) >= limit:
                            # Check if there's more
                            next_ea = searcher(ea + 1, max_ea)
                            more = next_ea != idaapi.BADADDR
                            break
                    ea += 1
            except Exception as e:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "n": 0,
                        "cursor": {"done": True},
                        "error": str(e),
                    }
                )
                continue

            if cancelled:
                cursor = {"next": offset + len(matches), "cancelled": True}
            elif more:
                cursor = {"next": offset + limit}
            else:
                cursor = {"done": True}
            results.append(
                {
                    "pattern": pattern,
                    "matches": matches,
                    "n": len(matches),
                    "cursor": cursor,
                }
            )
        return results

    # ------------------------------------------------------------------
    # basic_blocks
    # ------------------------------------------------------------------

    def basic_blocks(self, addrs, max_blocks: int = 1000, offset: int = 0) -> list[dict]:
        addrs = normalize_list_input(addrs)

        # Enforce max limit
        if max_blocks <= 0 or max_blocks > 10000:
            max_blocks = 10000

        results = []
        for fn_addr in addrs:
            try:
                ea = parse_address(fn_addr)
                func = self.adapter.get_func(ea)
                if not func:
                    results.append(
                        {
                            "addr": fn_addr,
                            "error": "Function not found",
                            "blocks": [],
                            "cursor": {"done": True},
                        }
                    )
                    continue

                all_blocks = self.adapter.collect_all_basic_blocks(func)

                # Apply pagination
                total_blocks = len(all_blocks)
                blocks = all_blocks[offset : offset + max_blocks]
                more = offset + max_blocks < total_blocks

                results.append(
                    {
                        "addr": fn_addr,
                        "blocks": blocks,
                        "count": len(blocks),
                        "total_blocks": total_blocks,
                        "cursor": (
                            {"next": offset + max_blocks} if more else {"done": True}
                        ),
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "addr": fn_addr,
                        "error": str(e),
                        "blocks": [],
                        "cursor": {"done": True},
                    }
                )
        return results

    # ------------------------------------------------------------------
    # find
    # ------------------------------------------------------------------

    def find(self, type: str, targets, limit: int = 1000, offset: int = 0, timeout=None) -> list[dict]:
        import idaapi

        if not isinstance(targets, list):
            targets = [targets]

        # Enforce max limit to prevent token overflow
        if limit <= 0 or limit > 10000:
            limit = 10000

        results = []

        if type == "string":
            # Raw byte search for UTF-8 substrings across the binary
            for pattern in targets:
                pattern_str = str(pattern)
                pattern_bytes = pattern_str.encode("utf-8")
                if not pattern_bytes:
                    results.append(
                        {
                            "query": pattern_str,
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": "Empty pattern",
                        }
                    )
                    continue

                matches = []
                skipped = 0
                more = False
                try:
                    ea = self.adapter.inf_get_min_ea()
                    max_ea = self.adapter.inf_get_max_ea()
                    mask = b"\xff" * len(pattern_bytes)
                    while ea != idaapi.BADADDR:
                        ea = self.adapter.raw_bin_search(ea, max_ea, pattern_bytes, mask)
                        if ea != idaapi.BADADDR:
                            if skipped < offset:
                                skipped += 1
                            else:
                                matches.append(hex(ea))
                                if len(matches) >= limit:
                                    next_ea = self.adapter.raw_bin_search(
                                        ea + 1, max_ea, pattern_bytes, mask
                                    )
                                    more = next_ea != idaapi.BADADDR
                                    break
                            ea += 1
                except Exception:
                    pass

                results.append(
                    {
                        "query": pattern_str,
                        "matches": matches,
                        "count": len(matches),
                        "cursor": {"next": offset + limit} if more else {"done": True},
                        "error": None,
                    }
                )

        elif type == "immediate":
            # Search for immediate values
            for value in targets:
                if isinstance(value, str):
                    try:
                        value = int(value, 0)
                    except ValueError:
                        value = 0

                matches = []
                skipped = 0
                more = False
                try:
                    candidates = self.adapter.value_candidates_for_immediate(value)
                    if not candidates:
                        results.append(
                            {
                                "query": value,
                                "matches": [],
                                "count": 0,
                                "cursor": {"done": True},
                                "error": "Immediate out of range",
                            }
                        )
                        continue

                    seen_insn = set()
                    for seg_ea in self.adapter.segments():
                        seg = self.adapter.getseg(seg_ea)
                        if not seg or not (seg.perm & idaapi.SEGPERM_EXEC):
                            continue
                        for normalized, size, pattern_bytes in candidates:
                            ea = seg.start_ea
                            while ea != idaapi.BADADDR and ea < seg.end_ea:
                                ea = self.adapter.raw_bin_search(
                                    ea, seg.end_ea, pattern_bytes, b"\xff" * size
                                )
                                if ea == idaapi.BADADDR:
                                    break

                                insn_start = self.adapter.resolve_immediate_insn_start(
                                    ea, value, seg.start_ea, normalized
                                )
                                if insn_start is not None and insn_start not in seen_insn:
                                    seen_insn.add(insn_start)
                                    if skipped < offset:
                                        skipped += 1
                                    else:
                                        matches.append(hex(insn_start))
                                        if len(matches) >= limit:
                                            more = True
                                            break

                                ea += 1

                            if more:
                                break
                        if more:
                            break
                except Exception:
                    pass

                results.append(
                    {
                        "query": value,
                        "matches": matches,
                        "count": len(matches),
                        "cursor": {"next": offset + limit} if more else {"done": True},
                        "error": None,
                    }
                )

        elif type == "data_ref":
            # Find all data references to targets
            for target_str in targets:
                try:
                    target = parse_address(str(target_str))
                    gen = (hex(xref) for xref in self.adapter.data_refs_to(target))
                    # Skip offset items, take limit+1 to check more
                    matches = list(islice(islice(gen, offset, None), limit + 1))
                    more = len(matches) > limit
                    if more:
                        matches = matches[:limit]

                    results.append(
                        {
                            "query": str(target_str),
                            "matches": matches,
                            "count": len(matches),
                            "cursor": (
                                {"next": offset + limit} if more else {"done": True}
                            ),
                            "error": None,
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "query": str(target_str),
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": str(e),
                        }
                    )

        elif type == "code_ref":
            # Find all code references to targets
            for target_str in targets:
                try:
                    target = parse_address(str(target_str))
                    gen = (hex(xref) for xref in self.adapter.code_refs_to(target, 0))
                    # Skip offset items, take limit+1 to check more
                    matches = list(islice(islice(gen, offset, None), limit + 1))
                    more = len(matches) > limit
                    if more:
                        matches = matches[:limit]

                    results.append(
                        {
                            "query": str(target_str),
                            "matches": matches,
                            "count": len(matches),
                            "cursor": (
                                {"next": offset + limit} if more else {"done": True}
                            ),
                            "error": None,
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "query": str(target_str),
                            "matches": [],
                            "count": 0,
                            "cursor": {"done": True},
                            "error": str(e),
                        }
                    )

        else:
            results.append(
                {
                    "query": None,
                    "matches": [],
                    "count": 0,
                    "cursor": {"done": True},
                    "error": f"Unknown search type: {type}",
                }
            )

        return results

    # ------------------------------------------------------------------
    # insn_query helpers
    # ------------------------------------------------------------------

    def _resolve_insn_scan_ranges(
        self, pattern: dict, allow_broad: bool
    ) -> tuple[list[tuple[int, int]], str | None]:
        func_addr = pattern.get("func")
        segment_name = pattern.get("segment")
        start_s = pattern.get("start")
        end_s = pattern.get("end")

        exec_segments = self.adapter.exec_segments()

        if func_addr is not None:
            try:
                ea = parse_address(func_addr)
                func = self.adapter.get_func(ea)
                if not func:
                    return [], f"Function not found at {func_addr}"
                return [(func.start_ea, func.end_ea)], None
            except Exception as e:
                return [], str(e)

        if segment_name is not None:
            for seg in exec_segments:
                if self.adapter.get_segm_name(seg) == segment_name:
                    return [(seg.start_ea, seg.end_ea)], None
            return [], f"Executable segment not found: {segment_name}"

        if start_s is not None or end_s is not None:
            if start_s is None:
                return [], "start is required when end is set"
            try:
                start_ea = parse_address(start_s)
                end_ea = parse_address(end_s) if end_s is not None else None
            except Exception as e:
                return [], str(e)

            if not exec_segments:
                return [], "No executable segments found"

            if end_ea is None:
                seg = self.adapter.getseg(start_ea)
                if not self.adapter.is_exec_seg(seg):
                    return [], "start address not in executable segment"
                end_ea = seg.end_ea

            if end_ea <= start_ea:
                return [], "end must be greater than start"

            ranges = []
            for seg in exec_segments:
                seg_start = max(seg.start_ea, start_ea)
                seg_end = min(seg.end_ea, end_ea)
                if seg_end > seg_start:
                    ranges.append((seg_start, seg_end))

            if not ranges:
                return [], "No executable ranges within start/end"

            return ranges, None

        if not allow_broad:
            return [], "Scope required: set func/segment/start/end or allow_broad=true"

        if not exec_segments:
            return [], "No executable segments found"

        return [(seg.start_ea, seg.end_ea) for seg in exec_segments], None

    def _scan_insn_ranges(
        self,
        ranges: list[tuple[int, int]],
        mnem: str,
        op0_val: int | None,
        op1_val: int | None,
        op2_val: int | None,
        any_val: int | None,
        limit: int,
        offset: int,
        max_scan_insns: int,
    ) -> tuple[list[str], bool, int, bool, int | None]:
        import idaapi
        import ida_ua

        matches: list[str] = []
        skipped = 0
        scanned = 0
        more = False
        truncated = False
        next_start: int | None = None

        for start_ea, end_ea in ranges:
            ea = start_ea
            while ea < end_ea:
                if scanned >= max_scan_insns:
                    truncated = True
                    next_start = ea
                    break

                scanned += 1

                insn = self.adapter.decode_insn_at(ea)
                if insn is None:
                    ea = self.adapter.next_head(ea, end_ea)
                    if ea == idaapi.BADADDR:
                        break
                    continue

                if mnem and self.adapter.insn_mnem(insn) != mnem:
                    ea = self.adapter.next_head(ea, end_ea)
                    if ea == idaapi.BADADDR:
                        break
                    continue

                match = True
                if op0_val is not None and self.adapter.operand_value(insn, 0) != op0_val:
                    match = False
                if op1_val is not None and self.adapter.operand_value(insn, 1) != op1_val:
                    match = False
                if op2_val is not None and self.adapter.operand_value(insn, 2) != op2_val:
                    match = False

                if any_val is not None and match:
                    found_any = False
                    for i in range(8):
                        if self.adapter.operand_type(insn, i) == ida_ua.o_void:
                            break
                        if self.adapter.operand_value(insn, i) == any_val:
                            found_any = True
                            break
                    if not found_any:
                        match = False

                if match:
                    if skipped < offset:
                        skipped += 1
                    else:
                        matches.append(hex(ea))
                        if len(matches) > limit:
                            more = True
                            matches = matches[:limit]
                            break

                ea = self.adapter.next_head(ea, end_ea)
                if ea == idaapi.BADADDR:
                    break

            if more or truncated:
                break

        return matches, more, scanned, truncated, next_start

    # ------------------------------------------------------------------
    # insn_query
    # ------------------------------------------------------------------

    def insn_query(self, queries, timeout=None) -> list[dict]:
        queries = normalize_dict_list(
            queries,
            lambda s: {
                "mnem": s,
                "offset": 0,
                "count": 100,
                "max_scan_insns": 200000,
                "allow_broad": False,
                "include_fn": False,
                "include_disasm": False,
            },
        )

        results: list[dict] = []
        for pattern in queries:
            mnem = str(pattern.get("mnem", "") or "").strip().lower()
            if mnem == "*":
                mnem = ""

            offset = _clamp_int(pattern.get("offset", 0), 0, 0, 2_000_000_000)
            count = _clamp_int(pattern.get("count", 100), 100, 0, 5000)
            max_scan_insns = _clamp_int(
                pattern.get("max_scan_insns", 200000), 200000, 1, 2_000_000
            )
            allow_broad = bool(pattern.get("allow_broad", False))
            include_fn = bool(pattern.get("include_fn", False))
            include_disasm = bool(pattern.get("include_disasm", False))

            summary = {
                "mnem": mnem or None,
                "op0": pattern.get("op0"),
                "op1": pattern.get("op1"),
                "op2": pattern.get("op2"),
                "op_any": pattern.get("op_any"),
                "func": pattern.get("func"),
                "segment": pattern.get("segment"),
                "start": pattern.get("start"),
                "end": pattern.get("end"),
                "offset": offset,
                "count": count,
                "max_scan_insns": max_scan_insns,
                "allow_broad": allow_broad,
            }

            try:
                op0_val = _parse_optional_int(pattern.get("op0"), "op0")
                op1_val = _parse_optional_int(pattern.get("op1"), "op1")
                op2_val = _parse_optional_int(pattern.get("op2"), "op2")
                any_val = _parse_optional_int(pattern.get("op_any"), "op_any")

                ranges, range_error = self._resolve_insn_scan_ranges(pattern, allow_broad)
                if range_error:
                    raise ValueError(range_error)

                addresses, more, scanned, truncated, next_start = self._scan_insn_ranges(
                    ranges,
                    mnem,
                    op0_val,
                    op1_val,
                    op2_val,
                    any_val,
                    count,
                    offset,
                    max_scan_insns,
                )

                rows = []
                for addr_s in addresses:
                    ea = int(addr_s, 16)
                    row = {"addr": addr_s}
                    if include_disasm:
                        row["disasm"] = self.adapter.disasm_line(ea)
                    if include_fn:
                        row["fn"] = get_function(ea, raise_error=False)
                    rows.append(row)

                summary["op0"] = op0_val
                summary["op1"] = op1_val
                summary["op2"] = op2_val
                summary["op_any"] = any_val

                results.append(
                    {
                        "query": summary,
                        "ranges": [
                            {"start": hex(start_ea), "end": hex(end_ea)}
                            for start_ea, end_ea in ranges
                        ],
                        "matches": rows,
                        "count": len(rows),
                        "cursor": {"next": offset + count} if more else {"done": True},
                        "scanned": scanned,
                        "truncated": truncated,
                        "next_start": hex(next_start) if next_start is not None else None,
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "query": summary,
                        "ranges": [],
                        "matches": [],
                        "count": 0,
                        "cursor": {"done": True},
                        "scanned": 0,
                        "truncated": False,
                        "next_start": None,
                        "error": str(e),
                    }
                )

        return results

    # ------------------------------------------------------------------
    # export_funcs
    # ------------------------------------------------------------------

    def export_funcs(self, addrs, format: str = "json") -> dict:
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                func = self.adapter.get_func(ea)
                if not func:
                    results.append({"addr": addr, "error": "Function not found"})
                    continue

                func_data = {
                    "addr": addr,
                    "name": self.adapter.get_func_name(func.start_ea),
                    "prototype": get_prototype(func),
                    "size": hex(func.end_ea - func.start_ea),
                    "comments": get_all_comments(ea),
                }

                if format == "json":
                    func_data["asm"] = get_assembly_lines(ea)
                    code, err = decompile_function_safe(ea)
                    func_data["code"] = code
                    if code is None and err:
                        func_data["decompile_error"] = err
                    func_data["xrefs"] = get_all_xrefs(ea)

                results.append(func_data)

            except Exception as e:
                results.append({"addr": addr, "error": str(e)})

        if format == "c_header":
            # Generate C header file
            lines = ["// Auto-generated by IDA Pro MCP", ""]
            for func in results:
                if "prototype" in func and func["prototype"]:
                    lines.append(f"{func['prototype']};")
            return {"format": "c_header", "content": "\n".join(lines)}

        elif format == "prototypes":
            # Just prototypes
            prototypes = []
            for func in results:
                if "prototype" in func and func["prototype"]:
                    prototypes.append(
                        {"name": func.get("name"), "prototype": func["prototype"]}
                    )
            return {"format": "prototypes", "functions": prototypes}

        return {"format": "json", "functions": results}

    # ------------------------------------------------------------------
    # callgraph
    # ------------------------------------------------------------------

    def callgraph(
        self,
        roots,
        max_depth: int = 5,
        max_nodes: int = 1000,
        max_edges: int = 5000,
        max_edges_per_func: int = 200,
    ) -> list[dict]:
        roots = normalize_list_input(roots)
        if max_depth < 0:
            max_depth = 0
        if max_nodes <= 0 or max_nodes > 100000:
            max_nodes = 100000
        if max_edges <= 0 or max_edges > 200000:
            max_edges = 200000
        if max_edges_per_func <= 0 or max_edges_per_func > 5000:
            max_edges_per_func = 5000
        results = []

        for root in roots:
            try:
                ea = parse_address(root)
                func = self.adapter.get_func(ea)
                if not func:
                    results.append(
                        {
                            "root": root,
                            "error": "Function not found",
                            "nodes": [],
                            "edges": [],
                        }
                    )
                    continue

                nodes = {}
                edges = []
                visited = set()
                truncated = False
                per_func_capped = False
                limit_reason = None

                def hit_limit(reason: str):
                    nonlocal truncated, limit_reason
                    truncated = True
                    limit_reason = reason

                def traverse(addr, depth):
                    nonlocal per_func_capped
                    if truncated:
                        return
                    if depth > max_depth or addr in visited:
                        return
                    if len(nodes) >= max_nodes:
                        hit_limit("nodes")
                        return
                    visited.add(addr)

                    f = self.adapter.get_func(addr)
                    if not f:
                        return

                    func_name = self.adapter.get_func_name(f.start_ea)
                    nodes[hex(addr)] = {
                        "addr": hex(addr),
                        "name": func_name,
                        "depth": depth,
                    }

                    # Get callees
                    edges_added = 0
                    for item_ea in self.adapter.func_items(f.start_ea):
                        if truncated:
                            break
                        for xref in self.adapter.code_refs_from(item_ea, 0):
                            if truncated:
                                break
                            if edges_added >= max_edges_per_func:
                                per_func_capped = True
                                break
                            callee_func = self.adapter.get_func(xref)
                            if callee_func:
                                if len(edges) >= max_edges:
                                    hit_limit("edges")
                                    break
                                edges.append(
                                    {
                                        "from": hex(addr),
                                        "to": hex(callee_func.start_ea),
                                        "type": "call",
                                    }
                                )
                                edges_added += 1
                                traverse(callee_func.start_ea, depth + 1)
                        if edges_added >= max_edges_per_func:
                            break

                traverse(ea, 0)

                results.append(
                    {
                        "root": root,
                        "nodes": list(nodes.values()),
                        "edges": edges,
                        "max_depth": max_depth,
                        "truncated": truncated,
                        "limit_reason": limit_reason,
                        "max_nodes": max_nodes,
                        "max_edges": max_edges,
                        "max_edges_per_func": max_edges_per_func,
                        "per_func_capped": per_func_capped,
                        "error": None,
                    }
                )

            except Exception as e:
                results.append({"root": root, "error": str(e), "nodes": [], "edges": []})

        return results

"""Application service for security analysis.

Orchestrates vulnerability detection, crypto identification, dangerous-caller
tracing, stack-string detection and source-to-sink path finding. The logic is a
faithful move of the original ``api_security`` tool bodies; all low-level IDA
SDK access is delegated to ``SecurityAdapter``.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import islice

from ...infrastructure.sync.sync import IDAError
from ...utils import parse_address, normalize_list_input


class SecurityService:
    def __init__(self, adapter) -> None:
        self._adapter = adapter

    # ------------------------------------------------------------------
    # detect_vulns
    # ------------------------------------------------------------------
    def detect_vulns(
        self,
        addrs=None,
        vuln_types=None,
        severity=None,
        offset: int = 0,
        count: int = 100,
    ) -> dict:
        a = self._adapter
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_severity = severity_order.get(severity or "low", 3)

        # Parse vuln type filter
        type_filter = None
        if vuln_types:
            type_filter = set(normalize_list_input(vuln_types))

        # Determine which functions to scan
        if addrs:
            func_eas = []
            for x in normalize_list_input(addrs):
                try:
                    func_eas.append(parse_address(x))
                except IDAError:
                    pass
        else:
            func_eas = a.iter_functions(a.MAX_SCAN_FUNCS)

        # Phase 1: Find all dangerous sinks in the binary (imports + named functions)
        sink_locations: dict[int, tuple[str, dict]] = {}  # ea -> (canonical_name, info)

        # Check imports
        for ea, name in a.enum_imports():
            match = a.match_sink(name)
            if match:
                sink_locations[ea] = match

        # Check named functions
        for ea in a.iter_functions():
            name = a.get_name(ea)
            if not name:
                continue
            match = a.match_sink(name)
            if match:
                sink_locations[ea] = match

        # Phase 2: For each target function, find calls to dangerous sinks
        findings: list[dict] = []
        scanned = 0

        for func_ea in func_eas:
            func = a.get_func(func_ea)
            if not func:
                continue

            func_name = a.func_name_or_hex(func.start_ea)
            scanned += 1

            for head in a.iter_code_heads(func.start_ea, func.end_ea):
                for target in a.call_targets_from(head):
                    if target not in sink_locations:
                        continue

                    sink_name, info = sink_locations[target]
                    sev = info["severity"]

                    # Apply filters
                    if severity_order.get(sev, 3) > min_severity:
                        continue
                    if type_filter and info["vuln"] not in type_filter:
                        continue

                    findings.append({
                        "func": func_name,
                        "func_addr": hex(func.start_ea),
                        "call_site": hex(head),
                        "sink": sink_name,
                        "vuln": info["vuln"],
                        "severity": sev,
                        "note": info["note"],
                    })

        # Sort by severity
        findings.sort(key=lambda f: severity_order.get(f["severity"], 3))

        # Build summary
        by_type: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for f in findings:
            by_type[f["vuln"]] += 1
            by_severity[f["severity"]] += 1

        total = len(findings)
        if count == 0:
            page = findings[offset:]
        else:
            page = findings[offset:offset + count]
        has_more = offset + len(page) < total

        return {
            "scanned": scanned,
            "total_findings": total,
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "findings": page,
            "offset": offset,
            "count": len(page),
            "next_offset": offset + len(page) if has_more else None,
        }

    # ------------------------------------------------------------------
    # find_crypto
    # ------------------------------------------------------------------
    def find_crypto(
        self,
        scan_constants: bool = True,
        scan_tables: bool = True,
        offset: int = 0,
        count: int = 50,
    ) -> dict:
        a = self._adapter
        results: list[dict] = []

        # Phase 1: Scan for magic constants in function code
        if scan_constants:
            seen_constants: set[tuple[int, int]] = set()  # (func_ea, constant)

            for func_ea in a.iter_functions(a.MAX_SCAN_FUNCS):
                func = a.get_func(func_ea)
                if not func:
                    continue

                for head in a.iter_code_heads(func.start_ea, func.end_ea):
                    insn = a.decode_insn(head)
                    if insn is None:
                        continue

                    for val in a.iter_imm_operands(insn):
                        if val in a.CRYPTO_MAGIC_CONSTANTS:
                            key = (func_ea, val)
                            if key not in seen_constants:
                                seen_constants.add(key)
                                func_name = a.func_name_or_hex(func_ea)
                                results.append({
                                    "type": "magic_constant",
                                    "addr": hex(head),
                                    "func": func_name,
                                    "func_addr": hex(func_ea),
                                    "value": hex(val),
                                    "algo": a.CRYPTO_MAGIC_CONSTANTS[val],
                                })

        # Phase 2: Scan binary segments for known S-box / table signatures
        if scan_tables:
            bad = a.bad_addr()
            for seg_start, seg_end in a.iter_segments():
                for sig in a.CRYPTO_SIGNATURES:
                    pattern = sig["bytes"]
                    pattern_len = len(pattern)
                    ea = seg_start

                    while ea < seg_end - pattern_len:
                        found = a.search_pattern(ea, seg_end, pattern)
                        if found == bad or found >= seg_end:
                            break

                        # Verify full match
                        candidate = a.get_bytes(found, pattern_len)
                        if candidate == pattern:
                            # Find containing function if any
                            func = a.get_func(found)
                            func_name = None
                            if func:
                                func_name = a.func_name_or_hex(func.start_ea)

                            results.append({
                                "type": sig["type"],
                                "addr": hex(found),
                                "func": func_name,
                                "algo": sig["algo"],
                                "name": sig["name"],
                                "size": pattern_len,
                            })

                        ea = found + pattern_len

        # Deduplicate and group by algorithm
        by_algo: dict[str, list[dict]] = defaultdict(list)
        for r in results:
            by_algo[r["algo"]].append(r)

        cap = count if count > 0 else None
        return {
            "total_findings": len(results),
            "algorithms_found": list(by_algo.keys()),
            "by_algorithm": {
                algo: hits[offset:offset + cap] if cap else hits[offset:]
                for algo, hits in by_algo.items()
            },
        }

    # ------------------------------------------------------------------
    # find_dangerous_callers
    # ------------------------------------------------------------------
    def find_dangerous_callers(
        self,
        sink: str,
        max_depth: int = 3,
        offset: int = 0,
        count: int = 200,
    ) -> dict:
        a = self._adapter
        max_depth = min(max_depth, 10)

        # Resolve sink address
        sink_ea = None
        try:
            sink_ea = parse_address(sink)
        except IDAError:
            pass

        if sink_ea is None:
            # Search by name
            for ea in a.iter_functions():
                name = a.get_name(ea)
                if a.strip_ida_name(name).lower() == sink.lower():
                    sink_ea = ea
                    break
            # Also check imports
            if sink_ea is None:
                for ea, name in a.enum_imports():
                    if a.strip_ida_name(name).lower() == sink.lower():
                        sink_ea = ea
                        break

        if sink_ea is None:
            raise IDAError(f"Could not find sink function: {sink!r}")

        sink_name = a.func_name_or_hex(sink_ea)

        # BFS upward through callers
        visited: set[int] = set()
        edges: list[dict] = []
        queue: list[tuple[int, int]] = [(sink_ea, 0)]  # (ea, depth)

        while queue:
            current_ea, depth = queue.pop(0)
            if current_ea in visited or depth > max_depth:
                continue
            visited.add(current_ea)

            for caller_ea, call_site in a.callers_to(current_ea, a.MAX_XREFS_PER_SINK):
                caller_name = a.func_name_or_hex(caller_ea)
                target_name = a.func_name_or_hex(current_ea)

                edges.append({
                    "caller": caller_name,
                    "caller_addr": hex(caller_ea),
                    "call_site": hex(call_site),
                    "target": target_name,
                    "target_addr": hex(current_ea),
                    "depth": depth,
                })

                if caller_ea not in visited and depth + 1 <= max_depth:
                    queue.append((caller_ea, depth + 1))

        # Build call chain summary
        root_callers = [e for e in edges if e["depth"] == max_depth or
                        e["caller_addr"] not in {e2["target_addr"] for e2 in edges}]

        total_edges = len(edges)
        if count == 0:
            page = edges[offset:]
        else:
            page = edges[offset:offset + count]
        has_more = offset + len(page) < total_edges

        return {
            "sink": sink_name,
            "sink_addr": hex(sink_ea),
            "total_callers": len(visited) - 1,
            "total_edges": total_edges,
            "max_depth": max_depth,
            "edges": page,
            "offset": offset,
            "count": len(page),
            "next_offset": offset + len(page) if has_more else None,
            "root_entry_points": [e["caller"] for e in root_callers],
        }

    # ------------------------------------------------------------------
    # detect_stack_strings
    # ------------------------------------------------------------------
    def detect_stack_strings(
        self,
        addrs=None,
        min_length: int = 4,
        offset: int = 0,
        count: int = 200,
    ) -> dict:
        a = self._adapter
        if addrs:
            func_eas = []
            for x in normalize_list_input(addrs):
                try:
                    func_eas.append(parse_address(x))
                except IDAError:
                    pass
        else:
            func_eas = a.iter_functions(a.MAX_SCAN_FUNCS)

        results: list[dict] = []

        for func_ea in func_eas:
            func = a.get_func(func_ea)
            if not func:
                continue

            func_name = a.func_name_or_hex(func.start_ea)

            # Track mov [rbp-X], imm8 patterns (stack byte stores)
            stack_stores: dict[int, list[tuple[int, int]]] = defaultdict(list)  # offset -> [(ea, byte_val)]

            for head in a.iter_code_heads(func.start_ea, func.end_ea):
                insn = a.decode_insn(head)
                if insn is None:
                    continue

                # Look for: mov [stack_var], immediate_byte
                if not a.is_mov_like(insn):
                    continue

                store = a.stack_store_imm(insn)
                if store is None:
                    continue

                store_off, val = store
                stack_stores[store_off].append((head, val))

            # Find contiguous stack store sequences that form strings
            if not stack_stores:
                continue

            offsets = sorted(stack_stores.keys())
            current_string = []
            current_start = None
            current_addrs = []

            for i, off in enumerate(offsets):
                if current_string and off != offsets[i - 1] + 1:
                    # Gap - emit current string if long enough
                    if len(current_string) >= min_length:
                        results.append({
                            "func": func_name,
                            "func_addr": hex(func_ea),
                            "string": "".join(current_string),
                            "length": len(current_string),
                            "first_insn": hex(current_addrs[0]),
                        })
                    current_string = []
                    current_addrs = []

                # Take the last store to this offset
                ea, val = stack_stores[off][-1]
                current_string.append(chr(val))
                current_addrs.append(ea)

            # Flush remaining
            if len(current_string) >= min_length:
                results.append({
                    "func": func_name,
                    "func_addr": hex(func_ea),
                    "string": "".join(current_string),
                    "length": len(current_string),
                    "first_insn": hex(current_addrs[0]),
                })

        total = len(results)
        if count == 0:
            page = results[offset:]
        else:
            page = results[offset:offset + count]
        has_more = offset + len(page) < total

        return {
            "total": total,
            "results": page,
            "offset": offset,
            "count": len(page),
            "next_offset": offset + len(page) if has_more else None,
        }

    # ------------------------------------------------------------------
    # trace_source_to_sink
    # ------------------------------------------------------------------
    def trace_source_to_sink(
        self,
        sources,
        sinks,
        max_depth: int = 5,
        offset: int = 0,
        count: int = 100,
    ) -> dict:
        a = self._adapter
        max_depth = min(max_depth, 10)

        source_names = normalize_list_input(sources)
        sink_names = normalize_list_input(sinks)

        def resolve_func_ea(name: str):
            """Resolve function name to EA, checking both functions and imports."""
            try:
                return parse_address(name)
            except IDAError:
                pass
            for ea in a.iter_functions():
                fn = a.get_name(ea)
                if a.strip_ida_name(fn).lower() == name.lower():
                    return ea
            # Check imports
            for ea, n in a.enum_imports():
                if a.strip_ida_name(n).lower() == name.lower():
                    return ea
            return None

        # Resolve source and sink EAs
        source_eas: dict[int, str] = {}
        for name in source_names:
            ea = resolve_func_ea(name)
            if ea is not None:
                source_eas[ea] = a.get_name(ea) or name

        sink_eas: dict[int, str] = {}
        for name in sink_names:
            ea = resolve_func_ea(name)
            if ea is not None:
                sink_eas[ea] = a.get_name(ea) or name

        if not source_eas:
            raise IDAError(f"No source functions found: {source_names}")
        if not sink_eas:
            raise IDAError(f"No sink functions found: {sink_names}")

        # BFS forward from sources: find all functions reachable from callers of sources
        forward_reachable: dict[int, int] = {}  # func_ea -> depth from source

        queue: list[tuple[int, int]] = []
        for src_ea in source_eas:
            for caller_ea in a.call_callers_to(src_ea, a.MAX_XREFS_PER_SINK):
                queue.append((caller_ea, 0))

        while queue:
            ea, depth = queue.pop(0)
            if ea in forward_reachable or depth > max_depth:
                continue
            forward_reachable[ea] = depth

            # Follow callees
            func = a.get_func(ea)
            if not func:
                continue
            for callee_ea in a.call_callees_from_func(func):
                if callee_ea not in forward_reachable:
                    queue.append((callee_ea, depth + 1))

        # BFS backward from sinks: find all functions that call sinks
        backward_reachable: dict[int, int] = {}  # func_ea -> depth from sink

        queue = []
        for sink_ea in sink_eas:
            for caller_ea in a.call_callers_to(sink_ea, a.MAX_XREFS_PER_SINK):
                queue.append((caller_ea, 0))

        while queue:
            ea, depth = queue.pop(0)
            if ea in backward_reachable or depth > max_depth:
                continue
            backward_reachable[ea] = depth

            for caller_ea in a.call_callers_to(ea, a.MAX_XREFS_PER_SINK):
                if caller_ea not in backward_reachable:
                    queue.append((caller_ea, depth + 1))

        # Intersection: functions reachable from both sources and sinks
        intersection = set(forward_reachable.keys()) & set(backward_reachable.keys())

        paths: list[dict] = []
        for ea in intersection:
            name = a.func_name_or_hex(ea)
            paths.append({
                "func": name,
                "func_addr": hex(ea),
                "depth_from_source": forward_reachable[ea],
                "depth_from_sink": backward_reachable[ea],
                "total_distance": forward_reachable[ea] + backward_reachable[ea],
            })

        paths.sort(key=lambda p: p["total_distance"])

        total = len(paths)
        if count == 0:
            page = paths[offset:]
        else:
            page = paths[offset:offset + count]
        has_more = offset + len(page) < total

        return {
            "sources": {hex(ea): name for ea, name in source_eas.items()},
            "sinks": {hex(ea): name for ea, name in sink_eas.items()},
            "forward_reachable_count": len(forward_reachable),
            "backward_reachable_count": len(backward_reachable),
            "intersection_count": total,
            "paths": page,
            "offset": offset,
            "count": len(page),
            "next_offset": offset + len(page) if has_more else None,
        }

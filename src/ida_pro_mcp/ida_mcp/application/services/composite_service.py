"""Application service for composite analysis tools that aggregate
multiple data sources."""

from __future__ import annotations

from collections import defaultdict, deque

from ...infrastructure.adapters.composite_adapter import CompositeAdapter
from ...infrastructure.sync.sync import IDAError
from ...utils import (
    get_prototype,
    get_callees,
    get_callers,
    get_all_xrefs,
    get_all_comments,
    extract_function_strings,
    extract_function_constants,
    decompile_function_safe,
    get_assembly_lines,
    normalize_list_input,
)

# Max decompile lines before truncation.
_DECOMPILE_LINE_CAP = 100
# Max strings/constants returned in compact mode.
_TOP_STRINGS = 10
_TOP_CONSTANTS = 10
# Constants filtered out of extract_function_constants results.
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF})

_VALID_ACTIONS = frozenset({"rename_func", "set_type", "set_comment"})

_MAX_TRACE_NODES = 200
_MAX_TRACE_EDGES = 500


class CompositeService:
    """High-level orchestration for composite analysis tools."""

    def __init__(self, adapter: CompositeAdapter):
        self.adapter = adapter

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filter_constants(self, raw: list[dict], limit: int = _TOP_CONSTANTS) -> list[dict]:
        """Drop boring constants, return top N by absolute value."""
        out = []
        for c in raw:
            val = c.get("value", 0)
            if not isinstance(val, int):
                continue
            if abs(val) < 0x100 or val in _BORING_CONSTANTS:
                continue
            out.append(c)
        out.sort(key=lambda c: abs(c.get("value", 0)) if isinstance(c.get("value"), int) else 0, reverse=True)
        return out[:limit]

    def _cap_decompile(self, code: str | None) -> tuple[str | None, int | None]:
        """Cap decompiled output at _DECOMPILE_LINE_CAP lines.
        Returns (possibly_truncated_code, total_lines_or_None)."""
        if code is None:
            return None, None
        lines = code.split("\n")
        total = len(lines)
        if total <= _DECOMPILE_LINE_CAP:
            return code, None  # not truncated
        truncated = "\n".join(lines[:_DECOMPILE_LINE_CAP])
        return truncated, total

    def _compact_strings(self, raw: list[dict], limit: int = _TOP_STRINGS) -> list[str]:
        """Return just the string values, deduplicated, capped at limit."""
        seen: set[str] = set()
        out: list[str] = []
        for s in raw:
            val = s.get("value") or s.get("string", "")
            if val and val not in seen:
                seen.add(val)
                out.append(val)
                if len(out) >= limit:
                    break
        return out

    def _compact_callees(self, raw: list[dict]) -> list[str]:
        """Return just callee names/addresses as strings."""
        return [c.get("name") or c.get("addr", "?") for c in raw]

    def _analyze_function_internal(self, ea: int, *, include_asm: bool = False) -> dict:
        """Core analysis logic — must be called from an @idasync context.

        Returns a compact response by default: decompilation capped at 100 lines,
        top 10 strings as values only, top 10 non-trivial constants, no disassembly.
        Pass include_asm=True to include full disassembly."""
        result: dict = {"addr": hex(ea), "error": None}

        try:
            func = self.adapter.get_func(ea)
            if func is None:
                result["error"] = f"No function at {hex(ea)}"
                return result

            result["name"] = self.adapter.get_func_name(ea)
            result["prototype"] = get_prototype(func)
            result["size"] = func.end_ea - func.start_ea

            # Decompilation — capped at _DECOMPILE_LINE_CAP lines.
            try:
                raw_code = decompile_function_safe(ea)
                code, total_lines = self._cap_decompile(raw_code)
                result["decompiled"] = code
                if total_lines is not None:
                    result["decompile_truncated"] = total_lines
            except Exception:
                result["decompiled"] = None

            # Assembly — opt-in only.
            if include_asm:
                try:
                    result["assembly"] = get_assembly_lines(ea)
                except Exception:
                    result["assembly"] = None

            # Strings — top 10 values only.
            result["strings"] = self._compact_strings(extract_function_strings(ea))
            # Constants — top 10 non-trivial.
            result["constants"] = self._filter_constants(extract_function_constants(ea))
            # Callees/callers — names only.
            result["callees"] = self._compact_callees(get_callees(hex(ea)))
            result["callers"] = self._compact_callees(get_callers(hex(ea)))
            result["xrefs"] = get_all_xrefs(ea)
            result["comments"] = get_all_comments(ea)
            result["basic_blocks"] = self.adapter.basic_block_info(ea)

        except Exception as exc:
            result["error"] = str(exc)

        return result

    # ------------------------------------------------------------------
    # Tool 1 — analyze_function
    # ------------------------------------------------------------------

    def analyze_function(self, addr: str, include_asm: bool = False) -> dict:
        try:
            ea = self.adapter.resolve_addr(addr)
        except IDAError as exc:
            return {"addr": addr, "error": str(exc)}

        return self._analyze_function_internal(ea, include_asm=include_asm)

    # ------------------------------------------------------------------
    # Tool 2 — analyze_component
    # ------------------------------------------------------------------

    def analyze_component(self, addrs) -> dict:
        raw = normalize_list_input(addrs)
        if not raw:
            return {"error": "Empty address list"}

        ea_map: dict[int, str] = {}
        for a in raw:
            try:
                ea_map[self.adapter.resolve_addr(a)] = a
            except IDAError:
                return {"error": f"Cannot resolve address: {a!r}"}

        ea_set = set(ea_map.keys())

        # --- Per-function COMPACT summary (no decompile, no disasm) ---
        functions: list[dict] = []
        for ea in ea_set:
            func = self.adapter.get_func(ea)
            if func is None:
                functions.append({"addr": hex(ea), "error": "No function"})
                continue
            name = self.adapter.get_func_name(ea)
            strings_raw = extract_function_strings(ea)
            top_strings = self._compact_strings(strings_raw, limit=5)
            callee_list = self._compact_callees(get_callees(hex(ea)))
            bb = self.adapter.basic_block_info(ea)
            functions.append({
                "addr": hex(ea),
                "name": name,
                "prototype": get_prototype(func),
                "size": func.end_ea - func.start_ea,
                "callees": callee_list,
                "strings": top_strings,
                "basic_blocks": bb["count"],
                "complexity": bb["cyclomatic_complexity"],
            })

        # --- Internal call graph ---
        nodes = [hex(ea) for ea in ea_set]
        edges: list[dict] = []
        for ea in ea_set:
            for callee in (get_callees(hex(ea)) or []):
                callee_ea = callee.get("addr")
                if isinstance(callee_ea, str):
                    try:
                        callee_ea = int(callee_ea, 16)
                    except (ValueError, TypeError):
                        continue
                if callee_ea in ea_set:
                    edges.append({
                        "from": hex(ea),
                        "to": hex(callee_ea),
                        "name": callee.get("name", ""),
                    })

        # --- Shared globals ---
        func_globals: dict[int, set[int]] = {}
        for ea in ea_set:
            func_globals[ea] = self.adapter.collect_function_globals(ea)

        global_refcount: dict[int, list[str]] = defaultdict(list)
        for ea, gset in func_globals.items():
            fname = self.adapter.get_func_name(ea) or hex(ea)
            for g in gset:
                global_refcount[g].append(fname)

        shared_globals = []
        for g_ea, accessors in sorted(global_refcount.items()):
            if len(accessors) >= 2:
                shared_globals.append({
                    "addr": hex(g_ea),
                    "name": self.adapter.get_name(g_ea) or hex(g_ea),
                    "accessed_by": sorted(accessors),
                })

        # --- Interface vs internal ---
        interface_functions: list[str] = []
        internal_only: list[str] = []
        for ea in ea_set:
            callers = get_callers(hex(ea))
            has_external = False
            for c in (callers or []):
                caller_addr = c.get("addr") or c.get("start_ea")
                if isinstance(caller_addr, str):
                    try:
                        caller_addr = int(caller_addr, 16)
                    except (ValueError, TypeError):
                        has_external = True
                        break
                if caller_addr not in ea_set:
                    has_external = True
                    break
            if has_external:
                interface_functions.append(hex(ea))
            else:
                internal_only.append(hex(ea))

        # --- String usage across functions ---
        string_funcs: dict[str, set[str]] = defaultdict(set)
        for ea in ea_set:
            fname = self.adapter.get_func_name(ea) or hex(ea)
            for s in (extract_function_strings(ea) or []):
                sval = s.get("value") or s.get("string", "")
                if sval:
                    string_funcs[sval].add(fname)

        string_usage = {
            s: sorted(fnames)
            for s, fnames in sorted(string_funcs.items())
            if len(fnames) >= 2
        }

        return {
            "functions": functions,
            "internal_call_graph": {"nodes": nodes, "edges": edges},
            "shared_globals": shared_globals,
            "interface_functions": interface_functions,
            "internal_only": internal_only,
            "string_usage": string_usage,
        }

    # ------------------------------------------------------------------
    # Tool 3 — diff_before_after
    # ------------------------------------------------------------------

    def diff_before_after(self, addr: str, action: str, action_args: dict) -> dict:
        if action not in _VALID_ACTIONS:
            return {"error": f"Invalid action {action!r}. Must be one of: {', '.join(sorted(_VALID_ACTIONS))}"}

        try:
            ea = self.adapter.resolve_addr(addr)
        except IDAError as exc:
            return {"error": str(exc)}

        func = self.adapter.get_func(ea)
        if func is None:
            return {"error": f"No function at {hex(ea)}"}

        # --- Before ---
        before = decompile_function_safe(ea)

        # --- Apply action ---
        applied: str
        try:
            if action == "rename_func":
                name = action_args.get("name")
                if not name:
                    return {"error": "action_args must contain 'name'"}
                ok = self.adapter.set_name(ea, name)
                if not ok:
                    return {"error": f"set_name failed for {name!r}"}
                applied = f"Renamed to {name!r}"

            elif action == "set_type":
                type_str = action_args.get("type")
                if not type_str:
                    return {"error": "action_args must contain 'type'"}
                ok, err = self.adapter.apply_type(ea, type_str)
                if not ok:
                    return {"error": err}
                applied = f"Set type to {type_str!r}"

            elif action == "set_comment":
                comment = action_args.get("comment")
                if comment is None:
                    return {"error": "action_args must contain 'comment'"}
                self.adapter.set_comment(ea, comment)
                applied = f"Set comment: {comment!r}"

            else:
                return {"error": f"Unhandled action {action!r}"}
        except Exception as exc:
            return {"error": f"Action {action!r} failed: {exc}"}

        # --- After ---
        after = decompile_function_safe(ea)

        return {
            "before": before,
            "after": after,
            "action_applied": applied,
            "changes_detected": before != after,
        }

    # ------------------------------------------------------------------
    # Tool 4 — trace_data_flow
    # ------------------------------------------------------------------

    def trace_data_flow(
        self, addr: str, direction: str = "forward", max_depth: int = 5
    ) -> dict:
        if direction not in ("forward", "backward"):
            return {"error": f"direction must be 'forward' or 'backward', got {direction!r}"}

        try:
            start_ea = self.adapter.resolve_addr(addr)
        except IDAError as exc:
            return {"error": str(exc)}

        if max_depth < 1:
            max_depth = 1
        if max_depth > 20:
            max_depth = 20

        visited: set[int] = set()
        nodes: list[dict] = []
        edges: list[dict] = []
        depth_reached = 0

        # BFS queue: (ea, depth)
        queue: deque[tuple[int, int]] = deque()
        queue.append((start_ea, 0))
        visited.add(start_ea)

        while queue and len(nodes) < _MAX_TRACE_NODES:
            ea, depth = queue.popleft()
            if depth > max_depth:
                continue
            if depth > depth_reached:
                depth_reached = depth

            # Build node info.
            func = self.adapter.get_func(ea)
            func_name = self.adapter.get_func_name(ea) if func else None
            insn_text = self.adapter.get_disasm(ea) if self.adapter.is_loaded(ea) else None

            # Determine if this address references a global/string.
            name_at = self.adapter.get_name(ea)
            node_type = "code"
            if func is None and self.adapter.is_loaded(ea):
                node_type = "data"

            nodes.append({
                "addr": hex(ea),
                "func": func_name,
                "instruction": insn_text,
                "type": node_type,
                "name": name_at if name_at else None,
                "depth": depth,
            })

            if depth >= max_depth:
                continue

            # Follow xrefs in the requested direction.
            if direction == "forward":
                xrefs = self.adapter.xrefs_from(ea)
            else:
                xrefs = self.adapter.xrefs_to(ea)

            for xref in xrefs:
                if len(edges) >= _MAX_TRACE_EDGES:
                    break
                target = xref.to if direction == "forward" else xref.frm
                # Classify xref type.
                xtype = "code" if xref.iscode else "data"

                edges.append({
                    "from": hex(ea) if direction == "forward" else hex(target),
                    "to": hex(target) if direction == "forward" else hex(ea),
                    "type": xtype,
                })

                if target not in visited and len(nodes) + len(queue) < _MAX_TRACE_NODES:
                    visited.add(target)
                    queue.append((target, depth + 1))

        return {
            "start": hex(start_ea),
            "direction": direction,
            "depth_reached": depth_reached,
            "nodes": nodes,
            "edges": edges,
        }

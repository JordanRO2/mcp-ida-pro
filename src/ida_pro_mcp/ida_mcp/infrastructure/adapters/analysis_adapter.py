"""Adapter for code-analysis SDK access (idaapi / idautils / Hex-Rays / etc.).

Extracts the lowest-level IDA SDK calls used by the analysis tools: instruction
decoding, operand access, raw byte search, flowchart/disassembly iteration,
caller/callee collection and the per-function profiling primitives. Nothing here
imports ``idaapi`` at module load; the SDK modules are imported lazily inside
methods so the file imports cleanly outside IDA.
"""

from __future__ import annotations

import struct

from ..compat import (
    raw_bin_search,
    make_bytes_searcher,
    inf_get_min_ea,
    inf_get_max_ea,
)
from ...utils import (
    parse_address,
    get_prototype,
    extract_function_strings,
    extract_function_constants,
)
from ...domain.entities import BasicBlock

_IMM_SCAN_BACK_MAX = 15


class AnalysisAdapter:
    """Lowest-level IDA SDK access for code-analysis tools."""

    # --- segment / range info ---

    def inf_get_min_ea(self) -> int:
        return inf_get_min_ea()

    def inf_get_max_ea(self) -> int:
        return inf_get_max_ea()

    def raw_bin_search(
        self, ea: int, max_ea: int, data: bytes, mask: bytes, flags: int = 0
    ) -> int:
        """Search for raw bytes with mask, compatible across IDA versions.

        Returns the match address, or idaapi.BADADDR if not found.
        """
        import ida_bytes

        search_flags = flags or (
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        )
        return raw_bin_search(ea, max_ea, data, mask, search_flags)

    def make_bytes_searcher(self, pattern: str):
        return make_bytes_searcher(pattern)

    # --- instruction primitives ---

    def decode_insn_at(self, ea: int):
        import ida_ua

        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            return None
        return insn

    def next_head(self, ea: int, end_ea: int) -> int:
        import ida_bytes

        return ida_bytes.next_head(ea, end_ea)

    def operand_value(self, insn, i: int):
        import ida_ua

        op = insn.ops[i]
        if op.type == ida_ua.o_void:
            return None
        if op.type in (ida_ua.o_mem, ida_ua.o_far, ida_ua.o_near):
            return op.addr
        return op.value

    def operand_type(self, insn, i: int) -> int:
        return insn.ops[i].type

    def insn_mnem(self, insn) -> str:
        try:
            return insn.get_canon_mnem().lower()
        except Exception:
            return ""

    def resolve_immediate_insn_start(
        self,
        match_ea: int,
        value: int,
        seg_start: int,
        alt_value: int | None = None,
    ) -> int | None:
        import ida_ua

        start_min = max(seg_start, match_ea - _IMM_SCAN_BACK_MAX)
        for start in range(match_ea, start_min - 1, -1):
            insn = self.decode_insn_at(start)
            if insn is None:
                continue
            end_ea = start + insn.size
            if not (start <= match_ea < end_ea):
                continue
            for i in range(8):
                op_type = self.operand_type(insn, i)
                if op_type == ida_ua.o_void:
                    break
                if op_type != ida_ua.o_imm:
                    continue
                op_val = self.operand_value(insn, i)
                if op_val is None:
                    continue
                if op_val == value or (alt_value is not None and op_val == alt_value):
                    offb = getattr(insn.ops[i], "offb", 0)
                    if offb and start + offb != match_ea:
                        continue
                    return start
        return None

    # --- function / address resolution ---

    def get_func(self, ea: int):
        import idaapi

        return idaapi.get_func(ea)

    def get_func_name(self, ea: int) -> str:
        import ida_funcs

        return ida_funcs.get_func_name(ea) or "<unnamed>"

    def get_name_ea(self, name: str) -> int:
        import idaapi

        return idaapi.get_name_ea(idaapi.BADADDR, name)

    def name_addr(self, ea: int):
        import ida_name

        return ida_name.get_name(ea)

    def resolve_function_start(self, query: object) -> tuple[int | None, str | None]:
        import idaapi

        q = str(query or "").strip()
        if not q:
            return None, "Function query is required"

        ea = idaapi.BADADDR
        try:
            ea = parse_address(q)
        except Exception:
            ea = idaapi.get_name_ea(idaapi.BADADDR, q)

        if ea == idaapi.BADADDR:
            return None, f"Failed to resolve function: {q}"

        func = idaapi.get_func(ea)
        if not func:
            return None, f"Not a function: {q}"
        return func.start_ea, None

    def list_function_starts(self) -> list[int]:
        import idautils

        return list(idautils.Functions())

    def func_extent(self, fn) -> int:
        return fn.end_ea - fn.start_ea

    def has_type(self, start_ea: int) -> bool:
        import ida_typeinf
        import ida_nalt

        return ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), start_ea)

    # --- disassembly / flowchart / metrics ---

    def disasm_line(self, ea: int) -> str:
        import ida_lines

        line = ida_lines.generate_disasm_line(ea, 0)
        return ida_lines.tag_remove(line) if line else ""

    def func_items(self, start_ea: int) -> list[int]:
        import idautils

        return list(idautils.FuncItems(start_ea))

    def count_instructions(self, start_ea: int) -> int:
        import idautils

        return sum(1 for _ in idautils.FuncItems(start_ea))

    def count_basic_blocks(self, fn) -> int:
        import idaapi

        return sum(1 for _ in idaapi.FlowChart(fn))

    def disasm_lines_limited(self, fn, max_insns: int) -> tuple[list[str], bool]:
        import ida_lines
        import idautils

        lines: list[str] = []
        truncated = False
        for item_ea in idautils.FuncItems(fn.start_ea):
            if len(lines) >= max_insns:
                truncated = True
                break
            line = ida_lines.generate_disasm_line(item_ea, 0)
            instruction = ida_lines.tag_remove(line) if line else ""
            lines.append(f"{item_ea:x}  {instruction}")
        return lines, truncated

    def collect_basic_blocks_limited(
        self, fn, max_blocks: int
    ) -> tuple[list, bool]:
        import idaapi

        blocks: list = []
        truncated = False
        for block in idaapi.FlowChart(fn):
            if len(blocks) >= max_blocks:
                truncated = True
                break
            blocks.append(
                BasicBlock(
                    start=hex(block.start_ea),
                    end=hex(block.end_ea),
                    size=block.end_ea - block.start_ea,
                    type=block.type,
                    successors=[hex(s.start_ea) for s in block.succs()],
                    predecessors=[hex(p.start_ea) for p in block.preds()],
                )
            )
        return blocks, truncated

    def collect_all_basic_blocks(self, fn) -> list:
        import idaapi

        all_blocks = []
        for block in idaapi.FlowChart(fn):
            all_blocks.append(
                BasicBlock(
                    start=hex(block.start_ea),
                    end=hex(block.end_ea),
                    size=block.end_ea - block.start_ea,
                    type=block.type,
                    successors=[hex(succ.start_ea) for succ in block.succs()],
                    predecessors=[hex(pred.start_ea) for pred in block.preds()],
                )
            )
        return all_blocks

    def collect_callees_for_function(self, fn) -> list[dict]:
        import idaapi
        import idautils
        import ida_funcs

        callees: dict[int, dict] = {}
        for item_ea in idautils.FuncItems(fn.start_ea):
            for target in idautils.CodeRefsFrom(item_ea, 0):
                callee = idaapi.get_func(target)
                if not callee:
                    continue
                callee_start = callee.start_ea
                if callee_start in callees:
                    continue
                callees[callee_start] = {
                    "addr": hex(callee_start),
                    "name": ida_funcs.get_func_name(callee_start) or "<unnamed>",
                }
        return list(callees.values())

    def collect_callers_for_function(self, fn) -> list[dict]:
        import idaapi
        import idautils
        import ida_funcs

        callers: dict[int, dict] = {}
        for caller_site in idautils.CodeRefsTo(fn.start_ea, 0):
            caller = idaapi.get_func(caller_site)
            if not caller:
                continue
            caller_start = caller.start_ea
            if caller_start in callers:
                continue

            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, caller_site)
            if insn.itype not in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]:
                continue

            callers[caller_start] = {
                "addr": hex(caller_start),
                "name": ida_funcs.get_func_name(caller_start) or "<unnamed>",
            }
        return list(callers.values())

    def func_summary(self, fn) -> dict:
        """Compact candidate record for a function used by func_profile."""
        import ida_funcs

        return {
            "start_ea": fn.start_ea,
            "addr": hex(fn.start_ea),
            "name": ida_funcs.get_func_name(fn.start_ea) or "<unnamed>",
            "size_int": fn.end_ea - fn.start_ea,
            "size": hex(fn.end_ea - fn.start_ea),
        }

    # --- segment access ---

    def getseg(self, ea: int):
        import idaapi

        return idaapi.getseg(ea)

    def get_segm_name(self, seg) -> str:
        import idaapi

        return idaapi.get_segm_name(seg)

    def exec_segments(self) -> list:
        import idaapi
        import idautils

        out = []
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg and (seg.perm & idaapi.SEGPERM_EXEC):
                out.append(seg)
        return out

    def segments(self) -> list[int]:
        import idautils

        return list(idautils.Segments())

    def is_exec_seg(self, seg) -> bool:
        import idaapi

        return bool(seg and (seg.perm & idaapi.SEGPERM_EXEC))

    # --- xref primitives ---

    def is_mapped(self, ea: int) -> bool:
        import ida_bytes

        return ida_bytes.is_mapped(ea)

    def xrefs_to(self, ea: int) -> list:
        import idautils

        return list(idautils.XrefsTo(ea))

    def xrefs_to_flagged(self, ea: int, flags: int = 0) -> list:
        import idautils

        return list(idautils.XrefsTo(ea, flags))

    def xrefs_from_flagged(self, ea: int, flags: int = 0) -> list:
        import idautils

        return list(idautils.XrefsFrom(ea, flags))

    def data_refs_to(self, ea: int):
        import idautils

        return idautils.DataRefsTo(ea)

    def code_refs_to(self, ea: int, flags: int = 0):
        import idautils

        return idautils.CodeRefsTo(ea, flags)

    def code_refs_from(self, ea: int, flags: int = 0):
        import idautils

        return idautils.CodeRefsFrom(ea, flags)

    # --- decode_insn helpers used by callees() ---

    def is_call_insn(self, insn) -> bool:
        import idaapi

        return insn.itype in [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]

    def call_target(self, insn):
        import ida_ua

        op0 = insn.ops[0]
        if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
            return op0.addr
        elif op0.type == ida_ua.o_imm:
            return op0.value
        return None

    # --- type / struct primitives (xrefs_to_field) ---

    def get_idati(self):
        import ida_typeinf

        return ida_typeinf.get_idati()

    def get_struct_field_tid(
        self, til, struct_name: str, field_name: str
    ) -> tuple[int | None, str | None]:
        """Resolve a struct.field to its tid.

        Returns (tid, error). On success error is None. On failure tid is None
        and error explains why; tid may also be a sentinel string-coded error.
        """
        import idaapi
        import ida_typeinf

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False):
            return None, f"Struct '{struct_name}' not found"

        idx = ida_typeinf.get_udm_by_fullname(None, struct_name + "." + field_name)
        if idx == -1:
            return None, f"Field '{field_name}' not found in '{struct_name}'"

        tid = tif.get_udm_tid(idx)
        if tid == idaapi.BADADDR:
            return None, "Unable to get tid"
        return tid, None

    # --- decompile / typeinfo for disasm() ---

    def get_func_signature(self, fn):
        """Return (rettype, args) for a function via tinfo, or (None, None)."""
        import ida_typeinf
        import ida_nalt
        from ...domain.entities import Argument

        tif = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tif, fn.start_ea) and tif.is_func():
            ftd = ida_typeinf.func_type_data_t()
            if tif.get_func_details(ftd):
                rettype = str(ftd.rettype)
                args = [
                    Argument(name=(a.name or f"arg{i}"), type=str(a.type))
                    for i, a in enumerate(ftd)
                ]
                return rettype, args
        return None, None

    # --- value encoding helpers (immediate search) ---

    @staticmethod
    def value_to_le_bytes(value: int) -> tuple[bytes, int, int] | None:
        if value < 0:
            if value >= -0x80000000:
                size = 4
                value &= 0xFFFFFFFF
            elif value >= -0x8000000000000000:
                size = 8
                value &= 0xFFFFFFFFFFFFFFFF
            else:
                return None
        else:
            if value <= 0xFFFFFFFF:
                size = 4
            elif value <= 0xFFFFFFFFFFFFFFFF:
                size = 8
            else:
                return None

        fmt = "<I" if size == 4 else "<Q"
        return struct.pack(fmt, value), size, value

    @staticmethod
    def value_candidates_for_immediate(value: int) -> list[tuple[int, int, bytes]]:
        candidates: list[tuple[int, int, bytes]] = []

        def add(size: int, signed_val: int):
            if size == 4:
                masked = signed_val & 0xFFFFFFFF
                if not (-0x80000000 <= signed_val <= 0x7FFFFFFF):
                    return
                b = struct.pack("<I", masked)
            else:
                masked = signed_val & 0xFFFFFFFFFFFFFFFF
                if not (-0x8000000000000000 <= signed_val <= 0x7FFFFFFFFFFFFFFF):
                    return
                b = struct.pack("<Q", masked)
            candidates.append((masked, size, b))

        add(4, value)
        add(8, value)
        return candidates

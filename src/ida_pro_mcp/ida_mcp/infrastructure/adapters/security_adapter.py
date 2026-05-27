"""Infrastructure adapter for security analysis.

Wraps the low-level ``idaapi``/``idautils`` calls used by the security service:
name normalization, sink matching, import enumeration, caller/xref traversal,
crypto constant/table scanning. Keeping these here isolates IDA SDK access from
the orchestration logic in ``application.services.security_service``.

This module imports ``idaapi`` at load time (like the original ``api_security``
module did), so it is only importable inside IDA. The DI container constructs it
lazily via a factory so ``container.py`` / py_compile stay IDA-free.
"""

from __future__ import annotations

from itertools import islice
from typing import Callable

import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_nalt
import ida_ua
import idc

from .. import compat


# ============================================================================
# Dangerous Function Patterns
# ============================================================================

# Maps dangerous sink functions to vulnerability class and severity
_DANGEROUS_SINKS: dict[str, dict] = {
    # Buffer overflow - critical
    "strcpy":    {"vuln": "buffer_overflow", "severity": "critical", "note": "No bounds check, use strncpy/strlcpy"},
    "strcat":    {"vuln": "buffer_overflow", "severity": "critical", "note": "No bounds check, use strncat/strlcat"},
    "gets":      {"vuln": "buffer_overflow", "severity": "critical", "note": "Always unsafe, use fgets"},
    "scanf":     {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s, use width specifier"},
    "sscanf":    {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s, use width specifier"},
    "vscanf":    {"vuln": "buffer_overflow", "severity": "high",     "note": "Unbounded %s format"},
    "wcscpy":    {"vuln": "buffer_overflow", "severity": "critical", "note": "Wide-char strcpy, no bounds check"},
    "wcscat":    {"vuln": "buffer_overflow", "severity": "critical", "note": "Wide-char strcat, no bounds check"},
    "lstrcpyA":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 strcpy, no bounds check"},
    "lstrcpyW":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 wide strcpy, no bounds check"},
    "lstrcatA":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 strcat, no bounds check"},
    "lstrcatW":  {"vuln": "buffer_overflow", "severity": "critical", "note": "Win32 wide strcat, no bounds check"},
    # Unsafe memory ops
    "memcpy":    {"vuln": "buffer_overflow", "severity": "medium",   "note": "Check size param for user control"},
    "memmove":   {"vuln": "buffer_overflow", "severity": "medium",   "note": "Check size param for user control"},
    "RtlCopyMemory": {"vuln": "buffer_overflow", "severity": "medium", "note": "Check size param"},
    # Format string
    "printf":    {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "fprintf":   {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "sprintf":   {"vuln": "format_string", "severity": "critical", "note": "Format string + no bounds check"},
    "snprintf":  {"vuln": "format_string", "severity": "medium", "note": "Bounded but check format param"},
    "vprintf":   {"vuln": "format_string", "severity": "high",   "note": "va_list format string"},
    "vsprintf":  {"vuln": "format_string", "severity": "critical", "note": "va_list + no bounds"},
    "vsnprintf": {"vuln": "format_string", "severity": "medium", "note": "Bounded va_list format"},
    "syslog":    {"vuln": "format_string", "severity": "high",   "note": "Check if format is user-controlled"},
    "wprintf":   {"vuln": "format_string", "severity": "high",   "note": "Wide-char format string"},
    "swprintf":  {"vuln": "format_string", "severity": "high",   "note": "Wide-char sprintf"},
    "OutputDebugStringA": {"vuln": "format_string", "severity": "low", "note": "Debug info leak"},
    # Command injection
    "system":    {"vuln": "command_injection", "severity": "critical", "note": "Shell command execution"},
    "popen":     {"vuln": "command_injection", "severity": "critical", "note": "Shell command via pipe"},
    "_popen":    {"vuln": "command_injection", "severity": "critical", "note": "Shell command via pipe"},
    "execl":     {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execle":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execlp":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execv":     {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execve":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "execvp":    {"vuln": "command_injection", "severity": "critical", "note": "Process execution"},
    "WinExec":   {"vuln": "command_injection", "severity": "critical", "note": "Win32 command execution"},
    "ShellExecuteA": {"vuln": "command_injection", "severity": "critical", "note": "Win32 shell execute"},
    "ShellExecuteW": {"vuln": "command_injection", "severity": "critical", "note": "Win32 shell execute"},
    "CreateProcessA": {"vuln": "command_injection", "severity": "high", "note": "Process creation"},
    "CreateProcessW": {"vuln": "command_injection", "severity": "high", "note": "Process creation"},
    # Use-after-free related
    "free":      {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after this call"},
    "realloc":   {"vuln": "use_after_free", "severity": "medium", "note": "Old pointer invalid after realloc"},
    "HeapFree":  {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    "LocalFree": {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    "GlobalFree": {"vuln": "use_after_free", "severity": "medium", "note": "Check for use after free"},
    # Integer overflow
    "atoi":      {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check, use strtol"},
    "atol":      {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check, use strtol"},
    "atoll":     {"vuln": "integer_overflow", "severity": "medium", "note": "No overflow check"},
    # Race conditions (TOCTOU)
    "access":    {"vuln": "toctou", "severity": "medium", "note": "Time-of-check/time-of-use race"},
    # Network
    "recv":      {"vuln": "untrusted_input", "severity": "medium", "note": "Network input - validate before use"},
    "recvfrom":  {"vuln": "untrusted_input", "severity": "medium", "note": "Network input - validate before use"},
    "WSARecv":   {"vuln": "untrusted_input", "severity": "medium", "note": "Win32 network input"},
    "ReadFile":  {"vuln": "untrusted_input", "severity": "low",    "note": "File input - validate before use"},
    "InternetReadFile": {"vuln": "untrusted_input", "severity": "medium", "note": "Internet input"},
}

# Stripped name variants to match (IDA may add prefixes/suffixes)
_SINK_NAMES_LOWER = {k.lower(): k for k in _DANGEROUS_SINKS}


# ============================================================================
# Crypto Constants
# ============================================================================

# Well-known crypto S-box / round constant fragments (first 16 bytes as signature)
_CRYPTO_SIGNATURES: list[dict] = [
    # AES
    {"name": "AES S-Box", "bytes": bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]), "algo": "AES", "type": "sbox"},
    {"name": "AES Inv S-Box", "bytes": bytes([0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB]), "algo": "AES", "type": "sbox_inv"},
    {"name": "AES Rcon", "bytes": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]), "algo": "AES", "type": "rcon"},
    # DES
    {"name": "DES Initial Perm", "bytes": bytes([58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4]), "algo": "DES", "type": "permutation"},
    {"name": "DES S-Box 1", "bytes": bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]), "algo": "DES", "type": "sbox"},
    # MD5 round constants (T[1..4] as 32-bit LE)
    {"name": "MD5 T constants", "bytes": bytes([0x78, 0xA4, 0x6A, 0xD7, 0x56, 0xB7, 0xC7, 0xE8, 0xDB, 0x70, 0x20, 0x24, 0xEE, 0xCE, 0xBD, 0xC1]), "algo": "MD5", "type": "round_constants"},
    # SHA-256 initial hash values (first 8 bytes: H0=6a09e667)
    {"name": "SHA-256 Init H", "bytes": bytes([0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5]), "algo": "SHA-256", "type": "init_hash"},
    # SHA-256 round constants K (first 16 bytes)
    {"name": "SHA-256 K", "bytes": bytes([0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71, 0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9]), "algo": "SHA-256", "type": "round_constants"},
    # RC4 (detected by 0-255 identity permutation init pattern)
    {"name": "RC4 S-Box Init", "bytes": bytes(range(16)), "algo": "RC4", "type": "sbox_init"},
    # Blowfish P-array (first 16 bytes of P[0..3])
    {"name": "Blowfish P-array", "bytes": bytes([0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44]), "algo": "Blowfish", "type": "p_array"},
    # CRC32 table (first 16 bytes of standard polynomial)
    {"name": "CRC32 Table", "bytes": bytes([0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99]), "algo": "CRC32", "type": "lookup_table"},
    # TEA/XTEA delta constant
    {"name": "TEA Delta", "bytes": bytes([0x79, 0xB9, 0x9E, 0x9A]), "algo": "TEA/XTEA", "type": "constant"},
    # Whirlpool S-box
    {"name": "Whirlpool S-Box", "bytes": bytes([0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52]), "algo": "Whirlpool", "type": "sbox"},
]

# Magic constants often found in crypto implementations
_CRYPTO_MAGIC_CONSTANTS: dict[int, str] = {
    0x67452301: "MD5/SHA-1 init A",
    0xEFCDAB89: "MD5/SHA-1 init B",
    0x98BADCFE: "MD5/SHA-1 init C",
    0x10325476: "MD5/SHA-1 init D",
    0xC3D2E1F0: "SHA-1 init E",
    0x6A09E667: "SHA-256 init H0",
    0xBB67AE85: "SHA-256 init H1",
    0x3C6EF372: "SHA-256 init H2",
    0xA54FF53A: "SHA-256 init H3",
    0x510E527F: "SHA-256 init H4",
    0x9B05688C: "SHA-256 init H5",
    0x1F83D9AB: "SHA-256 init H6",
    0x5BE0CD19: "SHA-256 init H7",
    0x5A827999: "SHA-1 K0",
    0x6ED9EBA1: "SHA-1 K1",
    0x8F1BBCDC: "SHA-1 K2",
    0xCA62C1D6: "SHA-1 K3",
    0x9E3779B9: "TEA/XTEA delta",
    0x61C88647: "TEA/XTEA delta (neg)",
    0xB7E15163: "RC5/RC6 P constant",
    0x9E3779B1: "RC5/RC6 Q constant",
    0x428A2F98: "SHA-256 K[0]",
    0x71374491: "SHA-256 K[1]",
    0xB5C0FBCF: "SHA-256 K[2]",
    0xE9B5DBA5: "SHA-256 K[3]",
}


# ============================================================================
# Limits
# ============================================================================

_MAX_SCAN_FUNCS = 5000
_MAX_XREFS_PER_SINK = 200


class SecurityAdapter:
    """Low-level IDA SDK access for security analysis.

    All ``idaapi``/``idautils`` interaction used by the security service is
    funneled through this adapter so the orchestration layer never touches the
    SDK directly. Behavior is a faithful extraction of the original
    ``api_security`` helpers.
    """

    # Expose the pattern tables / limits so the service can read them without
    # importing the SDK.
    DANGEROUS_SINKS = _DANGEROUS_SINKS
    CRYPTO_SIGNATURES = _CRYPTO_SIGNATURES
    CRYPTO_MAGIC_CONSTANTS = _CRYPTO_MAGIC_CONSTANTS
    MAX_SCAN_FUNCS = _MAX_SCAN_FUNCS
    MAX_XREFS_PER_SINK = _MAX_XREFS_PER_SINK

    # ---- name helpers ----------------------------------------------------

    @staticmethod
    def strip_ida_name(name: str) -> str:
        """Strip IDA prefixes/suffixes to get base function name."""
        # Remove common prefixes: _, __, j_, .
        stripped = name.lstrip("_").lstrip(".")
        if stripped.startswith("j_"):
            stripped = stripped[2:]
        # Remove @N suffix (stdcall decoration)
        if "@" in stripped:
            stripped = stripped.split("@")[0]
        # Remove imp_ prefix
        if stripped.startswith("imp_"):
            stripped = stripped[4:]
        return stripped

    def match_sink(self, name: str) -> tuple[str, dict] | None:
        """Match a function name against known dangerous sinks."""
        stripped = self.strip_ida_name(name)
        key = stripped.lower()
        if key in _SINK_NAMES_LOWER:
            canonical = _SINK_NAMES_LOWER[key]
            return canonical, _DANGEROUS_SINKS[canonical]
        return None

    @staticmethod
    def get_name(ea: int) -> str:
        return idc.get_name(ea, 0) or ""

    # ---- iteration helpers ----------------------------------------------

    @staticmethod
    def iter_functions(limit: int | None = None):
        if limit is None:
            return list(idautils.Functions())
        return list(islice(idautils.Functions(), limit))

    @staticmethod
    def get_func(ea: int):
        return ida_funcs.get_func(ea)

    @staticmethod
    def func_name_or_hex(ea: int) -> str:
        return idc.get_name(ea, 0) or hex(ea)

    @staticmethod
    def enum_imports() -> list[tuple[int, str]]:
        """Enumerate (ea, name) for all import names across all modules."""
        result: list[tuple[int, str]] = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            collected: list[tuple[int, str]] = []

            def imp_cb(ea: int, name: str | None, ordinal: int) -> bool:
                if name:
                    collected.append((ea, name))
                return True

            ida_nalt.enum_import_names(i, imp_cb)
            result.extend(collected)
        return result

    # ---- code iteration --------------------------------------------------

    @staticmethod
    def iter_code_heads(start_ea: int, end_ea: int):
        """Yield code heads within a function range."""
        for head in idautils.Heads(start_ea, end_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                yield head

    @staticmethod
    def call_targets_from(head: int):
        """Yield xref.to for direct calls from a head."""
        for xref in idautils.XrefsFrom(head, 0):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                yield xref.to

    @staticmethod
    def callers_to(ea: int, limit: int = _MAX_XREFS_PER_SINK):
        """Yield (caller_func_start_ea, call_site_ea) for code/jump xrefs to ea."""
        for xref in islice(idautils.XrefsTo(ea, 0), limit):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN):
                continue
            func = ida_funcs.get_func(xref.frm)
            if func:
                yield func.start_ea, xref.frm

    @staticmethod
    def call_callers_to(ea: int, limit: int = _MAX_XREFS_PER_SINK):
        """Yield caller func start_ea for direct call xrefs (fl_CF/fl_CN) to ea."""
        for xref in islice(idautils.XrefsTo(ea, 0), limit):
            if xref.type not in (idaapi.fl_CF, idaapi.fl_CN):
                continue
            caller = ida_funcs.get_func(xref.frm)
            if caller:
                yield caller.start_ea

    @staticmethod
    def call_callees_from_func(func) -> list[int]:
        """Return list of callee func start_eas for direct calls within func."""
        callees: list[int] = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                continue
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    target_func = ida_funcs.get_func(xref.to)
                    if target_func:
                        callees.append(target_func.start_ea)
        return callees

    # ---- crypto scanning -------------------------------------------------

    @staticmethod
    def decode_insn(head: int):
        """Decode an instruction; return insn_t or None."""
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, head) == 0:
            return None
        return insn

    @staticmethod
    def iter_imm_operands(insn):
        """Yield 32-bit immediate operand values from an instruction.

        Preserves the IDA-9 fix: UA_MAXOP was dropped from the ida_ua module in
        IDA 9.0, fall back to the historical operand count (8).
        """
        for op_idx in range(getattr(ida_ua, "UA_MAXOP", 8)):
            op = insn.ops[op_idx]
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_imm:
                yield op.value & 0xFFFFFFFF

    @staticmethod
    def iter_segments():
        """Yield (start_ea, end_ea) for every segment."""
        seg = idaapi.get_first_seg()
        while seg:
            yield seg.start_ea, seg.end_ea
            seg = idaapi.get_next_seg(seg.start_ea)

    @staticmethod
    def search_pattern(start_ea: int, end_ea: int, pattern: bytes):
        """Find next occurrence of pattern in [start_ea, end_ea).

        Preserves the IDA-9 fix: uses ``compat.raw_bin_search`` (IDA 9.0 dropped
        the old ``ida_bytes.bin_search`` signature in favour of find_bytes).
        Returns the found ea, or ``idaapi.BADADDR``.
        """
        return compat.raw_bin_search(
            start_ea, end_ea, pattern, None,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
        )

    @staticmethod
    def bad_addr() -> int:
        return idaapi.BADADDR

    @staticmethod
    def get_bytes(ea: int, size: int):
        return ida_bytes.get_bytes(ea, size)

    # ---- stack-string detection -----------------------------------------

    @staticmethod
    def is_mov_like(insn) -> bool:
        return insn.itype in (idaapi.NN_mov, idaapi.NN_movzx)

    @staticmethod
    def stack_store_imm(insn):
        """If insn is `mov [stack], imm8` return (offset, byte_val), else None."""
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        if op0.type not in (ida_ua.o_displ, ida_ua.o_phrase) or op1.type != ida_ua.o_imm:
            return None
        val = op1.value & 0xFF
        if val < 0x20 or val > 0x7E:  # Printable ASCII only
            return None
        offset = op0.addr if op0.type == ida_ua.o_displ else op0.value
        return offset, val

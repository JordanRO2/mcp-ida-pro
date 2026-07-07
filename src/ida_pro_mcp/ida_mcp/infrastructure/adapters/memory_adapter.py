"""Infrastructure adapter for memory reading/writing operations.

Holds the raw ``ida_bytes`` / ``idaapi`` / ``ida_typeinf`` / ``ida_nalt`` calls
extracted from the legacy flat ``api_memory`` module. Behavior is preserved
verbatim.
"""

from __future__ import annotations

import ida_bytes
import idaapi

from ...infrastructure.sync.sync import IDAError


class MemoryAdapter:
    """Raw IDA SDK access for memory read/write tools."""

    def get_bytes(self, ea: int, size: int):
        return ida_bytes.get_bytes(ea, size)

    def read_bytes_bss_safe(self, ea: int, size: int) -> bytes:
        """Read ``size`` bytes at ``ea``, substituting 0 for unloaded bytes.

        IDA reports 0xFF for bytes that belong to the address space but are not
        backed by file content (e.g. ``.bss`` / virtual space). Callers expect
        zero-initialized virtual memory, so unloaded bytes are read as 0 and the
        return is always exactly ``size`` bytes long (2fee279).
        """
        out = bytearray(size)
        for i in range(size):
            if ida_bytes.is_loaded(ea + i):
                out[i] = ida_bytes.get_byte(ea + i)
        return bytes(out)

    def read_int_bss_safe(self, ea: int, size: int) -> int:
        """Read an int of ``size`` bytes at ``ea`` honoring IDB endianness.

        Returns 0 for unloaded (``.bss`` / virtual) space instead of the 0xFF
        bytes IDA reports there (2fee279).
        """
        if not ida_bytes.is_loaded(ea):
            return 0
        if size == 1:
            return ida_bytes.get_byte(ea)
        if size == 2:
            return ida_bytes.get_word(ea)
        if size == 4:
            return ida_bytes.get_dword(ea)
        if size == 8:
            return ida_bytes.get_qword(ea)
        raise ValueError(f"unsupported integer size: {size}")

    def is_mapped(self, ea: int) -> bool:
        return ida_bytes.is_mapped(ea)

    def patch_bytes(self, ea: int, data: bytes) -> None:
        ida_bytes.patch_bytes(ea, data)

    def get_strlit_contents(self, ea: int):
        return idaapi.get_strlit_contents(ea, -1, 0)

    def get_name_ea(self, query: str) -> int:
        return idaapi.get_name_ea(idaapi.BADADDR, query)

    @property
    def BADADDR(self) -> int:
        return idaapi.BADADDR

    def get_global_variable_value_internal(self, ea: int) -> str:
        import ida_typeinf
        import ida_nalt
        import ida_bytes

        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, ea):
            if not ida_bytes.has_any_name(ea):
                raise IDAError(f"Failed to get type information for variable at {ea:#x}")

            size = ida_bytes.get_item_size(ea)
            if size == 0:
                raise IDAError(f"Failed to get type information for variable at {ea:#x}")
        else:
            size = tif.get_size()

        if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                return '""'
            return_string = raw.decode("utf-8", errors="replace").strip()
            return f'"{return_string}"'

        if size in (1, 2, 4, 8):
            return hex(self.read_int_bss_safe(ea, size))
        return " ".join(hex(b) for b in self.read_bytes_bss_safe(ea, size))

"""Infrastructure adapter for IDA type-system access (api_types domain).

Wraps the lower-level ``idaapi`` / ``ida_typeinf`` / ``ida_nalt`` / ``ida_bytes``
/ Hex-Rays calls used by the type tools. Behavior preservation outranks purity:
some orchestration that interleaves IDA calls with control flow remains in the
service. The primitives extracted here are the cleanly-wrappable ones.

This module imports ``idaapi`` lazily inside methods so the file still compiles
outside IDA (e.g. py_compile / AST checks).
"""

from __future__ import annotations

from typing import Any

from ..compat import get_ordinal_limit, inf_is_64bit, guess_tinfo


class TypesAdapter:
    """Adapter over IDA type-system primitives."""

    # -- generic byte reads (used by read_struct) --------------------------

    def is_64bit(self) -> bool:
        return inf_is_64bit()

    def get_byte(self, ea: int) -> int:
        import idaapi

        return idaapi.get_byte(ea)

    def get_word(self, ea: int) -> int:
        import idaapi

        return idaapi.get_word(ea)

    def get_dword(self, ea: int) -> int:
        import idaapi

        return idaapi.get_dword(ea)

    def get_qword(self, ea: int) -> int:
        import idaapi

        return idaapi.get_qword(ea)

    def get_name_ea(self, name: str) -> int:
        import idaapi

        return idaapi.get_name_ea(idaapi.BADADDR, name)

    @property
    def BADADDR(self) -> int:
        import idaapi

        return idaapi.BADADDR

    def get_func(self, ea: int) -> Any:
        import idaapi

        return idaapi.get_func(ea)

    # -- ordinal / catalog -------------------------------------------------

    def get_ordinal_limit(self) -> int:
        return get_ordinal_limit()

    # -- type inference (infer_types) --------------------------------------

    def guess_tinfo(self, tif: Any, ea: int) -> bool:
        return guess_tinfo(tif, ea)

    def get_tinfo(self, tif: Any, ea: int) -> bool:
        import ida_nalt

        return ida_nalt.get_tinfo(tif, ea)

    def get_item_size(self, ea: int) -> int:
        import ida_bytes

        return ida_bytes.get_item_size(ea)

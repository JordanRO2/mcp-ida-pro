"""Infrastructure adapter for the sigmaker engine.

Wraps the vendored ``_sigmaker`` engine plus the few ``idaapi``/``ida_funcs``
calls used for address/function resolution, so the sigmaker service stays free
of direct IDA SDK access.

The vendored engine module lives at the package root
(``ida_pro_mcp.ida_mcp._sigmaker``) and is left in place; this adapter is the
single import site for it.
"""

from __future__ import annotations

import dataclasses

import idaapi
import ida_funcs

from ...utils import parse_address
from ... import _sigmaker as _sm


_FORMAT_ALIASES = {
    "ida": "ida",
    "x64dbg": "x64dbg",
    "mask": "mask",
    "bitmask": "bitmask",
}


class SigmakerAdapter:
    """Low-level access for signature creation/scanning."""

    @staticmethod
    def resolve_format(fmt: str) -> str:
        key = fmt.lower().strip()
        if key not in _FORMAT_ALIASES:
            raise ValueError(
                f"Unknown signature format '{fmt}'. "
                f"Valid formats: ida, x64dbg, mask, bitmask"
            )
        return _FORMAT_ALIASES[key]

    @staticmethod
    def make_config(
        fmt: str,
        wildcard_operands: bool = True,
        continue_outside_function: bool = True,
        max_length: int = 1000,
    ):
        return _sm.SigMakerConfig(
            output_format=_sm.SignatureType(fmt),
            wildcard_operands=wildcard_operands,
            continue_outside_of_function=continue_outside_function,
            wildcard_optimized=False,
            ask_longer_signature=False,
            max_single_signature_length=max_length,
            max_xref_signature_length=max_length,
        )

    @staticmethod
    def replace_config(cfg, **changes):
        return dataclasses.replace(cfg, **changes)

    @staticmethod
    def resolve_addr(addr_str: str) -> int:
        """Resolve an address string or name to an ea."""
        try:
            return parse_address(addr_str)
        except Exception:
            ea = idaapi.get_name_ea(idaapi.BADADDR, addr_str)
            if ea == idaapi.BADADDR:
                raise ValueError(f"Cannot resolve address or name: {addr_str}")
            return ea

    @staticmethod
    def format_sig(sig, fmt: str) -> str:
        return format(sig, fmt)

    @staticmethod
    def signature_maker():
        return _sm.SignatureMaker()

    @staticmethod
    def xref_finder():
        return _sm.XrefFinder()

    @staticmethod
    def is_unique(sig) -> bool:
        return _sm.SignatureSearcher.is_unique(f"{sig:ida}")

    @staticmethod
    def get_func(ea: int):
        return ida_funcs.get_func(ea)

    @staticmethod
    def get_func_name(ea: int):
        return idaapi.get_func_name(ea) or None

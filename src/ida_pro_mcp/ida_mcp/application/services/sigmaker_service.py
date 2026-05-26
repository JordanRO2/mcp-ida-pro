"""Application service for signature creation and scanning.

Faithful move of the original ``api_sigmaker`` tool bodies. All engine /
IDA SDK access is delegated to ``SigmakerAdapter``.
"""

from __future__ import annotations

from typing import NotRequired, TypedDict

from ...utils import normalize_list_input


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class MakeSigResult(TypedDict):
    query: str
    addr: str | None
    signature: str | None
    format: str
    unique: NotRequired[bool]
    error: NotRequired[str]


class MakeSigForFunctionResult(TypedDict):
    query: str
    addr: str | None
    name: str | None
    signature: str | None
    format: str
    error: NotRequired[str]


class XrefSigResult(TypedDict):
    query: str
    addr: str | None
    signatures: list[dict] | None
    total_xrefs: NotRequired[int]
    error: NotRequired[str]


class SigmakerService:
    def __init__(self, adapter) -> None:
        self._adapter = adapter

    # ------------------------------------------------------------------
    def make_signature(
        self,
        addrs,
        format: str = "ida",
        wildcard_operands: bool = True,
        max_length: int = 1000,
    ) -> list[MakeSigResult]:
        a = self._adapter
        fmt = a.resolve_format(format)
        cfg = a.make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
        maker = a.signature_maker()
        addrs_list = normalize_list_input(addrs)

        results: list[MakeSigResult] = []
        for addr_str in addrs_list:
            ea = None
            try:
                ea = a.resolve_addr(addr_str)
                result = maker.make_signature(ea, cfg)
                sig_str = a.format_sig(result.signature, fmt)
                # Verify uniqueness
                is_unique = a.is_unique(result.signature)
                results.append({
                    "query": addr_str,
                    "addr": hex(ea),
                    "signature": sig_str,
                    "format": format,
                    "unique": is_unique,
                })
            except Exception as e:
                results.append({
                    "query": addr_str,
                    "addr": hex(ea) if ea is not None else None,
                    "signature": None,
                    "format": format,
                    "error": str(e),
                })
        return results

    # ------------------------------------------------------------------
    def make_signature_for_function(
        self,
        addrs,
        format: str = "ida",
        wildcard_operands: bool = True,
        max_length: int = 1000,
    ) -> list[MakeSigForFunctionResult]:
        a = self._adapter
        fmt = a.resolve_format(format)
        cfg = a.make_config(fmt, wildcard_operands=wildcard_operands, max_length=max_length)
        maker = a.signature_maker()
        addrs_list = normalize_list_input(addrs)

        results: list[MakeSigForFunctionResult] = []
        for addr_str in addrs_list:
            ea = None
            try:
                ea = a.resolve_addr(addr_str)
                func = a.get_func(ea)
                if not func:
                    results.append({
                        "query": addr_str,
                        "addr": hex(ea),
                        "name": None,
                        "signature": None,
                        "format": format,
                        "error": f"No function at {hex(ea)}",
                    })
                    continue

                func_ea = func.start_ea
                func_name = a.get_func_name(func_ea)
                result = maker.make_signature(func_ea, cfg)
                sig_str = a.format_sig(result.signature, fmt)
                results.append({
                    "query": addr_str,
                    "addr": hex(func_ea),
                    "name": func_name,
                    "signature": sig_str,
                    "format": format,
                })
            except Exception as e:
                results.append({
                    "query": addr_str,
                    "addr": hex(ea) if ea is not None else None,
                    "name": None,
                    "signature": None,
                    "format": format,
                    "error": str(e),
                })
        return results

    # ------------------------------------------------------------------
    def make_signature_for_range(
        self,
        start: str,
        end: str,
        format: str = "ida",
        wildcard_operands: bool = True,
    ) -> MakeSigResult:
        a = self._adapter
        fmt = a.resolve_format(format)
        cfg = a.make_config(fmt, wildcard_operands=wildcard_operands)
        maker = a.signature_maker()

        try:
            start_ea = a.resolve_addr(start)
            end_ea = a.resolve_addr(end)
            result = maker.make_signature(start_ea, cfg, end=end_ea)
            sig_str = a.format_sig(result.signature, fmt)
            is_unique = a.is_unique(result.signature)
            return {
                "query": f"{start}-{end}",
                "addr": hex(start_ea),
                "signature": sig_str,
                "format": format,
                "unique": is_unique,
            }
        except Exception as e:
            return {
                "query": f"{start}-{end}",
                "addr": None,
                "signature": None,
                "format": format,
                "error": str(e),
            }

    # ------------------------------------------------------------------
    def find_xref_signatures(
        self,
        addrs,
        format: str = "ida",
        top: int = 5,
        max_length: int = 250,
    ) -> list[XrefSigResult]:
        a = self._adapter
        fmt = a.resolve_format(format)
        cfg = a.make_config(fmt, max_length=max_length)
        cfg = a.replace_config(cfg, print_top_x=top)
        finder = a.xref_finder()
        addrs_list = normalize_list_input(addrs)

        results: list[XrefSigResult] = []
        for addr_str in addrs_list:
            ea = None
            try:
                ea = a.resolve_addr(addr_str)
                xref_result = finder.find_xrefs(ea, cfg)

                sigs = []
                for gs in xref_result.signatures[:top]:
                    sig_str = a.format_sig(gs.signature, fmt)
                    sigs.append({
                        "xref_addr": hex(int(gs.address)) if gs.address else None,
                        "signature": sig_str,
                        "length": len(gs.signature),
                    })

                results.append({
                    "query": addr_str,
                    "addr": hex(ea),
                    "signatures": sigs,
                    "total_xrefs": len(xref_result.signatures),
                })
            except Exception as e:
                results.append({
                    "query": addr_str,
                    "addr": hex(ea) if ea is not None else None,
                    "signatures": None,
                    "error": str(e),
                })
        return results

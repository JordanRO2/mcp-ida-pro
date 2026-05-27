"""Signature creation and scanning tools for IDA Pro MCP.

This module integrates sigmaker.py functionality to provide:
- Unique signature generation for addresses/functions
- Range-based signature generation (selection)
- XREF-based signature discovery
- Multiple output formats: IDA, x64dbg, mask, bitmask

Thin MCP tool layer: each ``@tool`` preserves the original public name,
signature, decorators and docstring, and delegates to ``SigmakerService``
resolved from the DI container.
"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...container import get_sigmaker_service
from ...application.services.sigmaker_service import (
    MakeSigResult,
    MakeSigForFunctionResult,
    XrefSigResult,
)


@tool
@idasync
def make_signature(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to create unique signatures for "
        "(e.g. '0x401000', 'main', or ['0x401000', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigResult]:
    """Create unique byte signatures for addresses. Generates the shortest
    unique signature starting at each address by walking instructions and
    wildcarding operands. Useful for finding stable patterns that survive
    recompilation."""
    return get_sigmaker_service().make_signature(
        addrs, format=format, wildcard_operands=wildcard_operands, max_length=max_length
    )


@tool
@idasync
def make_signature_for_function(
    addrs: Annotated[
        list[str] | str,
        "Function address(es) or name(s) to create signatures for "
        "(e.g. 'main', '0x401000', or ['main', 'sub_402000'])",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes before giving up (default: 1000)",
    ] = 1000,
) -> list[MakeSigForFunctionResult]:
    """Create unique byte signatures for function entry points. Resolves each
    name/address to a function, then generates the shortest unique signature
    starting at the function start."""
    return get_sigmaker_service().make_signature_for_function(
        addrs, format=format, wildcard_operands=wildcard_operands, max_length=max_length
    )


@tool
@idasync
def make_signature_for_range(
    start: Annotated[str, "Start address or name (e.g. '0x401000')"],
    end: Annotated[str, "End address or name (exclusive, e.g. '0x401020')"],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    wildcard_operands: Annotated[
        bool,
        "Wildcard instruction operands for relocatable signatures (default: true)",
    ] = True,
) -> MakeSigResult:
    """Create a byte signature for a specific address range (e.g. a selected
    region). Unlike make_signature, this does NOT guarantee uniqueness — it
    simply encodes the bytes in the range with optional operand wildcarding."""
    return get_sigmaker_service().make_signature_for_range(
        start, end, format=format, wildcard_operands=wildcard_operands
    )


@tool
@idasync
def find_xref_signatures(
    addrs: Annotated[
        list[str] | str,
        "Address(es) or name(s) to find XREF signatures for "
        "(e.g. a data address referenced by code)",
    ],
    format: Annotated[
        str,
        "Output format: 'ida' (default), 'x64dbg', 'mask', or 'bitmask'",
    ] = "ida",
    top: Annotated[
        int,
        "Number of shortest signatures to return per address (default: 5)",
    ] = 5,
    max_length: Annotated[
        int,
        "Maximum signature length in bytes (default: 250)",
    ] = 250,
) -> list[XrefSigResult]:
    """Find signatures for code locations that reference an address. For each
    input address, finds all code cross-references TO it, generates a unique
    signature at each xref site, and returns the shortest ones. Ideal for
    creating signatures for data addresses, vtable entries, or string
    references that can't be signatured directly."""
    return get_sigmaker_service().find_xref_signatures(
        addrs, format=format, top=top, max_length=max_length
    )

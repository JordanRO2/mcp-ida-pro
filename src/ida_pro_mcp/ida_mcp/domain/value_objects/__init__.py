"""Domain value objects for the IDA Pro MCP server.

Small immutable value types and pattern/encoding descriptors used across the
tool layer, modeled as ``TypedDict`` types (plus the generic ``Page``
pagination wrapper). For now they are re-exported from the legacy ``utils``
module; the tool-migration phase will relocate the definitions here. Import
them from this package going forward, e.g.::

    from ..domain.value_objects import ConvertedNumber, Page

Canonical (current) definitions live in
``ida_pro_mcp.ida_mcp.utils``.
"""

from ...utils import (
    ConvertedNumber,
    NumberConversion,
    PatternMatch,
    CodePattern,
    InsnPattern,
    Page,
    T,
)

__all__ = [
    "ConvertedNumber",
    "NumberConversion",
    "PatternMatch",
    "CodePattern",
    "InsnPattern",
    "Page",
    "T",
]

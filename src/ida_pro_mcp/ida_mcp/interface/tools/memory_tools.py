"""Memory reading and writing operations for IDA Pro MCP.

This module provides batch operations for reading and writing memory at various
granularities (bytes, integers, strings) and patching binary data.
"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...domain.entities import (
    IntRead,
    IntWrite,
    MemoryPatch,
    MemoryRead,
)
from ...container import get_memory_service


# ============================================================================
# Memory Reading Operations
# ============================================================================


@tool
@idasync
def get_bytes(regions: list[MemoryRead] | MemoryRead) -> list[dict]:
    """Read bytes from memory addresses"""
    return get_memory_service().get_bytes(regions)


@tool
@idasync
def get_int(
    queries: Annotated[
        list[IntRead] | IntRead,
        "Integer read requests (ty, addr). ty: i8/u64/i16le/i16be/etc",
    ],
) -> list[dict]:
    """Read integer values from memory addresses"""
    return get_memory_service().get_int(queries)


@tool
@idasync
def get_string(
    addrs: Annotated[list[str] | str, "Addresses to read strings from"],
) -> list[dict]:
    """Read strings from memory addresses"""
    return get_memory_service().get_string(addrs)


@tool
@idasync
def get_global_value(
    queries: Annotated[
        list[str] | str, "Global variable addresses or names to read values from"
    ],
) -> list[dict]:
    """Read global variable values by address or symbol name."""
    return get_memory_service().get_global_value(queries)


# ============================================================================
# Batch Data Operations
# ============================================================================


@tool
@idasync
def patch(patches: list[MemoryPatch] | MemoryPatch) -> list[dict]:
    """Patch bytes at memory addresses with hex data"""
    return get_memory_service().patch(patches)


@tool
@idasync
def put_int(
    items: Annotated[
        list[IntWrite] | IntWrite,
        "Integer write requests (ty, addr, value). value is a string; supports 0x.. and negatives",
    ],
) -> list[dict]:
    """Write integer values to memory addresses"""
    return get_memory_service().put_int(items)

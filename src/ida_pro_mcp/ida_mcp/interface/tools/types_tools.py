"""MCP tools for the IDA type system (api_types domain).

Thin ``@tool`` / ``@idasync`` wrappers that preserve the exact public names,
signatures, decorators and docstrings of the original flat ``api_types`` module
and delegate to ``TypesService`` resolved from the DI container.
"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...container import get_types_service
from ...domain.entities import (
    StructRead,
    TypeEdit,
    TypeInspectQuery,
    TypeQuery,
    TypeApplyBatch,
    EnumUpsert,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare C type definitions in local type library."""
    return get_types_service().declare_type(decls)


@tool
@idasync
def enum_upsert(
    queries: Annotated[
        list[EnumUpsert] | EnumUpsert,
        "Create enums if missing and upsert enum members without destructive replacement",
    ],
) -> list[dict]:
    """Create or extend local enums in an idempotent way."""
    return get_types_service().enum_upsert(queries)


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(queries: list[StructRead] | StructRead) -> list[dict]:
    """Read struct fields from memory at address; auto-detect type when possible."""
    return get_types_service().read_struct(queries)


@tool
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
    offset: Annotated[int, "Skip first N results (default 0)"] = 0,
    count: Annotated[int, "Max results to return (default 100, 0=all)"] = 100,
) -> dict:
    """Search local structs/unions by name pattern with pagination."""
    return get_types_service().search_structs(filter, offset, count)


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def type_query(
    queries: Annotated[
        list[TypeQuery] | TypeQuery | str,
        "Type catalog query with filtering, pagination, and optional relationships",
    ],
) -> list[dict]:
    """Query local types with structured filters/projection-friendly output."""
    return get_types_service().type_query(queries)


@tool
@idasync
def type_inspect(
    queries: Annotated[
        list[TypeInspectQuery] | TypeInspectQuery | str,
        "Inspect named types and optionally include member layout",
    ],
) -> list[dict]:
    """Inspect named types (size/kind/declaration/members)."""
    return get_types_service().type_inspect(queries)


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[dict]:
    """Apply types (function/global/local/stack)"""
    return get_types_service().set_type(edits)


@tool
@idasync
def type_apply_batch(
    batch: Annotated[
        TypeApplyBatch | list[TypeEdit] | TypeEdit,
        "Batch type edits with optional stop_on_error behavior",
    ],
) -> dict:
    """Apply multiple type edits and return aggregate status."""
    return get_types_service().type_apply_batch(batch)


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer and apply likely types at target addresses."""
    return get_types_service().infer_types(addrs)

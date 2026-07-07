"""Core API Functions - IDB metadata and basic queries"""

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync
from ...domain.entities import (
    EntityQuery,
    Function,
    FunctionQuery,
    Global,
    Import,
    ListQuery,
    ImportQuery,
)
from ...domain.value_objects import NumberConversion, Page
from ...container import get_core_service

# ============================================================================
# Core API Functions
# ============================================================================


@tool
@idasync
def server_health() -> dict:
    """Health/ready probe for MCP server and current IDB state."""
    return get_core_service().server_health()


@tool
@idasync
def server_warmup(
    wait_auto_analysis: Annotated[bool, "Wait for auto analysis queue"] = True,
    build_caches: Annotated[bool, "Build core caches (currently strings)"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler plugin"] = True,
) -> dict:
    """Warm up IDA subsystems to reduce first-call latency and transient failures."""
    return get_core_service().server_warmup(wait_auto_analysis, build_caches, init_hexrays)


@tool
@idasync
def lookup_funcs(
    queries: Annotated[list[str] | str, "Address(es) or name(s)"],
) -> list[dict]:
    """Get functions by address or name (auto-detects)"""
    return get_core_service().lookup_funcs(queries)


@tool
def int_convert(
    inputs: Annotated[
        list[NumberConversion] | NumberConversion,
        "Convert numbers to various formats (hex, decimal, binary, ascii)",
    ],
) -> list[dict]:
    """Convert numbers to different formats"""
    return get_core_service().int_convert(inputs)


@tool
@idasync
def list_funcs(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List functions with optional filtering and pagination",
    ],
) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    return get_core_service().list_funcs(queries)


@tool
@idasync
def func_query(
    queries: Annotated[
        list[FunctionQuery] | FunctionQuery | str,
        "Richer function query (size/type/name filters + pagination)",
    ],
) -> list[dict]:
    """Query functions with richer filtering than list_funcs."""
    return get_core_service().func_query(queries)


@tool
@idasync
def list_globals(
    queries: Annotated[
        list[ListQuery] | ListQuery | str,
        "List global variables with optional filtering and pagination",
    ],
) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    return get_core_service().list_globals(queries)


@tool
@idasync
def entity_query(
    queries: Annotated[
        list[EntityQuery] | EntityQuery | str,
        "Generic entity query with filtering, projection, and pagination",
    ],
) -> list[dict]:
    """Query IDB entities with typed filters, projection, and pagination."""
    return get_core_service().entity_query(queries)


@tool
@idasync
def imports(
    offset: Annotated[int, "Starting pagination index (default: 0)"],
    count: Annotated[int, "Maximum rows (0 returns all imports)"],
) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return get_core_service().imports(offset, count)


@tool
@idasync
def imports_query(
    queries: Annotated[
        list[ImportQuery] | ImportQuery | str,
        "Import query with import/module filters and pagination",
    ],
) -> list[dict]:
    """Query imports with richer filtering than imports(offset,count)."""
    return get_core_service().imports_query(queries)


@tool
@idasync
def idb_save(
    path: Annotated[str, "Optional destination path (default: current IDB path)"] = "",
) -> dict:
    """Save active IDB to disk, optionally to a provided path.

    In the GUI (idaq) the open database is backed by loose working files that IDA
    actively manages; packing+killing them corrupts the DB on reopen (#446). GUI
    mode therefore uses IDA's native in-place save (Ctrl+W), and an explicit
    different destination writes a compressed copy WITHOUT killing the live files.
    Only headless idalib packs into a single compressed .i64/.idb.
    """
    return get_core_service().idb_save(path)


@tool
@idasync
def find_regex(
    pattern: Annotated[str, "Regex pattern to search for in strings"],
    limit: Annotated[int, "Max matches (default: 30, max: 500)"] = 30,
    offset: Annotated[int, "Skip first N matches (default: 0)"] = 0,
) -> dict:
    """Search strings by case-insensitive regex with offset/limit pagination."""
    return get_core_service().find_regex(pattern, limit, offset)


@tool
@idasync
def search_text(
    pattern: Annotated[str, "Text to search for in the rendered listing (literal substring by default)"],
    limit: Annotated[int, "Max hits per page (default: 30, max: 500)"] = 30,
    start: Annotated[str, "Lower bound (hex or symbol). Empty = first segment."] = "",
    end: Annotated[str, "Upper bound (hex or symbol, exclusive). Empty = last segment."] = "",
    regex: Annotated[bool, "Treat pattern as a Python regex"] = False,
    case_sensitive: Annotated[bool, "Case-sensitive match (default: false)"] = False,
    include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"] = "all",
    code_only: Annotated[bool, "Restrict search to executable segments (default: true)"] = True,
) -> dict:
    """Search the rendered listing (disassembly + comments) for `pattern` over
    [start, end). Complements find/find_bytes/find_regex (which match strings
    and bytes) by searching what IDA actually renders; cancellable and paged."""
    return get_core_service().search_text(
        pattern, limit, start, end, regex, case_sensitive, include, code_only
    )

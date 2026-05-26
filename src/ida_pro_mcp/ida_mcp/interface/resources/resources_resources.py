"""MCP Resources - browsable IDB state

Resources represent browsable state (read-only data) following MCP's philosophy.
Use tools for actions that modify state or perform expensive computations.

Thin MCP resource layer: each ``@resource`` preserves the original URI,
function name, signature, decorators and docstring, and delegates to
``ResourcesService`` resolved from the DI container.
"""

from typing import Annotated

from ...rpc import resource
from ...infrastructure.sync.sync import idasync
from ...container import get_resources_service
from ...domain.entities import Metadata, Segment


# ============================================================================
# Core IDB State
# ============================================================================


@resource("ida://idb/metadata")
@idasync
def idb_metadata_resource() -> Metadata:
    """Get IDB file metadata (path, arch, base address, size, hashes)"""
    return get_resources_service().idb_metadata()


@resource("ida://idb/segments")
@idasync
def idb_segments_resource() -> list[Segment]:
    """Get all memory segments with permissions"""
    return get_resources_service().idb_segments()


@resource("ida://idb/entrypoints")
@idasync
def idb_entrypoints_resource() -> list[dict]:
    """Get entry points (main, TLS callbacks, etc.)"""
    return get_resources_service().idb_entrypoints()


# ============================================================================
# UI State
# ============================================================================


@resource("ida://cursor")
@idasync
def cursor_resource() -> dict:
    """Get current cursor position and function"""
    return get_resources_service().cursor()


@resource("ida://selection")
@idasync
def selection_resource() -> dict:
    """Get current selection range (if any)"""
    return get_resources_service().selection()


# ============================================================================
# Function / Global Lookup
# ============================================================================


@resource("ida://function/{addr}")
@idasync
def function_resource(addr: Annotated[str, "Function address or name"]) -> dict:
    """Get function details: name, address, size, prototype, flags"""
    return get_resources_service().function(addr)


@resource("ida://global/{addr}")
@idasync
def global_resource(addr: Annotated[str, "Global address or name"]) -> dict:
    """Get global variable details: name, address, size, type"""
    return get_resources_service().global_(addr)


# ============================================================================
# Type Information
# ============================================================================


@resource("ida://types")
@idasync
def types_resource() -> list[dict]:
    """Get all local types"""
    return get_resources_service().types()


@resource("ida://structs")
@idasync
def structs_resource() -> list[dict]:
    """Get all structures/unions"""
    return get_resources_service().structs()


@resource("ida://struct/{name}")
@idasync
def struct_name_resource(name: Annotated[str, "Structure name"]) -> dict:
    """Get structure definition with fields"""
    return get_resources_service().struct_by_name(name)


# ============================================================================
# Import/Export Lookup by Name
# ============================================================================


@resource("ida://import/{name}")
@idasync
def import_name_resource(name: Annotated[str, "Import name"]) -> dict:
    """Get specific import details by name"""
    return get_resources_service().import_by_name(name)


@resource("ida://export/{name}")
@idasync
def export_name_resource(name: Annotated[str, "Export name"]) -> dict:
    """Get specific export details by name"""
    return get_resources_service().export_by_name(name)


# ============================================================================
# Type Lookup by Name
# ============================================================================


@resource("ida://type/{name}")
@idasync
def type_name_resource(name: Annotated[str, "Type name"]) -> dict:
    """Get type definition by name (structs, enums, typedefs)"""
    return get_resources_service().type_by_name(name)


# ============================================================================
# Cross-references
# ============================================================================


@resource("ida://xrefs/from/{addr}")
@idasync
def xrefs_from_resource(addr: Annotated[str, "Source address"]) -> list[dict]:
    """Get cross-references from address"""
    return get_resources_service().xrefs_from(addr)

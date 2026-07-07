"""IDA-free tests for the zeromcp MCP schema generator and notification handlers.

Covers the four MCP-spec fixes in zeromcp/mcp.py:
  * _type_to_json_schema(Any) -> {}                       (33a876a)
  * _schema_is_object_like helper                          (6b6dd63)
  * outputSchema wrapping: union-of-objects stays object-  (6b6dd63 + ed52145)
    rooted and unwrapped; scalars are still wrapped
  * notifications/initialized handler registered           (bbca735)

zeromcp/mcp.py is pure-stdlib (imports only stdlib + .jsonrpc), but the real
package parent ida_pro_mcp.ida_mcp.__init__ pulls in idaapi. To keep this test
fully IDA-free we load mcp.py (and its .jsonrpc sibling) under a private
synthetic package instead of importing through the real namespace.
"""
import importlib.util
import os
import sys
import types
from typing import Any, TypedDict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ZM_DIR = os.path.abspath(
    os.path.join(_HERE, "..", "src", "ida_pro_mcp", "ida_mcp", "zeromcp")
)
_PKG = "_zeromcp_spec_pkg"


def _load_mcp_module():
    """Load zeromcp/mcp.py as a standalone module, IDA-free."""
    mcp_name = _PKG + ".mcp"
    if mcp_name in sys.modules:
        return sys.modules[mcp_name]

    pkg = types.ModuleType(_PKG)
    pkg.__path__ = [_ZM_DIR]
    sys.modules[_PKG] = pkg

    # mcp.py does `from .jsonrpc import ...`, so load jsonrpc first.
    for name in ("jsonrpc", "mcp"):
        spec = importlib.util.spec_from_file_location(
            f"{_PKG}.{name}", os.path.join(_ZM_DIR, name + ".py")
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"{_PKG}.{name}"] = mod
        spec.loader.exec_module(mod)

    return sys.modules[mcp_name]


mcp_mod = _load_mcp_module()
McpServer = mcp_mod.McpServer


class _VariantA(TypedDict):
    a: int


class _VariantB(TypedDict):
    b: str


# --- 33a876a: Any maps to an empty schema ---------------------------------


def test_type_to_json_schema_any_is_empty():
    assert McpServer("t")._type_to_json_schema(Any) == {}


# --- 6b6dd63: _schema_is_object_like --------------------------------------


def test_schema_is_object_like():
    s = McpServer("t")
    assert s._schema_is_object_like({"type": "object"}) is True
    assert s._schema_is_object_like(
        {"anyOf": [{"type": "object"}, {"type": "object"}]}
    ) is True
    assert s._schema_is_object_like(
        {"anyOf": [{"type": "object"}, {"type": "string"}]}
    ) is False
    assert s._schema_is_object_like({"type": "string"}) is False
    assert s._schema_is_object_like({}) is False


# --- 6b6dd63 + ed52145: union-of-objects outputSchema ---------------------


def test_union_of_objects_output_schema_object_rooted_and_unwrapped():
    s = McpServer("t")

    def tool_union() -> _VariantA | _VariantB:
        ...

    out = s._generate_tool_schema("tool_union", tool_union)["outputSchema"]
    # ed52145: root must be object for strict validators.
    assert out["type"] == "object"
    # 6b6dd63: anyOf preserved, not wrapped in a "result" property.
    assert "anyOf" in out
    assert "properties" not in out


# --- ed52145 baseline: scalar returns are still wrapped -------------------


def test_scalar_output_schema_is_wrapped():
    s = McpServer("t")

    def tool_scalar() -> int:
        ...

    out = s._generate_tool_schema("tool_scalar", tool_scalar)["outputSchema"]
    assert out["type"] == "object"
    assert out["properties"]["result"] == {"type": "integer"}
    assert out["required"] == ["result"]


def test_single_object_output_schema_not_double_wrapped():
    s = McpServer("t")

    def tool_obj() -> _VariantA:
        ...

    out = s._generate_tool_schema("tool_obj", tool_obj)["outputSchema"]
    assert out["type"] == "object"
    # A plain object is passed through unwrapped (no "result" property).
    assert set(out.get("properties", {})) == {"a"}


# --- bbca735: notifications/initialized handler ---------------------------


def test_notifications_initialized_registered_and_none():
    s = McpServer("t")
    assert "notifications/initialized" in s.registry.methods
    assert s._mcp_notifications_initialized() is None

"""IDA-free unit tests for CoreService.idb_save GUI/headless branching (#446).

CoreService.idb_save only touches ``self.adapter``, so a FakeAdapter exercises
the full branch matrix without IDA. Importing the package normally is not an
option: ``ida_pro_mcp.ida_mcp.__init__`` registers every @tool and starts
server-side machinery that blocks in a headless test process. We therefore exec
just ``core_service.py`` against stubbed parent packages + stubbed sibling
modules (the same isolated-load technique the sync-cancellation test uses).
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_SVC_PATH = _SRC / "ida_pro_mcp" / "ida_mcp" / "application" / "services" / "core_service.py"
_MODNAME = "ida_pro_mcp.ida_mcp.application.services.core_service"


def _pkg(name: str, path: Path) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__path__ = [str(path)]  # mark as package so submodule resolution works
    return mod


def _load_core_service():
    """Exec core_service.py in isolation, stubbing only what its imports need."""
    # IDA SDK module referenced at core_service import time.
    sys.modules.setdefault("idaapi", MagicMock(name="idaapi"))

    # Parent packages: setdefault so a real already-imported package (e.g. the
    # lightweight top-level ``ida_pro_mcp`` used by test_server_transport) wins,
    # and give stubs the real filesystem __path__ so unrelated submodule imports
    # still resolve to real files.
    _parents = {
        "ida_pro_mcp": _SRC / "ida_pro_mcp",
        "ida_pro_mcp.ida_mcp": _SRC / "ida_pro_mcp" / "ida_mcp",
        "ida_pro_mcp.ida_mcp.infrastructure": _SRC / "ida_pro_mcp" / "ida_mcp" / "infrastructure",
        "ida_pro_mcp.ida_mcp.infrastructure.adapters": _SRC / "ida_pro_mcp" / "ida_mcp" / "infrastructure" / "adapters",
        "ida_pro_mcp.ida_mcp.infrastructure.cache": _SRC / "ida_pro_mcp" / "ida_mcp" / "infrastructure" / "cache",
        "ida_pro_mcp.ida_mcp.domain": _SRC / "ida_pro_mcp" / "ida_mcp" / "domain",
        "ida_pro_mcp.ida_mcp.application": _SRC / "ida_pro_mcp" / "ida_mcp" / "application",
        "ida_pro_mcp.ida_mcp.application.services": _SRC / "ida_pro_mcp" / "ida_mcp" / "application" / "services",
    }
    for _name, _path in _parents.items():
        if _name not in sys.modules:
            sys.modules[_name] = _pkg(_name, _path)

    # Sibling modules: provide exactly the names core_service imports, so the
    # heavy real modules (and their IDA deps) are never loaded.
    def _stub(name: str, **attrs):
        mod = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(mod, k, v)
        sys.modules[name] = mod

    _noop = lambda *a, **k: None  # noqa: E731
    _stub("ida_pro_mcp.ida_mcp.infrastructure.adapters.core_adapter", CoreAdapter=object)
    _stub(
        "ida_pro_mcp.ida_mcp.infrastructure.cache.strings_cache",
        get_strings_cache=lambda *a, **k: [],
        init_caches=_noop,
    )
    _stub("ida_pro_mcp.ida_mcp.domain.entities", Function=dict, Global=dict, Import=dict)
    _stub("ida_pro_mcp.ida_mcp.domain.value_objects", ConvertedNumber=object)
    _stub(
        "ida_pro_mcp.ida_mcp.utils",
        get_function=_noop,
        normalize_dict_list=_noop,
        normalize_list_input=_noop,
        parse_address=_noop,
        paginate=_noop,
        pattern_filter=_noop,
    )

    spec = importlib.util.spec_from_file_location(_MODNAME, _SVC_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MODNAME] = mod
    spec.loader.exec_module(mod)
    return mod.CoreService


CoreService = _load_core_service()


class FakeAdapter:
    def __init__(self, *, gui, idb_path="/db/sample.i64", ok=True):
        self._gui, self._idb_path, self._ok = gui, idb_path, ok
        self.calls = []

    def get_idb_path(self):
        return self._idb_path

    def is_gui(self):
        return self._gui

    def save_database_native(self):
        self.calls.append(("native",)); return self._ok

    def save_database_copy(self, save_path):
        self.calls.append(("copy", save_path)); return self._ok

    def save_database_pack(self, save_path):
        self.calls.append(("pack", save_path)); return self._ok


def test_headless_packs():
    a = FakeAdapter(gui=False)
    r = CoreService(a).idb_save("")
    assert a.calls == [("pack", "/db/sample.i64")]
    assert r == {"ok": True, "path": "/db/sample.i64", "error": None}


def test_gui_no_path_native_save():
    a = FakeAdapter(gui=True)
    r = CoreService(a).idb_save("")
    assert a.calls == [("native",)] and r["ok"] and r["path"] == "/db/sample.i64"


def test_gui_same_path_native_save():
    a = FakeAdapter(gui=True, idb_path="/db/sample.i64")
    CoreService(a).idb_save("/db/sample.i64")
    assert a.calls == [("native",)]


def test_gui_different_path_compressed_copy():
    a = FakeAdapter(gui=True, idb_path="/db/sample.i64")
    CoreService(a).idb_save("/db/snapshot.i64")
    assert a.calls == [("copy", "/db/snapshot.i64")]


def test_unresolvable_path():
    a = FakeAdapter(gui=False, idb_path="")
    r = CoreService(a).idb_save("")
    assert r == {"ok": False, "path": None, "error": "Could not resolve IDB path"}
    assert a.calls == []


def test_save_false_reports_error():
    a = FakeAdapter(gui=False, ok=False)
    r = CoreService(a).idb_save("")
    assert r["ok"] is False and r["error"] == "save_database returned false"

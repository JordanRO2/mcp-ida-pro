"""IDA-free tests for compat.tinfo_get_udm (IDA 9.0-SP0 fallback).

tinfo_t.get_udm() is missing in early IDA 9.0 builds (e.g. build 240925, this
environment); the wrapper must fall back to find_udm() + get_udm_by_tid().
compat.py imports ida_* at module top, so stub them and load in isolation.
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parents[1] / "src"
_COMPAT = _SRC / "ida_pro_mcp" / "ida_mcp" / "infrastructure" / "compat.py"


class _Udm:
    def __init__(self):
        self.name = ""


import importlib.abc  # noqa: E402
import importlib.machinery  # noqa: E402


class _IdaAutoStub(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Meta-path finder (find_spec API): any not-yet-loaded ida*/idc/idaapi
    module resolves to a MagicMock, so compat.py's many version-gated IDA
    imports all succeed without an IDA install."""

    def find_spec(self, name, path=None, target=None):
        head = name.split(".")[0]
        if (head in ("idaapi", "idc") or head.startswith("ida_") or head == "ida") and name not in sys.modules:
            return importlib.machinery.ModuleSpec(name, self)
        return None

    def create_module(self, spec):
        m = MagicMock(name=spec.name)
        if spec.name == "idaapi":
            m.get_kernel_version.return_value = "9.0"
        return m

    def exec_module(self, module):
        pass


def _load_compat():
    # ida_typeinf needs a real udm_t factory for the fallback path; everything
    # else IDA is auto-stubbed.
    ti = types.ModuleType("ida_typeinf")
    ti.udm_t = _Udm
    ti.tinfo_t = object
    sys.modules["ida_typeinf"] = ti
    idaapi_stub = MagicMock(name="idaapi")
    idaapi_stub.get_kernel_version.return_value = "9.0"
    sys.modules["idaapi"] = idaapi_stub
    finder = _IdaAutoStub()
    sys.meta_path.insert(0, finder)
    try:
        spec = importlib.util.spec_from_file_location("_compat_under_test", _COMPAT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.meta_path.remove(finder)
    return mod


compat = _load_compat()


class _ModernTif:
    def get_udm(self, name):
        return (5, f"modern:{name}")


class _LegacyTif:
    """No get_udm; only the old find_udm/get_udm_tid/get_udm_by_tid trio."""

    def __init__(self, members):
        self._members = members  # name -> idx

    def find_udm(self, name):
        return self._members.get(name, -1)

    def get_udm_tid(self, idx):
        return 1000 + idx

    def get_udm_by_tid(self, udm, tid):
        idx = tid - 1000
        for n, i in self._members.items():
            if i == idx:
                udm.name = n
        return 0


def test_modern_path_delegates_to_get_udm():
    assert compat.tinfo_get_udm(_ModernTif(), "foo") == (5, "modern:foo")


def test_legacy_fallback_finds_member():
    idx, udm = compat.tinfo_get_udm(_LegacyTif({"var_4": 2}), "var_4")
    assert idx == 2 and udm is not None and udm.name == "var_4"


def test_legacy_fallback_missing_returns_sentinel():
    idx, udm = compat.tinfo_get_udm(_LegacyTif({"var_4": 2}), "nope")
    assert idx == -1 and udm is None

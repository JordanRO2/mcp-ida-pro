"""IDA-free unit tests for PythonExecService.py_exec_file.

``py_exec_file`` executes a whole Python script FILE in the IDA globals
namespace using a single shared globals dict (no locals split), capturing
stdout/stderr. Its only IDA touchpoint is ``self.adapter.build_exec_globals()``,
so a FakeAdapter fully exercises it without IDA.

The real service module transitively imports the IDA-backed adapter (and, via
the package ``__init__``, the whole plugin), so we load the service module in
isolation: fake parent packages are registered in ``sys.modules`` and the
adapter import is satisfied by a stub. No ``idaapi``/``ida_*`` import happens.
"""

import importlib.util
import sys
import tempfile
import types
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
_SERVICE_PATH = (
    _SRC
    / "ida_pro_mcp"
    / "ida_mcp"
    / "application"
    / "services"
    / "python_exec_service.py"
)


def _load_service_class():
    """Load PythonExecService in isolation, then restore ``sys.modules``.

    We register fake parent packages + a stub adapter module so the service's
    relative imports resolve WITHOUT running the IDA-importing package
    ``__init__`` or the real adapter. Everything we add is removed afterward so
    this test never shadows the real ``ida_pro_mcp`` package for other tests.
    """
    adapter_name = (
        "ida_pro_mcp.ida_mcp.infrastructure.adapters.python_exec_adapter"
    )
    mod_name = "ida_pro_mcp.ida_mcp.application.services.python_exec_service"

    added: list[str] = []

    def _reg(name: str, module) -> None:
        if name not in sys.modules:
            sys.modules[name] = module
            added.append(name)

    try:
        for pkg in (
            "ida_pro_mcp",
            "ida_pro_mcp.ida_mcp",
            "ida_pro_mcp.ida_mcp.application",
            "ida_pro_mcp.ida_mcp.application.services",
            "ida_pro_mcp.ida_mcp.infrastructure",
            "ida_pro_mcp.ida_mcp.infrastructure.adapters",
        ):
            m = types.ModuleType(pkg)
            m.__path__ = []  # mark as a package
            _reg(pkg, m)

        # Satisfy `from ...infrastructure.adapters.python_exec_adapter import
        # PythonExecAdapter` with a stub so the real IDA-importing adapter is
        # never loaded. The service only references the class for DI; tests
        # inject their own FakeAdapter instance.
        adapter_mod = types.ModuleType(adapter_name)

        class PythonExecAdapter:  # stub placeholder
            pass

        adapter_mod.PythonExecAdapter = PythonExecAdapter
        _reg(adapter_name, adapter_mod)

        spec = importlib.util.spec_from_file_location(mod_name, _SERVICE_PATH)
        module = importlib.util.module_from_spec(spec)
        _reg(mod_name, module)
        spec.loader.exec_module(module)
        return module.PythonExecService
    finally:
        # Undo every sys.modules entry we introduced so the real package stays
        # importable for other test modules run in the same process.
        for name in added:
            sys.modules.pop(name, None)


PythonExecService = _load_service_class()


class FakeAdapter:
    """Stands in for PythonExecAdapter: supplies the exec globals namespace."""

    def __init__(self, extra=None):
        self._extra = extra or {}

    def build_exec_globals(self) -> dict:
        g = {"__builtins__": __builtins__, "injected_value": 42}
        g.update(self._extra)
        return g


def _write_script(text: str) -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    )
    f.write(text)
    f.close()
    return f.name


def test_py_exec_file_runs_and_returns_result():
    path = _write_script("print('hi')\nresult = 6\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == "6"
    assert r["stdout"] == "hi\n"
    assert r["stderr"] == ""


def test_py_exec_file_missing_file():
    r = PythonExecService(FakeAdapter()).py_exec_file(
        "/definitely/not/a/real/path_xyz_42.py"
    )
    assert r["result"] == ""
    assert r["stdout"] == ""
    assert "File not found" in r["stderr"]


def test_py_exec_file_top_level_defs_visible():
    # Single shared globals dict: a top-level def must be callable by later
    # top-level code. py_eval's locals-split would break this.
    path = _write_script("def f():\n    return 5\n\nresult = f()\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == "5"
    assert r["stderr"] == ""


def test_py_exec_file_sees_injected_globals():
    # Values from build_exec_globals() are visible to the script.
    path = _write_script("result = injected_value\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == "42"


def test_py_exec_file_result_defaults_empty():
    # No `result` assignment -> result is "".
    path = _write_script("x = 1 + 1\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == ""
    assert r["stderr"] == ""


def test_py_exec_file_exception_captured():
    # An exception in the script is captured as a traceback in stderr, and
    # any stdout emitted before the raise is preserved.
    path = _write_script("print('before')\nraise ValueError('boom')\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == ""
    assert "before\n" in r["stdout"]
    assert "ValueError: boom" in r["stderr"]


def test_py_exec_file_sets_dunder_file():
    path = _write_script("result = __file__\n")
    r = PythonExecService(FakeAdapter()).py_exec_file(path)
    assert r["result"] == path

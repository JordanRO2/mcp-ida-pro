"""IDA-free unit tests for @idasync native cancellation + get_tool_deadline().

sync.py imports idaapi/ida_kernwin/idc at module top and pulls McpToolError /
jsonrpc helpers via relative imports, so we register lightweight fake modules in
sys.modules BEFORE loading sync.py by file path. The fakes are restored
immediately after load (sync.py has already bound its module-level references),
so nothing leaks into the rest of the suite (e.g. test_server_transport.py,
which imports the real ida_pro_mcp package).
"""
import importlib.util
import os
import sys
import time
from types import ModuleType

import pytest

SYNC_MOD_NAME = "ida_pro_mcp.ida_mcp.infrastructure.sync.sync"
SYNC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src",
    "ida_pro_mcp",
    "ida_mcp",
    "infrastructure",
    "sync",
    "sync.py",
)

_MISSING = object()


def _make_ida_kernwin() -> ModuleType:
    mod = ModuleType("ida_kernwin")
    mod._cancelled = False
    mod.clr_count = 0
    mod.set_count = 0

    def clr_cancelled():
        mod._cancelled = False
        mod.clr_count += 1

    def set_cancelled():
        mod._cancelled = True
        mod.set_count += 1

    def user_cancelled():
        return mod._cancelled

    def reset():
        mod._cancelled = False
        mod.clr_count = 0
        mod.set_count = 0

    mod.clr_cancelled = clr_cancelled
    mod.set_cancelled = set_cancelled
    mod.user_cancelled = user_cancelled
    mod.reset = reset
    return mod


def _make_fakes() -> dict:
    idaapi = ModuleType("idaapi")
    idaapi.MFF_WRITE = 1
    idaapi.get_kernel_version = lambda: "9.0"

    def execute_sync(fn, flags):
        # Run synchronously on the calling thread (no real IDA main thread).
        fn()
        return 1

    idaapi.execute_sync = execute_sync

    idc = ModuleType("idc")
    idc.batch = lambda n: 0

    ida_kernwin = _make_ida_kernwin()

    rpc = ModuleType("ida_pro_mcp.ida_mcp.rpc")

    class McpToolError(Exception):
        pass

    rpc.McpToolError = McpToolError

    jsonrpc = ModuleType("ida_pro_mcp.ida_mcp.zeromcp.jsonrpc")
    jsonrpc.get_current_cancel_event = lambda: None

    class RequestCancelledError(Exception):
        pass

    jsonrpc.RequestCancelledError = RequestCancelledError

    def _pkg(name):
        m = ModuleType(name)
        m.__path__ = []  # mark as a package so submodule imports resolve
        return m

    fakes = {
        "idaapi": idaapi,
        "idc": idc,
        "ida_kernwin": ida_kernwin,
        "ida_pro_mcp": _pkg("ida_pro_mcp"),
        "ida_pro_mcp.ida_mcp": _pkg("ida_pro_mcp.ida_mcp"),
        "ida_pro_mcp.ida_mcp.rpc": rpc,
        "ida_pro_mcp.ida_mcp.zeromcp": _pkg("ida_pro_mcp.ida_mcp.zeromcp"),
        "ida_pro_mcp.ida_mcp.zeromcp.jsonrpc": jsonrpc,
        "ida_pro_mcp.ida_mcp.infrastructure": _pkg(
            "ida_pro_mcp.ida_mcp.infrastructure"
        ),
        "ida_pro_mcp.ida_mcp.infrastructure.sync": _pkg(
            "ida_pro_mcp.ida_mcp.infrastructure.sync"
        ),
    }
    return fakes


def _load_sync():
    fakes = _make_fakes()
    names = list(fakes) + [SYNC_MOD_NAME]
    saved = {name: sys.modules.get(name, _MISSING) for name in names}
    sys.modules.update(fakes)
    try:
        spec = importlib.util.spec_from_file_location(SYNC_MOD_NAME, SYNC_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[SYNC_MOD_NAME] = module
        spec.loader.exec_module(module)
        return module, fakes["ida_kernwin"]
    finally:
        # sync.py already bound its module-level references; drop the fakes so
        # the real ida_pro_mcp package remains importable for other tests.
        for name, val in saved.items():
            if val is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = val


sync, KERNWIN = _load_sync()


@pytest.fixture(autouse=True)
def _reset_kernwin():
    KERNWIN.reset()
    sync._deadline_state.deadline = None
    yield


@sync.idasync
def _body(sleep_for=0.0, capture=None):
    if capture is not None:
        capture["deadline"] = sync.get_tool_deadline()
        capture["now"] = time.monotonic()
    if sleep_for:
        time.sleep(sleep_for)
    return "RESULT"


def test_deadline_none_at_rest():
    assert sync.get_tool_deadline() is None


def test_deadline_exposed_inside_body():
    capture = {}
    r = _body(capture=capture)
    assert r == "RESULT"
    d = capture["deadline"]
    assert isinstance(d, float)
    # Default 60s timeout -> deadline sits in the future relative to the
    # monotonic clock captured inside the body.
    assert d > capture["now"]


def test_deadline_cleared_and_flag_cleared_after_normal_call():
    r = _body()
    assert r == "RESULT"
    # Cleared in the finally block.
    assert sync.get_tool_deadline() is None
    # clr_cancelled called at entry AND in finally (>= 2).
    assert KERNWIN.clr_count >= 2
    assert KERNWIN.user_cancelled() is False


def test_timer_fires_set_cancelled_and_clears_sticky():
    # timeout smaller than the body's runtime -> the daemon Timer must fire.
    r = _body(sleep_for=0.2, timeout=0.05)
    assert r == "RESULT"
    assert KERNWIN.set_count >= 1
    # Sticky cancel flag cleared in finally so the next tool starts clean.
    assert KERNWIN.user_cancelled() is False


def test_grace_returns_body_value_not_timeout_error():
    # Body finishes (~0.2s) well within the 5s grace window after the native
    # cancel fires, so the wrapper returns the body value instead of raising
    # IDASyncError.
    r = _body(sleep_for=0.2, timeout=0.05)
    assert r == "RESULT"


def test_no_timer_when_no_timeout_and_no_cancel_event():
    # With timeout=0 and no cancel event, sync_wrapper takes the untimed path:
    # deadline stays None and set_cancelled is never scheduled.
    r = _body(timeout=0)
    assert r == "RESULT"
    assert KERNWIN.set_count == 0
    assert sync.get_tool_deadline() is None


def test_package_reexport_declares_get_tool_deadline():
    # infrastructure/sync/__init__.py must re-export get_tool_deadline so
    # consumers can `from ...infrastructure.sync import get_tool_deadline`.
    init_path = os.path.join(os.path.dirname(SYNC_PATH), "__init__.py")
    with open(init_path, "r", encoding="utf-8") as fh:
        src = fh.read()
    assert "get_tool_deadline" in src

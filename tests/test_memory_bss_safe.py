"""IDA-free unit tests for the virtual-space FF->zero memory fix (2fee279).

Unloaded (``.bss`` / virtual) bytes are reported as 0xFF by IDA; the fix makes
the memory trio surface them as 0 instead. The adapter/service import IDA
modules at module top and live under ``ida_pro_mcp.ida_mcp`` whose package
``__init__`` hangs on import, so we load ONLY the two target files in isolation
under a synthetic package namespace (``_bsspkg.mcp.*``) backed by stubbed IDA
modules, then RESTORE ``sys.modules`` so nothing leaks to sibling test files.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src" / "ida_pro_mcp" / "ida_mcp"
_ADAPTER_PATH = _SRC / "infrastructure" / "adapters" / "memory_adapter.py"
_SERVICE_PATH = _SRC / "application" / "services" / "memory_service.py"


class _Holder:
    """Per-test control block for the fake IDA modules."""

    mem = None       # FakeMem backing store for ida_bytes
    tif_size = 0     # size reported by the fake tinfo_t


class FakeMem:
    """Fake ida_bytes store: [base, base+len(data)) is loaded, everything else unloaded.

    Mirrors IDA: unloaded bytes read back as 0xFF via the raw getters.
    """

    def __init__(self, base: int, data: bytes = b""):
        self.base = base
        self.data = bytes(data)

    def _byte(self, ea: int) -> int:
        off = ea - self.base
        if 0 <= off < len(self.data):
            return self.data[off]
        return 0xFF  # IDA reports 0xFF for unloaded bytes

    def is_loaded(self, ea: int) -> bool:
        off = ea - self.base
        return 0 <= off < len(self.data)

    def get_byte(self, ea: int) -> int:
        return self._byte(ea)

    def get_word(self, ea: int) -> int:
        return self._byte(ea) | (self._byte(ea + 1) << 8)

    def get_dword(self, ea: int) -> int:
        return sum(self._byte(ea + i) << (8 * i) for i in range(4))

    def get_qword(self, ea: int) -> int:
        return sum(self._byte(ea + i) << (8 * i) for i in range(8))

    def get_bytes(self, ea: int, size: int) -> bytes:
        return bytes(self._byte(ea + i) for i in range(size))


class _FakeTif:
    def __init__(self, size: int):
        self._size = size

    def get_size(self) -> int:
        return self._size

    def is_array(self) -> bool:
        return False


def _load_isolated(fullname: str, path: Path):
    spec = importlib.util.spec_from_file_location(fullname, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[fullname] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mem():
    holder = _Holder()

    # --- snapshot every sys.modules key we are about to install/override ---
    installed = [
        "ida_bytes",
        "idaapi",
        "ida_typeinf",
        "ida_nalt",
        "_bsspkg",
        "_bsspkg.mcp",
        "_bsspkg.mcp.infrastructure",
        "_bsspkg.mcp.infrastructure.sync",
        "_bsspkg.mcp.infrastructure.sync.sync",
        "_bsspkg.mcp.infrastructure.adapters",
        "_bsspkg.mcp.infrastructure.adapters.memory_adapter",
        "_bsspkg.mcp.application",
        "_bsspkg.mcp.application.services",
        "_bsspkg.mcp.application.services.memory_service",
        "_bsspkg.mcp.utils",
    ]
    saved = {name: sys.modules.get(name) for name in installed}

    def _pkg(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        m.__path__ = []  # mark as package so relative imports resolve
        sys.modules[name] = m
        return m

    try:
        # --- absolute IDA stubs (top-level imports in the target modules) ---
        ib = types.ModuleType("ida_bytes")
        ib.is_loaded = lambda ea: holder.mem.is_loaded(ea)
        ib.get_byte = lambda ea: holder.mem.get_byte(ea)
        ib.get_word = lambda ea: holder.mem.get_word(ea)
        ib.get_dword = lambda ea: holder.mem.get_dword(ea)
        ib.get_qword = lambda ea: holder.mem.get_qword(ea)
        ib.get_bytes = lambda ea, size: holder.mem.get_bytes(ea, size)
        ib.is_mapped = lambda ea: holder.mem.is_loaded(ea)
        ib.has_any_name = lambda ea: True
        ib.get_item_size = lambda ea: 0
        sys.modules["ida_bytes"] = ib

        idaapi = types.ModuleType("idaapi")
        idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        idaapi.get_name_ea = lambda base, name: idaapi.BADADDR
        idaapi.get_strlit_contents = lambda ea, a, b: None
        sys.modules["idaapi"] = idaapi

        ida_typeinf = types.ModuleType("ida_typeinf")
        ida_typeinf.tinfo_t = lambda: _FakeTif(holder.tif_size)
        sys.modules["ida_typeinf"] = ida_typeinf

        ida_nalt = types.ModuleType("ida_nalt")
        ida_nalt.get_tinfo = lambda tif, ea: True
        sys.modules["ida_nalt"] = ida_nalt

        # --- synthetic package tree mirroring ida_pro_mcp.ida_mcp.* ---
        _pkg("_bsspkg")
        _pkg("_bsspkg.mcp")
        _pkg("_bsspkg.mcp.infrastructure")
        _pkg("_bsspkg.mcp.infrastructure.sync")
        _pkg("_bsspkg.mcp.infrastructure.adapters")
        _pkg("_bsspkg.mcp.application")
        _pkg("_bsspkg.mcp.application.services")

        sync_mod = types.ModuleType("_bsspkg.mcp.infrastructure.sync.sync")

        class IDAError(Exception):
            pass

        sync_mod.IDAError = IDAError
        sys.modules["_bsspkg.mcp.infrastructure.sync.sync"] = sync_mod

        utils_mod = types.ModuleType("_bsspkg.mcp.utils")
        utils_mod.parse_address = lambda a: a if isinstance(a, int) else int(a, 0)
        utils_mod.normalize_list_input = lambda x: list(x) if isinstance(x, list) else [x]
        utils_mod.looks_like_address = lambda x: True
        sys.modules["_bsspkg.mcp.utils"] = utils_mod

        adapter_mod = _load_isolated(
            "_bsspkg.mcp.infrastructure.adapters.memory_adapter", _ADAPTER_PATH
        )
        service_mod = _load_isolated(
            "_bsspkg.mcp.application.services.memory_service", _SERVICE_PATH
        )

        ns = types.SimpleNamespace(
            holder=holder,
            MemoryAdapter=adapter_mod.MemoryAdapter,
            MemoryService=service_mod.MemoryService,
            IDAError=IDAError,
        )
        yield ns
    finally:
        # --- restore: delete keys that were absent, restore ones that existed ---
        for name, prev in saved.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev


# ---------------------------------------------------------------------------
# Adapter primitives
# ---------------------------------------------------------------------------


def test_read_bytes_bss_safe_fully_unloaded_is_zero(mem):
    mem.holder.mem = FakeMem(0x1000, b"")  # nothing loaded
    adapter = mem.MemoryAdapter()
    assert adapter.read_bytes_bss_safe(0x5000, 16) == b"\x00" * 16


def test_read_bytes_bss_safe_partial_load(mem):
    # first two bytes loaded, remainder unloaded
    mem.holder.mem = FakeMem(0x2000, b"\xaa\xbb")
    adapter = mem.MemoryAdapter()
    assert adapter.read_bytes_bss_safe(0x2000, 4) == b"\xaa\xbb\x00\x00"


def test_read_bytes_bss_safe_fully_loaded(mem):
    mem.holder.mem = FakeMem(0x3000, b"\x01\x02\x03\x04")
    adapter = mem.MemoryAdapter()
    assert adapter.read_bytes_bss_safe(0x3000, 4) == b"\x01\x02\x03\x04"


def test_read_int_bss_safe_unloaded_is_zero(mem):
    mem.holder.mem = FakeMem(0x4000, b"")
    adapter = mem.MemoryAdapter()
    for size in (1, 2, 4, 8):
        assert adapter.read_int_bss_safe(0x9000, size) == 0


def test_read_int_bss_safe_loaded_values(mem):
    mem.holder.mem = FakeMem(0x5000, b"\x11\x22\x33\x44\x55\x66\x77\x88")
    adapter = mem.MemoryAdapter()
    assert adapter.read_int_bss_safe(0x5000, 1) == 0x11
    assert adapter.read_int_bss_safe(0x5000, 2) == 0x2211
    assert adapter.read_int_bss_safe(0x5000, 4) == 0x44332211
    assert adapter.read_int_bss_safe(0x5000, 8) == 0x8877665544332211


def test_read_int_bss_safe_unsupported_size_raises(mem):
    mem.holder.mem = FakeMem(0x6000, b"\x01\x02\x03")
    adapter = mem.MemoryAdapter()
    with pytest.raises(ValueError):
        adapter.read_int_bss_safe(0x6000, 3)


def test_global_var_value_unloaded_int_is_zero_not_ff(mem):
    # size==4 int in unloaded space must read 0x0, not 0xffffffff
    mem.holder.mem = FakeMem(0x7000, b"")
    mem.holder.tif_size = 4
    adapter = mem.MemoryAdapter()
    assert adapter.get_global_variable_value_internal(0xB000) == "0x0"


def test_global_var_value_unloaded_bytes_are_zero_not_ff(mem):
    # size not in {1,2,4,8} -> byte-join branch; unloaded bytes are 0x0 each
    mem.holder.mem = FakeMem(0x7100, b"")
    mem.holder.tif_size = 3
    adapter = mem.MemoryAdapter()
    assert adapter.get_global_variable_value_internal(0xB100) == "0x0 0x0 0x0"


# ---------------------------------------------------------------------------
# Service routing through the BSS-safe adapter reads
# ---------------------------------------------------------------------------


def test_service_get_bytes_unloaded_returns_zeros(mem):
    mem.holder.mem = FakeMem(0x8000, b"")
    svc = mem.MemoryService(mem.MemoryAdapter())
    out = svc.get_bytes({"addr": "0xC000", "size": 3})
    assert out == [{"addr": "0xC000", "data": "0x0 0x0 0x0"}]


def test_service_get_bytes_loaded_roundtrip(mem):
    mem.holder.mem = FakeMem(0x8100, b"\xde\xad\xbe\xef")
    svc = mem.MemoryService(mem.MemoryAdapter())
    out = svc.get_bytes({"addr": str(0x8100), "size": 4})
    assert out == [{"addr": "33024", "data": "0xde 0xad 0xbe 0xef"}]


def test_service_get_int_unloaded_is_zero_no_error(mem):
    mem.holder.mem = FakeMem(0x8200, b"")
    svc = mem.MemoryService(mem.MemoryAdapter())
    out = svc.get_int({"addr": "0xD000", "ty": "u32le"})
    assert out == [{"addr": "0xD000", "ty": "u32le", "value": 0, "error": None}]


def test_service_get_int_loaded_value(mem):
    mem.holder.mem = FakeMem(0x8300, b"\x11\x22\x33\x44")
    svc = mem.MemoryService(mem.MemoryAdapter())
    out = svc.get_int({"addr": str(0x8300), "ty": "u32le"})
    assert out[0]["value"] == 0x44332211
    assert out[0]["error"] is None

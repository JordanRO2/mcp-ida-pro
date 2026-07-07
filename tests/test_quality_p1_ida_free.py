"""IDA-free unit tests for the quality_p1 backlog features.

Covers, without a live IDA:
  * parse_address symbol resolution + new error strings (utils, 753bb81)
  * decompile_function_safe -> (code, error) tuple contract (utils, c395db9)
  * hexrays_local_var_exists helper (utils, c395db9)
  * ModifyService.force_recompile / set_op_type / make_data (modify trio)
  * ModifyService.add_bookmark slot reuse/allocation (b3eb2eb)
  * rename_at_ea actionable conflict message (modify_service, c395db9)
  * AnalysisService.xrefs_to is_mapped guard + xref_count + message (c395db9)

Strategy: the real source files are loaded in isolation via importlib under their
canonical package names, with concrete (non-MagicMock) ``ida_*`` module stubs and
stub parent packages pre-seeded in sys.modules.  Importing the whole
``ida_pro_mcp`` package is intentionally avoided (it hangs).  All stubs are
snapshot-and-restored so nothing leaks into sibling test files.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src"
_PKG_ROOT = _SRC / "ida_pro_mcp" / "ida_mcp"

BADADDR = 0xFFFFFFFFFFFFFFFF

# ---------------------------------------------------------------------------
# Concrete ida_* stubs (NOT MagicMock: parse_address compares against BADADDR)
# ---------------------------------------------------------------------------

_NAME_MAP: dict[str, int] = {}


def _make_ida_stubs() -> dict[str, types.ModuleType]:
    stubs: dict[str, types.ModuleType] = {}

    def mod(name: str) -> types.ModuleType:
        m = types.ModuleType(name)
        stubs[name] = m
        return m

    idaapi = mod("idaapi")
    idaapi.BADADDR = BADADDR
    idaapi.SN_CHECK = 0x01
    idaapi.SN_FORCE = 0x800

    def get_name_ea(_from_ea, name):
        return _NAME_MAP.get(str(name), BADADDR)

    idaapi.get_name_ea = get_name_ea

    def set_name(ea, name, flags=0):
        return True

    idaapi.set_name = set_name

    ida_funcs = mod("ida_funcs")
    ida_funcs.func_t = type("func_t", (), {})

    ida_typeinf = mod("ida_typeinf")
    ida_typeinf.tinfo_t = type("tinfo_t", (), {})

    ida_hexrays = mod("ida_hexrays")
    ida_hexrays.user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
    ida_hexrays.init_hexrays_plugin = lambda: False  # error paths by default

    for name in (
        "ida_kernwin",
        "ida_nalt",
        "idautils",
        "idc",
        "ida_lines",
        "ida_bytes",
        "ida_name",
        "ida_frame",
        "ida_dirtree",
        "ida_ua",
    ):
        mod(name)

    return stubs


def _make_pkg(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__path__ = []  # mark as a package so submodule imports resolve
    return m


def _load_source(fqname: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(fqname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[fqname] = module
    spec.loader.exec_module(module)
    return module


# Module handles populated by _load_all().
utils = None
modify_service = None
analysis_service = None

# The concrete ida_* stubs, created ONCE. The autouse fixture re-inserts these
# exact objects into sys.modules for the duration of each test (call-time
# `import idaapi` inside parse_address/rename_at_ea needs them present).
_IDA_STUBS = _make_ida_stubs()


def _load_all():
    """Load the real source modules in isolation, then FULLY clean sys.modules.

    Nothing is left registered after import so sibling test files (collected in
    the same pytest session) see an unpolluted sys.modules -- in particular the
    real ``ida_pro_mcp`` package is not shadowed by our fake package stubs.
    """
    global utils, modify_service, analysis_service

    pkg_names = [
        "ida_pro_mcp",
        "ida_pro_mcp.ida_mcp",
        "ida_pro_mcp.ida_mcp.infrastructure",
        "ida_pro_mcp.ida_mcp.infrastructure.sync",
        "ida_pro_mcp.ida_mcp.infrastructure.adapters",
        "ida_pro_mcp.ida_mcp.application",
        "ida_pro_mcp.ida_mcp.application.services",
        "ida_pro_mcp.ida_mcp.domain",
        "ida_pro_mcp.ida_mcp.domain.entities",
    ]

    added: list[str] = []
    prior: dict[str, object] = {}

    def put(name: str, module) -> None:
        if name not in prior:
            prior[name] = sys.modules.get(name)
        added.append(name)
        sys.modules[name] = module

    for n, m in _IDA_STUBS.items():
        put(n, m)
    for n in pkg_names:
        put(n, _make_pkg(n))

    sync_mod = types.ModuleType("ida_pro_mcp.ida_mcp.infrastructure.sync.sync")

    class IDAError(Exception):
        def __init__(self, message):
            super().__init__(message)
            self.message = message

    sync_mod.IDAError = IDAError
    put("ida_pro_mcp.ida_mcp.infrastructure.sync.sync", sync_mod)

    ma = types.ModuleType("ida_pro_mcp.ida_mcp.infrastructure.adapters.modify_adapter")
    ma.ModifyAdapter = type("ModifyAdapter", (), {})
    put(ma.__name__, ma)

    aa = types.ModuleType("ida_pro_mcp.ida_mcp.infrastructure.adapters.analysis_adapter")
    aa.AnalysisAdapter = type("AnalysisAdapter", (), {})
    put(aa.__name__, aa)

    added.append("ida_pro_mcp.ida_mcp.utils")
    prior.setdefault("ida_pro_mcp.ida_mcp.utils", sys.modules.get("ida_pro_mcp.ida_mcp.utils"))
    utils = _load_source("ida_pro_mcp.ida_mcp.utils", _PKG_ROOT / "utils.py")

    ent = sys.modules["ida_pro_mcp.ida_mcp.domain.entities"]
    for name in ("Argument", "DisassemblyFunction", "Xref", "BasicBlock"):
        setattr(ent, name, getattr(utils, name))

    for fq, rel in (
        (
            "ida_pro_mcp.ida_mcp.application.services.modify_service",
            _PKG_ROOT / "application" / "services" / "modify_service.py",
        ),
        (
            "ida_pro_mcp.ida_mcp.application.services.analysis_service",
            _PKG_ROOT / "application" / "services" / "analysis_service.py",
        ),
    ):
        added.append(fq)
        prior.setdefault(fq, sys.modules.get(fq))
        loaded = _load_source(fq, rel)
        if fq.endswith("modify_service"):
            modify_service = loaded
        else:
            analysis_service = loaded

    # Full cleanup: restore sys.modules to exactly its pre-import state.
    for name in added:
        prev = prior.get(name)
        if prev is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prev


_load_all()


@pytest.fixture(autouse=True)
def _ida_stub_ctx():
    """Make the concrete ida_* stubs visible for call-time inline imports."""
    saved = {n: sys.modules.get(n) for n in _IDA_STUBS}
    for n, m in _IDA_STUBS.items():
        sys.modules[n] = m
    try:
        yield
    finally:
        for n, prev in saved.items():
            if prev is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = prev


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeModifyAdapter:
    """Adapter double for ModifyService with a call log."""

    def __init__(self, **kw):
        self.calls = []
        # force_recompile
        self._functions = kw.get("functions", [0x1000, 0x2000])
        self._func_start = kw.get("func_start", {0x10: 0x10})
        self._names = kw.get("names", {})
        # set_op_type
        self._stroff = kw.get("stroff", (True, None))
        self._op_plain = kw.get("op_plain", True)
        self._op_stkvar = kw.get("op_stkvar", True)
        self._op_format = kw.get("op_format", True)
        # make_data
        self._set_type_ok = kw.get("set_type_ok", True)
        self._size = kw.get("size", 8)
        self._get_name = kw.get("get_name", "auto_name")
        self._get_type = kw.get("get_type", "int[2]")
        # bookmarks
        self._bookmarks = dict(kw.get("bookmarks", {}))  # slot -> ea

    # -- force_recompile --
    def functions(self):
        self.calls.append(("functions",))
        return list(self._functions)

    def func_start_ea(self, ea):
        return self._func_start.get(ea)

    def func_name(self, ea):
        return self._names.get(ea, "fn_%x" % ea)

    def mark_cfunc_dirty(self, ea):
        self.calls.append(("mark_dirty", ea))

    # -- set_op_type --
    def op_stroff_by_struct(self, ea, op_n, struct, delta):
        self.calls.append(("stroff", ea, op_n, struct, delta))
        return self._stroff

    def op_plain_offset(self, ea, op_n, target):
        self.calls.append(("plain_offset", ea, op_n, target))
        return self._op_plain

    def op_stkvar(self, ea, op_n):
        self.calls.append(("stkvar", ea, op_n))
        return self._op_stkvar

    def set_op_format(self, ea, op_n, kind):
        self.calls.append(("op_format", ea, op_n, kind))
        return self._op_format

    # -- make_data --
    def set_type(self, ea, decl):
        self.calls.append(("set_type", ea, decl))
        return self._set_type_ok

    def guess_size(self, ea):
        return self._size

    def del_items_expand(self, ea, nbytes):
        self.calls.append(("del_items", ea, nbytes))
        return True

    def set_name(self, ea, name):
        self.calls.append(("set_name", ea, name))
        return True

    def get_name(self, ea):
        return self._get_name

    def get_type(self, ea):
        return self._get_type

    def clear_cached_cfuncs(self):
        self.calls.append(("clear_cfuncs",))

    # -- bookmarks --
    @property
    def BADADDR(self):
        return BADADDR

    def get_bookmark(self, slot):
        return self._bookmarks.get(slot, BADADDR)

    def put_bookmark(self, ea, x, y, flags, slot, text):
        self.calls.append(("put_bookmark", ea, slot, text))
        self._bookmarks[slot] = ea


class FakeAnalysisAdapter:
    def __init__(self, mapped=True, xrefs=None):
        self._mapped = mapped
        self._xrefs = xrefs or []

    def is_mapped(self, ea):
        return self._mapped

    def xrefs_to(self, ea):
        return list(self._xrefs)


def _msvc():
    return modify_service.ModifyService(FakeModifyAdapter())


# ---------------------------------------------------------------------------
# parse_address (753bb81)
# ---------------------------------------------------------------------------


def test_parse_address_int_passthrough():
    assert utils.parse_address(255) == 255


def test_parse_address_hex_prefixed():
    assert utils.parse_address("0x1234") == 0x1234


def test_parse_address_resolves_name():
    _NAME_MAP.clear()
    _NAME_MAP["main"] = 0x123E
    try:
        assert utils.parse_address("main") == 0x123E
    finally:
        _NAME_MAP.clear()


def test_parse_address_unknown_name_raises_not_found():
    _NAME_MAP.clear()
    with pytest.raises(utils.IDAError) as ei:
        utils.parse_address("nonexistent_symbol_xyz_42")
    assert "Not found" in str(ei.value)


def test_parse_address_bare_hex_missing_prefix():
    _NAME_MAP.clear()
    with pytest.raises(utils.IDAError) as ei:
        utils.parse_address("1a2b")
    assert "missing 0x prefix" in str(ei.value)


# ---------------------------------------------------------------------------
# decompile_function_safe tuple + hexrays_local_var_exists (c395db9)
# ---------------------------------------------------------------------------


def test_decompile_function_safe_returns_tuple_on_failure():
    # ida_hexrays.init_hexrays_plugin stub returns False -> decompile_checked
    # raises IDAError("Hex-Rays decompiler is not available")
    code, err = utils.decompile_function_safe(0x1000)
    assert code is None
    assert err is not None
    assert "Hex-Rays decompiler is not available" in err


def test_hexrays_local_var_exists_false_without_decompiler():
    assert utils.hexrays_local_var_exists(0x1000, "v1") is False


# ---------------------------------------------------------------------------
# ModifyService.force_recompile
# ---------------------------------------------------------------------------


def test_force_recompile_all_when_none():
    svc = modify_service.ModifyService(FakeModifyAdapter(functions=[0x1000, 0x2000]))
    out = svc.force_recompile(None)
    assert out["summary"]["all"] is True
    assert out["summary"]["total"] == 2
    assert out["summary"]["ok"] == 2
    assert {r["addr"] for r in out["results"]} == {"0x1000", "0x2000"}


def test_force_recompile_all_when_empty_list():
    svc = modify_service.ModifyService(FakeModifyAdapter(functions=[0x1000]))
    out = svc.force_recompile([])
    assert out["summary"]["all"] is True
    assert out["summary"]["total"] == 1


def test_force_recompile_single_op():
    adapter = FakeModifyAdapter(func_start={0x10: 0x10}, names={0x10: "sub_10"})
    svc = modify_service.ModifyService(adapter)
    out = svc.force_recompile({"addr": "0x10"})
    assert out["summary"]["all"] is False
    assert out["summary"]["ok"] == 1
    assert out["results"][0]["name"] == "sub_10"
    assert ("mark_dirty", 0x10) in adapter.calls


def test_force_recompile_invalid_addr_skipped():
    adapter = FakeModifyAdapter()
    svc = modify_service.ModifyService(adapter)
    _NAME_MAP.clear()
    out = svc.force_recompile([{"addr": "not_a_symbol"}])
    assert out["summary"]["total"] == 0  # skipped, nothing marked
    assert not any(c[0] == "mark_dirty" for c in adapter.calls)


# ---------------------------------------------------------------------------
# ModifyService.set_op_type
# ---------------------------------------------------------------------------


def test_set_op_type_unknown_kind():
    out = _msvc().set_op_type({"addr": "0x10", "op_n": 0, "kind": "bogus"})
    assert out[0]["ok"] is False
    assert "unknown kind" in out[0]["error"]


def test_set_op_type_stroff_requires_struct():
    out = _msvc().set_op_type({"addr": "0x10", "kind": "stroff"})
    assert out[0]["ok"] is False
    assert "struct name required" in out[0]["error"]


def test_set_op_type_hex_format_ok():
    adapter = FakeModifyAdapter()
    out = modify_service.ModifyService(adapter).set_op_type(
        {"addr": "0x10", "op_n": 1, "kind": "hex"}
    )
    assert out[0]["ok"] is True
    assert ("op_format", 0x10, 1, "hex") in adapter.calls


def test_set_op_type_stroff_with_struct():
    adapter = FakeModifyAdapter(stroff=(True, None))
    out = modify_service.ModifyService(adapter).set_op_type(
        {"addr": "0x10", "op_n": 0, "kind": "stroff", "struct": "Point", "delta": 4}
    )
    assert out[0]["ok"] is True
    assert ("stroff", 0x10, 0, "Point", 4) in adapter.calls


def test_set_op_type_invalid_addr():
    _NAME_MAP.clear()
    out = _msvc().set_op_type({"addr": "junk_addr", "kind": "hex"})
    assert out[0]["ok"] is False
    assert "Not found" in out[0]["error"]


# ---------------------------------------------------------------------------
# ModifyService.make_data
# ---------------------------------------------------------------------------


def test_make_data_empty_type():
    out = _msvc().make_data({"addr": "0x10", "type": ""})
    assert out[0]["ok"] is False
    assert out[0]["error"] == "type declaration is required"


def test_make_data_settype_rejected():
    adapter = FakeModifyAdapter(set_type_ok=False)
    out = modify_service.ModifyService(adapter).make_data(
        {"addr": "0x10", "type": "int probe"}
    )
    assert out[0]["ok"] is False
    assert "SetType rejected declaration" in out[0]["error"]


def test_make_data_happy_path():
    adapter = FakeModifyAdapter(set_type_ok=True, size=8, get_type="int[2]")
    out = modify_service.ModifyService(adapter).make_data(
        {"addr": "0x10", "type": "int probe[2]", "name": "g_probe"}
    )
    entry = out[0]
    assert entry["ok"] is True
    assert entry["size"] == 8
    assert entry["name"] == "g_probe"
    # del_items called (delete_existing default True, size>0) + re-apply set_type
    assert ("del_items", 0x10, 8) in adapter.calls
    assert ("set_name", 0x10, "g_probe") in adapter.calls
    assert ("clear_cfuncs",) in adapter.calls
    # set_type applied twice (initial + re-apply after del_items)
    assert sum(1 for c in adapter.calls if c[0] == "set_type") == 2


def test_make_data_no_delete_when_flag_false():
    adapter = FakeModifyAdapter(set_type_ok=True, size=8)
    modify_service.ModifyService(adapter).make_data(
        {"addr": "0x10", "type": "int probe", "delete_existing": False}
    )
    assert not any(c[0] == "del_items" for c in adapter.calls)


# ---------------------------------------------------------------------------
# ModifyService.add_bookmark (b3eb2eb)
# ---------------------------------------------------------------------------


def test_add_bookmark_first_free_slot():
    adapter = FakeModifyAdapter(bookmarks={})  # all free
    out = modify_service.ModifyService(adapter).add_bookmark("0x123e", "main-entry")
    assert out["ok"] is True
    assert out["slot"] == 0
    assert out["title"] == "idaMCP: main-entry"
    assert ("put_bookmark", 0x123E, 0, "idaMCP: main-entry") in adapter.calls


def test_add_bookmark_reuses_existing_slot_for_same_ea():
    adapter = FakeModifyAdapter(bookmarks={0: 0x1111, 1: 0x123E, 2: 0x2222})
    out = modify_service.ModifyService(adapter).add_bookmark("0x123e", "again")
    assert out["ok"] is True
    assert out["slot"] == 1  # reuses the slot already holding 0x123E


def test_add_bookmark_empty_prefix():
    adapter = FakeModifyAdapter(bookmarks={})
    out = modify_service.ModifyService(adapter).add_bookmark("0x10", "label", prefix="")
    assert out["title"] == "label"


def test_add_bookmark_invalid_addr():
    _NAME_MAP.clear()
    out = _msvc().add_bookmark("not_an_addr", "x")
    assert out["ok"] is False
    assert "Not found" in out["error"]


# ---------------------------------------------------------------------------
# rename_at_ea (c395db9)
# ---------------------------------------------------------------------------


def test_rename_at_ea_conflict_message():
    _NAME_MAP.clear()
    _NAME_MAP["main"] = 0x123E
    try:
        ok, err = modify_service.rename_at_ea(0x11A0, "main")
        assert ok is False
        assert "already used" in err
        assert "0x123e" in err
    finally:
        _NAME_MAP.clear()


def test_rename_at_ea_success():
    _NAME_MAP.clear()
    ok, err = modify_service.rename_at_ea(0x11A0, "brand_new_name")
    assert ok is True
    assert err is None


def test_rename_at_ea_dry_run_conflict_still_reported():
    _NAME_MAP.clear()
    _NAME_MAP["main"] = 0x123E
    try:
        ok, err = modify_service.rename_at_ea(0x11A0, "main", dry_run=True)
        assert ok is False
        assert "already used" in err
    finally:
        _NAME_MAP.clear()


# ---------------------------------------------------------------------------
# AnalysisService.xrefs_to (c395db9)
# ---------------------------------------------------------------------------


def test_xrefs_to_unmapped_address():
    svc = analysis_service.AnalysisService(FakeAnalysisAdapter(mapped=False))
    out = svc.xrefs_to("0x1000")
    assert out[0]["xrefs"] is None
    assert "Address not mapped" in out[0]["error"]


def test_xrefs_to_zero_xrefs_message():
    svc = analysis_service.AnalysisService(FakeAnalysisAdapter(mapped=True, xrefs=[]))
    out = svc.xrefs_to("0x1000")
    entry = out[0]
    assert entry["xrefs"] == []
    assert entry["xref_count"] == 0
    assert "No cross-references" in entry["message"]

"""IDA-free unit tests for the sigmaker engine v1.8.0 upgrade.

Covers the two headline deltas ported from upstream 77c3090 (net of
0916ebf+77c3090, numpy-free):

  * ``WildcardPolicy.for_x86`` no longer wildcards immediates (``o_imm`` is
    excluded from the x86 wildcard set) while MEM/FAR/NEAR and the X86-specific
    register kinds are still wildcarded.
  * ``SignatureSearcher.is_unique`` bails at the second match instead of
    enumerating every match (``find_all(..., skip_more_than_one=True)``).

Also covers the ``GeneratedSignature`` (length, wildcard_count) ordering used
to rank xref signatures, and pins ``__version__``.

The engine module (``_sigmaker.py``) imports ``idaapi``/``idc`` and references
operand-type constants at class-definition time, so we install lightweight
stubs in ``sys.modules`` and load the file directly via importlib -- this keeps
the test fully headless (no IDA / idalib required) and avoids pulling in the
heavy ``ida_pro_mcp.ida_mcp`` package ``__init__``.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types


# --- module path ------------------------------------------------------------
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SIGMAKER_PATH = (
    _REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "_sigmaker.py"
)


# --- fake idaapi ------------------------------------------------------------
class _FakeInsn:
    """Stand-in for idaapi.insn_t (only used as a default_factory at import)."""

    def __init__(self):
        self.size = 0


def _make_fake_idaapi() -> types.ModuleType:
    m = types.ModuleType("idaapi")

    # Operand type constants (canonical IDA values). Distinct ints are required
    # because WildcardPolicy's kind enums are IntEnums built from them.
    m.o_void = 0
    m.o_reg = 1
    m.o_mem = 2
    m.o_phrase = 3
    m.o_displ = 4
    m.o_imm = 5
    m.o_far = 6
    m.o_near = 7
    m.o_idpspec0 = 8
    m.o_idpspec1 = 9
    m.o_idpspec2 = 10
    m.o_idpspec3 = 11
    m.o_idpspec4 = 12
    m.o_idpspec5 = 13

    m.BADADDR = 0xFFFFFFFFFFFFFFFF
    m.insn_t = _FakeInsn

    # Processor-id constants (referenced only inside method bodies).
    m.PLFM_386 = 0
    m.PLFM_ARM = 1
    m.PLFM_MIPS = 2
    m.PLFM_PPC = 3
    m.IDA_SDK_VERSION = 900

    # Search constants + fake search machinery (exercised by find_all).
    m.BIN_SEARCH_NOCASE = 1
    m.BIN_SEARCH_FORWARD = 2
    m.compiled_binpat_vec_t = lambda: object()
    m.parse_binpat_str = lambda *a, **k: None
    m.inf_get_min_ea = lambda: 0
    m.inf_get_max_ea = lambda: 0x7FFFFFFF
    m.user_cancelled = lambda: False

    # bin_search is replaced per-test; default: no matches.
    m.bin_search = lambda ea, max_ea, binary, flags: (m.BADADDR, None)
    return m


# Install stubs and load the engine module once for the whole test module.
# The engine binds ``idaapi``/``idc`` as module globals at exec time, so after
# loading we keep our own ``_fake_idaapi`` reference (which the tests mutate)
# and RESTORE sys.modules to its prior state -- that way this file never leaks
# its stubs into other test modules collected in the same pytest process.
_fake_idaapi = _make_fake_idaapi()
_prev = {name: sys.modules.get(name) for name in ("idaapi", "idc")}
sys.modules["idaapi"] = _fake_idaapi
sys.modules["idc"] = types.ModuleType("idc")

_spec = importlib.util.spec_from_file_location(
    "_sigmaker_v18_under_test", str(_SIGMAKER_PATH)
)
sm = importlib.util.module_from_spec(_spec)
# Register before exec so dataclasses can resolve string annotations
# (from __future__ import annotations) via sys.modules[cls.__module__].
sys.modules["_sigmaker_v18_under_test"] = sm
try:
    _spec.loader.exec_module(sm)
finally:
    for name, mod in _prev.items():
        if mod is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = mod


# ===========================================================================
# for_x86 immediate exclusion (headline delta #1)
# ===========================================================================
def test_for_x86_excludes_immediate_operands():
    policy = sm.WildcardPolicy.for_x86()
    # Immediates are literals baked into the encoding -> NOT wildcarded now.
    assert policy.allows_type(_fake_idaapi.o_imm) is False
    # Address-bearing operands still get wildcarded.
    assert policy.allows_type(_fake_idaapi.o_mem) is True
    assert policy.allows_type(_fake_idaapi.o_far) is True
    assert policy.allows_type(_fake_idaapi.o_near) is True
    # An x86 register-class kind is still present.
    assert policy.allows_type(_fake_idaapi.o_idpspec5) is True  # XMM
    # o_reg was never wildcardable.
    assert policy.allows_type(_fake_idaapi.o_reg) is False


def test_default_generic_still_wildcards_immediates():
    # The exclusion is x86-specific: the generic policy keeps IMM so the
    # behavior change is scoped to for_x86.
    policy = sm.WildcardPolicy.default_generic()
    assert policy.allows_type(_fake_idaapi.o_imm) is True


# ===========================================================================
# is_unique early-bail (headline delta #2)
# ===========================================================================
class _CountingSearch:
    """Fake idaapi.bin_search returning a scripted sequence of hits.

    ``hits`` is the sequence of match addresses to yield; after they are
    exhausted it returns BADADDR. ``calls`` records how many times it ran so a
    test can prove the loop bailed early instead of enumerating everything.
    """

    def __init__(self, hits, badaddr):
        self._hits = list(hits)
        self._badaddr = badaddr
        self.calls = 0

    def __call__(self, ea, max_ea, binary, flags):
        self.calls += 1
        if self._hits:
            return self._hits.pop(0), None
        return self._badaddr, None


class _InfiniteSearch:
    """Fake bin_search that always returns a fresh, never-BADADDR hit."""

    def __init__(self):
        self.calls = 0

    def __call__(self, ea, max_ea, binary, flags):
        self.calls += 1
        return 0x1000 + self.calls * 0x10, None


def test_is_unique_bails_at_second_match():
    # A pattern that would match "millions" of positions must NOT be fully
    # enumerated: is_unique passes skip_more_than_one=True so bin_search is
    # called exactly twice (first hit, second hit -> bail).
    search = _InfiniteSearch()
    _fake_idaapi.bin_search = search
    try:
        assert sm.SignatureSearcher.is_unique("11 22 ?? 44") is False
    finally:
        _fake_idaapi.bin_search = lambda ea, max_ea, binary, flags: (
            _fake_idaapi.BADADDR,
            None,
        )
    assert search.calls == 2, f"expected bail at 2, got {search.calls} calls"


def test_is_unique_true_for_single_match():
    search = _CountingSearch([0x1000], _fake_idaapi.BADADDR)
    _fake_idaapi.bin_search = search
    try:
        assert sm.SignatureSearcher.is_unique("11 22 33 44") is True
    finally:
        _fake_idaapi.bin_search = lambda ea, max_ea, binary, flags: (
            _fake_idaapi.BADADDR,
            None,
        )
    # 1 hit + 1 BADADDR terminator.
    assert search.calls == 2


def test_is_unique_false_for_zero_matches():
    search = _CountingSearch([], _fake_idaapi.BADADDR)
    _fake_idaapi.bin_search = search
    try:
        assert sm.SignatureSearcher.is_unique("11 22 33 44") is False
    finally:
        _fake_idaapi.bin_search = lambda ea, max_ea, binary, flags: (
            _fake_idaapi.BADADDR,
            None,
        )
    assert search.calls == 1


def test_find_all_without_skip_enumerates_every_match():
    # Contrast: plain find_all (skip_more_than_one=False) enumerates all hits.
    search = _CountingSearch([0x10, 0x20, 0x30], _fake_idaapi.BADADDR)
    _fake_idaapi.bin_search = search
    try:
        matches = sm.SignatureSearcher.find_all("11 22 33 44")
    finally:
        _fake_idaapi.bin_search = lambda ea, max_ea, binary, flags: (
            _fake_idaapi.BADADDR,
            None,
        )
    assert [int(x) for x in matches] == [0x10, 0x20, 0x30]
    assert search.calls == 4  # 3 hits + BADADDR terminator


def test_count_matches_delegates_to_find_all():
    search = _CountingSearch([0x10, 0x20], _fake_idaapi.BADADDR)
    _fake_idaapi.bin_search = search
    try:
        assert sm.SignatureSearcher.count_matches("11 22 33 44") == 2
    finally:
        _fake_idaapi.bin_search = lambda ea, max_ea, binary, flags: (
            _fake_idaapi.BADADDR,
            None,
        )


# ===========================================================================
# GeneratedSignature ordering by (length, wildcard_count)
# ===========================================================================
def _sig(*pairs) -> "sm.Signature":
    return sm.Signature(sm.SignatureByte(v, w) for v, w in pairs)


def test_generated_signature_orders_by_length_then_wildcards():
    shorter = sm.GeneratedSignature(_sig((0x11, False), (0x22, False)))
    longer = sm.GeneratedSignature(
        _sig((0x11, False), (0x22, False), (0x33, False))
    )
    # Shorter signature wins outright.
    assert shorter < longer
    assert sorted([longer, shorter]) == [shorter, longer]

    # Equal length -> fewer wildcards wins (more specific).
    few_wild = sm.GeneratedSignature(
        _sig((0x11, False), (0x22, False), (0x33, True))
    )
    many_wild = sm.GeneratedSignature(
        _sig((0x11, False), (0x22, True), (0x33, True))
    )
    assert few_wild < many_wild
    assert sorted([many_wild, few_wild]) == [few_wild, many_wild]


def test_generated_signature_has_v18_fields():
    gs = sm.GeneratedSignature(_sig((0x11, False)))
    # New-in-1.8.0 fields with backward-compatible defaults.
    assert gs.status == sm.GenerationStatus.UNIQUE
    assert gs.match_count is None
    assert gs.address is None


# ===========================================================================
# version / public surface
# ===========================================================================
def test_version_is_1_8_0():
    assert sm.__version__ == "1.8.0"


def test_v18_public_surface_present():
    for name in (
        "MinimalFunctionSignatureGenerator",
        "GenerationStatus",
        "ProgressReporter",
        "count_matches",
        "find_all_offsets",
    ):
        assert hasattr(sm, name) or hasattr(sm.SignatureSearcher, name), name
    assert hasattr(sm.SignatureMaker, "make_function_signature")

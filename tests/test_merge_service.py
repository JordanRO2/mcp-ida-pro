"""IDA-free unit tests for the merge-back reconciliation core.

Loads ``application/services/merge_service.py`` in isolation via importlib so
nothing imports the IDA-dependent ``ida_pro_mcp.ida_mcp`` package (which hangs
without idalib). merge_service.py has no top-level IDA imports, so it loads as
pure Python.
"""

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_MS_PATH = os.path.join(
    _HERE,
    "..",
    "src",
    "ida_pro_mcp",
    "ida_mcp",
    "application",
    "services",
    "merge_service.py",
)

_spec = importlib.util.spec_from_file_location("_merge_service_under_test", _MS_PATH)
ms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ms)


def _prov(sha="abc", base=0):
    return {"input_sha256": sha, "imagebase": base, "ida_version": "9.0"}


def _record(names=None, comments=None, prototypes=None, sha="abc", base=0):
    return {
        "provenance": _prov(sha, base),
        "names": names or [],
        "comments": comments or [],
        "prototypes": prototypes or [],
    }


def test_subtract_baseline_drops_unedited_and_keeps_edits():
    # Baseline (pristine re-analysis) has .init_proc at 0x1000.
    baseline = _record(names=[{"ea": "0x1000", "name": ".init_proc", "kind": "func"}])
    # Copy A renamed it; copy B left it as the pristine name.
    a = _record(names=[{"ea": "0x1000", "name": "RENAMED_A", "kind": "func"}])
    b = _record(names=[{"ea": "0x1000", "name": ".init_proc", "kind": "func"}])
    out = ms.subtract_baseline({"a": a, "b": b}, baseline)
    # A's edit survives; B's unchanged name is dropped (== baseline).
    assert [n["name"] for n in out["a"]["names"]] == ["RENAMED_A"]
    assert out["b"]["names"] == []
    # And the reconciliation now sees a clean singleton (no false conflict).
    plan, conflicts = ms.build_plan(out, policy="manual")
    assert conflicts == []
    assert plan["names"]["0x1000"]["name"] == "RENAMED_A"


# --------------------------------------------------------------------------
# enumerate_sessions
# --------------------------------------------------------------------------


def test_enumerate_from_path_set():
    p2s = {"/bins/crackme.elf": {"A", "B"}}
    assert ms.enumerate_sessions(p2s, path="/bins/crackme.elf") == ["A", "B"]


def test_enumerate_by_basename():
    p2s = {"/abs/one/crackme.elf": {"A", "B"}}
    assert ms.enumerate_sessions(p2s, path="crackme.elf") == ["A", "B"]


def test_enumerate_sources_override():
    p2s = {"/bins/x": {"A", "B", "C"}}
    assert ms.enumerate_sessions(p2s, path="/bins/x", sources=["C", "A"]) == ["A", "C"]


def test_enumerate_known_filter():
    p2s = {"/bins/x": {"A", "B", "C"}}
    assert ms.enumerate_sessions(p2s, path="/bins/x", known={"A", "C"}) == ["A", "C"]


# --------------------------------------------------------------------------
# check_provenance
# --------------------------------------------------------------------------


def test_provenance_match_returns_none():
    recs = {"A": _record(sha="abc"), "B": _record(sha="abc")}
    assert ms.check_provenance(recs) is None


def test_provenance_sha_mismatch_aborts():
    recs = {"A": _record(sha="abc"), "B": _record(sha="def")}
    err = ms.check_provenance(recs)
    assert err and "provenance mismatch" in err


def test_provenance_imagebase_mismatch_aborts():
    recs = {"A": _record(base=0), "B": _record(base=0x1000)}
    assert ms.check_provenance(recs) is not None


# --------------------------------------------------------------------------
# build_plan - agreements / singletons
# --------------------------------------------------------------------------


def test_singleton_name_auto_merges():
    a = _record(names=[{"ea": "0x1000", "name": "foo", "kind": "func"}])
    b = _record()
    plan, conflicts = ms.build_plan({"A": a, "B": b}, order=["A", "B"])
    assert conflicts == []
    assert plan["names"]["0x1000"]["name"] == "foo"


def test_agreement_no_conflict():
    a = _record(names=[{"ea": "0x2000", "name": "same", "kind": "func"}])
    b = _record(names=[{"ea": "0x2000", "name": "same", "kind": "func"}])
    plan, conflicts = ms.build_plan({"A": a, "B": b}, order=["A", "B"])
    assert conflicts == []
    assert plan["names"]["0x2000"]["name"] == "same"


def test_singleton_comment_and_prototype():
    a = _record(
        comments=[{"ea": "0x1004", "scope": "line", "regular": "hi", "repeatable": None}],
    )
    b = _record(prototypes=[{"ea": "0x1000", "type": "int foo()", "kind": "func"}])
    plan, conflicts = ms.build_plan({"A": a, "B": b}, order=["A", "B"])
    assert conflicts == []
    assert plan["comments"]["0x1004|line"]["regular"] == "hi"
    assert plan["prototypes"]["0x1000"]["type"] == "int foo()"


# --------------------------------------------------------------------------
# build_plan - conflicts + policy
# --------------------------------------------------------------------------


def _conflict_records():
    a = _record(names=[{"ea": "0x1000", "name": "foo", "kind": "func"}])
    b = _record(names=[{"ea": "0x1000", "name": "bar", "kind": "func"}])
    return {"A": a, "B": b}


def test_conflict_manual_leaves_unresolved():
    plan, conflicts = ms.build_plan(_conflict_records(), policy="manual", order=["A", "B"])
    assert "0x1000" not in plan["names"]
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["resolved"] is None
    assert set(c["candidates"].values()) == {"foo", "bar"}


def test_conflict_prefer_resolves():
    plan, conflicts = ms.build_plan(
        _conflict_records(), policy="prefer", prefer="A", order=["A", "B"]
    )
    assert plan["names"]["0x1000"]["name"] == "foo"
    assert conflicts[0]["resolved"] == "foo"


def test_conflict_first_and_last():
    plan_first, _ = ms.build_plan(_conflict_records(), policy="first", order=["A", "B"])
    plan_last, _ = ms.build_plan(_conflict_records(), policy="last", order=["A", "B"])
    assert plan_first["names"]["0x1000"]["name"] == "foo"
    assert plan_last["names"]["0x1000"]["name"] == "bar"


def test_prefer_absent_leaves_unresolved():
    # prefer points at a session that has no value for the key -> unresolved
    recs = _conflict_records()
    plan, conflicts = ms.build_plan(recs, policy="prefer", prefer="ZZZ", order=["A", "B"])
    assert "0x1000" not in plan["names"]
    assert conflicts[0]["resolved"] is None


def test_fields_filter_limits_classes():
    a = _record(
        names=[{"ea": "0x1", "name": "n", "kind": "func"}],
        comments=[{"ea": "0x2", "scope": "line", "regular": "c", "repeatable": None}],
    )
    plan, _ = ms.build_plan({"A": a}, fields=["names"], order=["A"])
    assert "0x1" in plan["names"]
    assert "comments" not in plan


# --------------------------------------------------------------------------
# plan_to_record
# --------------------------------------------------------------------------


def test_plan_to_record_shape():
    a = _record(
        names=[{"ea": "0x1000", "name": "foo", "kind": "func"}],
        comments=[{"ea": "0x1004", "scope": "line", "regular": "hi", "repeatable": None}],
        prototypes=[{"ea": "0x1000", "type": "int foo()", "kind": "func"}],
    )
    plan, _ = ms.build_plan({"A": a}, order=["A"])
    rec = ms.plan_to_record(plan)
    assert {"names", "comments", "prototypes"} == set(rec)
    assert rec["names"][0]["name"] == "foo"
    assert rec["comments"][0]["regular"] == "hi"
    assert rec["prototypes"][0]["type"] == "int foo()"
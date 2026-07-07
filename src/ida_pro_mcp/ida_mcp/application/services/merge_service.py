"""Annotation merge-back service.

Consolidates the divergent *user* annotations of N open copies of ONE binary
into a single canonical record, and provides the IDA-side primitives that
harvest / write those annotations. Two responsibilities live here:

* **Pure reconciliation** (``enumerate_sessions``, ``check_provenance``,
  ``build_plan``, ``plan_to_record``) — IDA-free, deterministic, unit-testable
  without an IDA install. The supervisor drives these to turn N exported
  records into one merged record under a conflict policy, with a ``dry_run``
  preview.

* **IDA-side extraction / application** (``MergeService.export_annotations`` /
  ``MergeService.apply_annotations``) — read this copy's user annotations
  EA-keyed (names via ``has_user_name``/``get_name``, comments via
  ``get_cmt``/``get_func_cmt``, prototypes/types via ``get_type``), or write an
  already-resolved record into the active database. Every ``idaapi``/``ida_*``
  import is lazy so this module imports cleanly with no IDA present (required
  for the IDA-free reconciliation tests and for ``py_compile``).

Annotation-extraction helpers deliberately live here (per task scope), never in
``utils.py``.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

# Annotation classes understood by the merge planner.
ALL_FIELDS = ("names", "comments", "prototypes")


# ============================================================================
# Pure reconciliation (IDA-free)
# ============================================================================


def enumerate_sessions(
    path_to_session: dict[str, "set[str] | list[str]"],
    path: str = "",
    sources: Optional[list[str]] = None,
    known: Optional["set[str] | list[str]"] = None,
) -> list[str]:
    """Resolve which session ids participate in a merge.

    ``sources`` (explicit ids) wins when provided. Otherwise every session id
    registered for ``path`` in ``path_to_session`` (the multi-valued set) is
    collected, matching by exact key, resolved absolute path, or basename so a
    caller can pass either the original binary path or the value used at open
    time. When ``known`` is given the result is intersected with it so stale /
    closed sessions are dropped (reachability). Returns a sorted list for
    deterministic ordering.
    """
    if sources:
        ids: set[str] = set(sources)
    else:
        ids = set()
        if path:
            try:
                from pathlib import Path

                norm = str(Path(path).resolve())
                base = Path(path).name
            except Exception:
                norm, base = path, path
            for key, sset in path_to_session.items():
                key_base = key.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                if key == path or key == norm or key_base == base:
                    ids |= set(sset)
    if known is not None:
        ids &= set(known)
    return sorted(ids)


def _provenance_signature(record: dict) -> tuple:
    prov = record.get("provenance", {}) or {}
    return (prov.get("input_sha256"), prov.get("imagebase"))


def check_provenance(records: dict[str, dict]) -> Optional[str]:
    """Return an error string if the copies are not the same binary, else None.

    Refuses to merge when the exported records disagree on input SHA-256 or
    image base — merging EA-keyed annotations across different binaries (or
    differently-rebased images) would corrupt the result.
    """
    sigs = {sid: _provenance_signature(r) for sid, r in records.items()}
    distinct = set(sigs.values())
    if len(distinct) <= 1:
        return None
    return (
        "Refusing to merge: copies differ in input_sha256/imagebase "
        f"(provenance mismatch across sessions {sorted(records)}): {sorted(distinct)}"
    )


def _index_record(record: dict, field: str) -> dict[str, dict]:
    """Index one record's ``field`` list into {key -> entry}."""
    out: dict[str, dict] = {}
    if field == "names":
        for n in record.get("names", []) or []:
            out[str(n.get("ea"))] = {
                "ea": n.get("ea"),
                "name": n.get("name"),
                "kind": n.get("kind", "data"),
            }
    elif field == "comments":
        for c in record.get("comments", []) or []:
            scope = c.get("scope", "line")
            out[f"{c.get('ea')}|{scope}"] = {
                "ea": c.get("ea"),
                "scope": scope,
                "regular": c.get("regular"),
                "repeatable": c.get("repeatable"),
            }
    elif field == "prototypes":
        for p in record.get("prototypes", []) or []:
            out[str(p.get("ea"))] = {
                "ea": p.get("ea"),
                "type": p.get("type"),
                "kind": p.get("kind", "func"),
            }
    return out


def _signature(field: str, entry: dict):
    """A hashable, comparable value used for agreement / conflict detection."""
    if field == "names":
        return entry.get("name")
    if field == "comments":
        return (entry.get("regular") or "", entry.get("repeatable") or "")
    if field == "prototypes":
        return entry.get("type")
    return None


def _is_empty(field: str, sig) -> bool:
    if field == "comments":
        return sig == ("", "") or sig is None
    return sig is None or sig == ""


def build_plan(
    records: dict[str, dict],
    fields: Optional[list[str]] = None,
    policy: str = "manual",
    prefer: str = "",
    order: Optional[list[str]] = None,
) -> tuple[dict[str, dict], list[dict]]:
    """Reconcile N exported records into a merge plan + conflict report.

    For every (field, key) the non-empty values across sessions are collected:

    * all sessions agree, or exactly one session has a value (singleton) ->
      auto-resolved into the plan.
    * two or more distinct non-empty values -> a CONFLICT, resolved by
      ``policy``:

      - ``manual``: left unresolved (``resolved`` is None) and NOT written;
        only agreements/singletons are applied.
      - ``first`` / ``last``: take the value from the earliest / latest session
        in ``order`` that has a non-empty value (open order, IDA does not
        timestamp individual edits).
      - ``prefer``: take ``prefer`` session's value if it has one, else leave
        unresolved.

    Returns ``(plan, conflicts)`` where ``plan`` is
    ``{field: {key: resolved_entry}}`` and ``conflicts`` is a list of dicts with
    ``field/key/ea/candidates/resolved``.
    """
    fields = list(fields) if fields else list(ALL_FIELDS)
    sess_ids = order if order is not None else sorted(records)
    # keep only sessions that actually have records, preserve requested order
    sess_ids = [sid for sid in sess_ids if sid in records]

    plan: dict[str, dict] = {f: {} for f in fields}
    conflicts: list[dict] = []

    for field in fields:
        indexed = {sid: _index_record(records[sid], field) for sid in sess_ids}
        all_keys: set[str] = set()
        for m in indexed.values():
            all_keys |= set(m.keys())

        for key in sorted(all_keys):
            # collect non-empty candidates {sid: entry}
            candidates: dict[str, dict] = {}
            sigs: dict[str, Any] = {}
            for sid in sess_ids:
                entry = indexed[sid].get(key)
                if entry is None:
                    continue
                sig = _signature(field, entry)
                if _is_empty(field, sig):
                    continue
                candidates[sid] = entry
                sigs[sid] = sig

            if not candidates:
                continue

            distinct = set(sigs.values())
            if len(distinct) == 1:
                # agreement or singleton: take the first contributing session
                first_sid = next(sid for sid in sess_ids if sid in candidates)
                plan[field][key] = dict(candidates[first_sid])
                continue

            # ---- conflict ----
            resolved_entry = None
            if policy == "prefer":
                if prefer in candidates:
                    resolved_entry = dict(candidates[prefer])
            elif policy == "first":
                first_sid = next(sid for sid in sess_ids if sid in candidates)
                resolved_entry = dict(candidates[first_sid])
            elif policy == "last":
                last_sid = next(
                    sid for sid in reversed(sess_ids) if sid in candidates
                )
                resolved_entry = dict(candidates[last_sid])
            # policy == "manual" -> resolved_entry stays None

            if resolved_entry is not None:
                plan[field][key] = resolved_entry

            conflicts.append(
                {
                    "field": field,
                    "key": key,
                    "ea": candidates[next(iter(candidates))].get("ea"),
                    "candidates": {sid: _signature(field, e) for sid, e in candidates.items()},
                    "resolved": _signature(field, resolved_entry) if resolved_entry else None,
                }
            )

    return plan, conflicts


def plan_to_record(plan: dict[str, dict]) -> dict:
    """Turn a resolved plan back into an apply-able annotation record."""
    return {
        "names": list(plan.get("names", {}).values()),
        "comments": list(plan.get("comments", {}).values()),
        "prototypes": list(plan.get("prototypes", {}).values()),
    }


def subtract_baseline(
    records: dict[str, dict], baseline: dict
) -> dict[str, dict]:
    """Drop annotations that are unchanged from a pristine ``baseline`` record.

    Auto-analysis / ELF symbol names (e.g. ``.init_proc``) are reported as user
    annotations by every copy, so without a baseline they look like conflicting
    edits. By subtracting the pristine baseline, each copy keeps ONLY its real
    edits, so unedited copies contribute nothing at those addresses and a
    genuine same-address divergence is the only thing that becomes a conflict.
    """
    base_idx = {f: _index_record(baseline, f) for f in ALL_FIELDS}
    out: dict[str, dict] = {}
    for sid, rec in records.items():
        newrec: dict[str, Any] = {"provenance": rec.get("provenance", {})}
        for field in ALL_FIELDS:
            kept = []
            for key, entry in _index_record(rec, field).items():
                base_entry = base_idx[field].get(key)
                if base_entry is not None and _signature(field, base_entry) == _signature(field, entry):
                    continue  # identical to pristine baseline -> not an edit
                kept.append(entry)
            newrec[field] = kept
        out[sid] = newrec
    return out


# ============================================================================
# IDA-side extraction / application
# ============================================================================


def _parse_ea(ea: "int | str") -> int:
    if isinstance(ea, int):
        return ea
    s = str(ea).strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 0)


class MergeService:
    """Read/write user annotations against the currently-active IDA database.

    Instances are stateless; every IDA symbol is imported lazily inside the
    method that needs it so the module stays importable without IDA.
    """

    # -- provenance -------------------------------------------------------

    def provenance(self) -> dict:
        import idaapi
        import ida_nalt

        path = ida_nalt.get_input_file_path() or ""
        sha = "unavailable"
        try:
            if path:
                with open(path, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            sha = "unavailable"
        return {
            "input_path": path,
            "input_sha256": sha,
            "imagebase": int(idaapi.get_imagebase()),
            "ida_version": idaapi.get_kernel_version(),
        }

    # -- names ------------------------------------------------------------

    @staticmethod
    def _has_user_name(ea: int) -> bool:
        import ida_bytes

        try:
            return bool(ida_bytes.has_user_name(ida_bytes.get_flags(ea)))
        except Exception:
            return False

    def _iter_user_names(self):
        import idautils
        import idaapi

        for ea, name in idautils.Names():
            if not name or not self._has_user_name(ea):
                continue
            fn = idaapi.get_func(ea)
            kind = "func" if (fn is not None and fn.start_ea == ea) else "data"
            yield ea, name, kind

    # -- export -----------------------------------------------------------

    def export_annotations(
        self,
        funcs: Optional[list[str]] = None,
        include_types: bool = True,
    ) -> dict:
        """Dump THIS copy's user annotations EA-keyed for merge-back.

        Returns a record with ``provenance`` plus ``names`` / ``comments`` /
        ``prototypes`` lists. ``funcs`` limits the per-function comment /
        prototype walk to the given function entry addresses (default: all
        functions); global user names are always exported.
        """
        import idautils
        import idaapi
        import ida_bytes
        import idc

        record: dict[str, Any] = {
            "provenance": self.provenance(),
            "names": [],
            "comments": [],
            "prototypes": [],
        }

        data_eas: list[int] = []
        for ea, name, kind in self._iter_user_names():
            record["names"].append({"ea": hex(ea), "name": name, "kind": kind})
            if kind == "data":
                data_eas.append(ea)

        # function-scoped comments + prototypes
        if funcs:
            func_eas = []
            for f in funcs:
                try:
                    func_eas.append(_parse_ea(f))
                except Exception:
                    continue
        else:
            func_eas = list(idautils.Functions())

        for ea in func_eas:
            fn = idaapi.get_func(ea)
            if fn is None:
                continue
            start = fn.start_ea

            func_reg = idc.get_func_cmt(start, False) or None
            func_rpt = idc.get_func_cmt(start, True) or None
            if func_reg or func_rpt:
                record["comments"].append(
                    {"ea": hex(start), "scope": "func", "regular": func_reg, "repeatable": func_rpt}
                )

            if include_types:
                proto = idc.get_type(start) or None
                if proto:
                    record["prototypes"].append({"ea": hex(start), "type": proto, "kind": "func"})

            for h in idautils.Heads(fn.start_ea, fn.end_ea):
                try:
                    if not ida_bytes.has_cmt(ida_bytes.get_flags(h)):
                        continue
                except Exception:
                    continue
                reg = idc.get_cmt(h, False) or None
                rpt = idc.get_cmt(h, True) or None
                if reg or rpt:
                    record["comments"].append(
                        {"ea": hex(h), "scope": "line", "regular": reg, "repeatable": rpt}
                    )

        # global data types for user-named data
        if include_types:
            for ea in data_eas:
                t = idc.get_type(ea) or None
                if t:
                    record["prototypes"].append({"ea": hex(ea), "type": t, "kind": "data"})

        return record

    # -- apply ------------------------------------------------------------

    def apply_annotations(self, record: dict) -> dict:
        """Write an already conflict-resolved record into the active database.

        Delegates to raw IDA primitives (``set_name`` / ``set_cmt`` /
        ``set_func_cmt`` / ``SetType``). Best-effort per item; per-item failures
        are collected in ``errors`` rather than aborting the whole apply.
        """
        import ida_name
        import idc

        summary = {"names": 0, "comments": 0, "prototypes": 0, "errors": []}

        for n in record.get("names", []) or []:
            name = n.get("name")
            if not name:
                continue
            try:
                ea = _parse_ea(n.get("ea"))
                if ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_FORCE):
                    summary["names"] += 1
                else:
                    summary["errors"].append(f"set_name failed at {n.get('ea')} -> {name}")
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"name {n.get('ea')}: {e}")

        for c in record.get("comments", []) or []:
            scope = c.get("scope", "line")
            reg = c.get("regular")
            rpt = c.get("repeatable")
            try:
                ea = _parse_ea(c.get("ea"))
                wrote = False
                if scope == "func":
                    if reg:
                        idc.set_func_cmt(ea, reg, False)
                        wrote = True
                    if rpt:
                        idc.set_func_cmt(ea, rpt, True)
                        wrote = True
                else:
                    if reg:
                        idc.set_cmt(ea, reg, False)
                        wrote = True
                    if rpt:
                        idc.set_cmt(ea, rpt, True)
                        wrote = True
                if wrote:
                    summary["comments"] += 1
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"comment {c.get('ea')}: {e}")

        for p in record.get("prototypes", []) or []:
            type_str = p.get("type")
            if not type_str:
                continue
            try:
                ea = _parse_ea(p.get("ea"))
                ok, err = self._apply_type(ea, str(type_str), p.get("kind", "func"))
                if ok:
                    summary["prototypes"] += 1
                elif err:
                    summary["errors"].append(f"type {p.get('ea')}: {err}")
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"type {p.get('ea')}: {e}")

        return summary

    @staticmethod
    def _apply_type(ea: int, type_str: str, kind: str) -> tuple[bool, Optional[str]]:
        """Best-effort apply of an exported (usually nameless) type string.

        ``idc.get_type`` yields a *nameless* declaration (e.g.
        ``int __fastcall(int a)``) which ``SetType`` rejects for functions.
        Try, in order: direct SetType; for functions, inject a throwaway
        declarator name before the first top-level ``(``; finally parse the
        nameless type via ``parse_decl`` and ``apply_tinfo`` (works for
        data/arrays/scalars). The injected name is only used for parsing — the
        symbol keeps its own name (applied separately).
        """
        import idc
        import ida_typeinf

        t = type_str.strip()
        if not t:
            return False, "empty type"
        decl = t if t.endswith(";") else t + ";"

        try:
            if idc.SetType(ea, decl):
                return True, None
        except Exception:  # noqa: BLE001
            pass

        if kind == "func":
            i = t.find("(")
            if i != -1:
                named = f"{t[:i]} __merge_proto{t[i:]}"
                named = named if named.endswith(";") else named + ";"
                try:
                    if idc.SetType(ea, named):
                        return True, None
                except Exception:  # noqa: BLE001
                    pass

        try:
            tif = ida_typeinf.tinfo_t()
            flags = getattr(ida_typeinf, "PT_SIL", 0) | getattr(ida_typeinf, "PT_TYP", 0)
            ida_typeinf.parse_decl(tif, None, decl, flags)
            if not tif.empty() and ida_typeinf.apply_tinfo(
                ea, tif, ida_typeinf.TINFO_DEFINITE
            ):
                return True, None
        except Exception as e:  # noqa: BLE001
            return False, str(e)

        return False, f"could not apply type {t!r}"
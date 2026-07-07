# Multi-process supervisor, N-copies parallelism & unified endpoint

This fork adds a **multi-process idalib supervisor** so that several agents can
analyze the **same binary in parallel**, plus a **unified MCP endpoint** that
transparently routes to your live IDA GUI *and* to headless worker copies —
started automatically when you open IDA, with zero manual steps.

It is a port and extension of upstream's supervisor work, adapted to this fork's
DDD layout, with an **N-copies** model (multiple private copies of one binary),
an **annotation merge-back**, **GUI adoption**, and a set of robustness/tool
fixes. See "What changed" at the bottom for the commit-level list.

---

## Why a supervisor at all

IDA's kernel is **single-threaded**: every database mutation runs on one main
thread via `execute_sync(MFF_WRITE)`, and the SDK is not thread-safe. So a
single IDB can never be analyzed in parallel — this is an IDA constraint, not a
wrapper limitation. The only way to get real parallelism is **one process per
IDB**.

IDA ships two runtimes:

- **GUI (`idaq`)** — the interactive window you watch. Inherently a single
  process / single database.
- **`idalib`** — the headless, embeddable library. You can run many of them.

The supervisor unifies both behind **one MCP endpoint**: it adopts your running
GUI *and* spawns headless `idalib` workers, routing each request to the right
one.

---

## Architecture

```
                          ┌──────────────────────────────┐
   MCP client  ─────────► │   SUPERVISOR (idalib-mcp)     │  ◄── the ONE endpoint
   (Claude, Cursor, …)    │   transport + router          │      (default :8745)
                          │   imports NO idapro           │
                          └───────────────┬──────────────┘
                             routes by injected database=<session_id>
             ┌───────────────────────────┼───────────────────────────┐
             ▼                           ▼                           ▼
     adopt your live GUI          headless worker #1          headless worker #2
     (backend="gui",              (own process, own           (own process, own
      routes to idaq :13337,       PRIVATE copy of the         PRIVATE copy of the
      forwards its auth token)     binary/IDB)                 binary/IDB)
```

- The **supervisor** is a pure transport/router. It imports no `idapro`
  (verified by test), spawns `python -m ida_pro_mcp.idalib_server` workers, and
  forwards MCP `tools/call` to the owning session over stdlib `http.client`
  JSON-RPC.
- **Workers** (`idalib_server.py`) are re-roled: each owns exactly one idalib
  database and serves MCP on its own ephemeral port.
- **GUI adoption**: the GUI plugin registers itself in a filesystem *discovery
  registry*; the supervisor discovers and adopts it so tools can run on the
  database you are looking at.

Routing key: every worker tool gets an injected **`database`** argument (a
`session_id`). The supervisor pops it and forwards to that session. It is
**optional** — see *Drop-in* below.

---

## N-copies: multiple private copies of one binary

`idb_open(path)` with an empty `preferred_session_id` **always mints a fresh
worker** with its own **private copy** of the binary. Opening the same binary
twice gives **two workers, two PIDs, two IDBs** — real parallelism on one
binary.

Why private copies are mandatory: two `idalib` processes opening the *same*
`.i64`/binary contend for the database lock (the second fails with
`open_rc=4`, "Database initialization failed"). Each fresh worker therefore
copies the binary/`.i64` into a per-session scratch dir and opens *that*, so:

- no lock contention,
- each copy's annotations (renames/comments/types) are isolated,
- cleanup is scoped to the scratch dir and never touches your original.

**Sharing (opt-in):** pass an existing `session_id` as `preferred_session_id`
to *share* that live worker/IDB instead of spawning a new one (collaborate on
one database).

Routing (`session_id -> host:port`) and reaping (process-handle-keyed) are
inherently N-copies-safe; the path→session index is many-valued
(`dict[str, set[str]]`) and used only for grouping / the merge seam, never for
auto-dedup.

---

## Merge-back: consolidate parallel work

When N agents each edit their own copy, `idb_merge` reconciles their divergent
annotations into a single canonical IDB — the "pass the parallel edits back to
a main database" step.

1. Enumerate the sessions for a binary and **export** each copy's user
   annotations (names via `has_user_name`, comments via `get_cmt`/`get_func_cmt`,
   prototypes/types), EA-keyed.
2. Open one **pristine baseline** (a fresh re-analysis) and **subtract** it, so
   unchanged auto-analysis / ELF symbol names are not mistaken for edits — only
   real edits survive, and a genuine same-address divergence is the only
   conflict.
3. **Reconcile** under a conflict policy (`manual` | `first` | `last` |
   `prefer`) with a `dry_run` preview + conflict report.
4. **Apply** the merged record to a target copy and **snapshot** a compressed
   `.i64` (`idb_snapshot`, `DBFL_COMP`, no kill).

Pure reconciliation (`enumerate_sessions`, `check_provenance`, `build_plan`,
`subtract_baseline`, `plan_to_record`) is IDA-free and unit-tested; the IDA-side
extraction/apply lives in `MergeService` and the worker tools.

---

## Unified, automatic, headless, single

- **Automatic**: on server start the GUI plugin registers itself in discovery
  and **auto-launches the supervisor** if one is not already running. Open IDA →
  everything is up. No manual command.
- **Single & shared**: the plugin first checks `127.0.0.1:8745`; if a supervisor
  is already listening it does **not** start another. N open IDA instances share
  **one** supervisor that adopts all of them. At most one, always.
- **Headless**: the supervisor and its workers are spawned with
  `CREATE_NO_WINDOW` on Windows — no console windows pop up.
- **Persistent**: the supervisor is a shared singleton and stays running after
  IDA closes; you stop it manually. (An optional `--parent-pid` makes it exit
  with a chosen process, off by default.)
- **Auth passthrough**: if your GUI enforces a stable auth token, the plugin
  registers that token in discovery and the supervisor forwards it
  (`Authorization: Bearer …`) when routing to the adopted GUI, so requests are
  not rejected with 401.
- **Drop-in for tools & skills**: the injected `database` argument is
  **optional**. When exactly one session is open, the router defaults to it, so
  tools and skills that never pass `database` work unchanged. Pass `database`
  only to disambiguate when several parallel copies are open.

The launch spec (which Python + source path the spawned workers need) is written
to `{ida_user_dir}/mcp/supervisor.json` at install time.

---

## Tools

Management tools (handled by the supervisor, not forwarded):

- `idb_open(input_path, mode=, preferred_session_id=, …)` — open a copy. `mode`:
  `prefer_headless` (default), `force_headless`, `prefer_gui` (adopt the running
  GUI if present), `force_gui`.
- `idb_list()` — adopted sessions + discovered GUI/worker instances.
- `idb_merge(path=|sources=, into=, policy=, prefer=, fields=, dry_run=, use_baseline=)`
  — consolidate N copies into one canonical `.i64`.

Worker tools used by the merge (also callable directly):

- `export_annotations(funcs=, include_types=)` — dump this copy's user
  annotations EA-keyed.
- `apply_annotations(record)` — write a merged record into this copy.
- `idb_snapshot(path)` — compressed snapshot without killing the live working
  files.

Every other tool (`decompile`, `list_funcs`, `search_text`, `rename`, …) is a
worker tool exposed with the optional injected `database` argument.

---

## How to use

**Install** (captures the Python for the spawned workers):

```
ida-pro-mcp --install         # installs the plugin + writes supervisor.json
```

**Interactive (single database):** just open IDA. The plugin auto-starts the
supervisor and registers your GUI. Point your MCP client at
`http://127.0.0.1:8745/mcp`. Call any tool/skill normally — with one session
open you don't need `database`; work routes to your live GUI and you see the
changes in the window.

**Parallel / multi-agent (same binary):**

```text
idb_open(binary)                 -> session A (own worker/copy)
idb_open(binary)                 -> session B (own worker/copy)   # different agent
decompile(addr, database=A)      # runs on copy A
rename(batch=…, database=B)      # runs on copy B, in parallel
idb_merge(path=binary, into=…)   # consolidate A+B into one .i64
```

Because parallel work happens on **copies**, your original database is never
touched — recommended for heavy or experimental fan-out.

**Config / env:**

- `IDA_MCP_SUPERVISOR_PORT` / `_HOST` / `_PYTHON` — override the endpoint / interpreter.
- `IDA_MCP_NO_SUPERVISOR=1` — do not auto-launch (parallel mode stays manual).
- `IDA_MCP_MAX_WORKERS` (default 4) — max concurrent worker databases; note each
  is a full idalib process (RAM = N × per-IDB footprint).

---

## What changed (commit-level)

- `feat(idalib): multi-process supervisor with N-copies parallelism`
- `feat(idalib): annotation merge-back across N parallel copies`
- `feat(plugin): register GUI instance in discovery for supervisor adoption`
- `feat(plugin): auto-launch one shared supervisor on IDA start`
- `feat(supervisor): default to the sole session when database is omitted`
- `fix(supervisor): forward auth token to adopted GUI + fully headless, persistent single supervisor`

Plus ported upstream backlog features carried in the same branch: `idb_save`
GUI-safe/headless-pack (prevents `.i64` corruption), `@idasync` native
cancellation + `get_tool_deadline`, `search_text` (cancellable rendered-listing
search), `decompile include_addresses`, modify tools
(`force_recompile`/`set_op_type`/`make_data`), `add_bookmark`, `parse_address`
symbol resolution, virtual-space `0x00` reads, sigmaker v1.8.0, zeromcp MCP-spec
fixes, `py_exec_file`, `compat.tinfo_get_udm` (fixes IDA 9.0-SP0 stack-var
ops), `find_bytes` graceful cancellation cursor, `/output` DNS-rebinding guard,
per-database host/port persistence, and an opt-in stable auth token.

The former `--isolated-contexts` model and the `idalib_open/switch/current/…`
context tools have been **removed**; the supervisor's N-copies + `database`
routing replaces them.
```

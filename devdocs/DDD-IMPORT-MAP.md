# DDD Import Map

Foundation phase of the flat -> DDD refactor. Shared infrastructure was moved
into the DDD layers; thin re-export shims were left at the old flat paths so the
not-yet-migrated `api_*.py` tool modules (and the tests) keep importing the old
names unchanged. This table is the reference for the **tool-migration phase**:
rewrite tool/test imports from the old shim path to the new canonical path, then
delete the shim once nothing imports it.

All paths are under the package root `ida_pro_mcp.ida_mcp`.

## Module relocations (old -> canonical)

| Old path (shim kept) | Canonical module | Notes |
|----------------------|------------------|-------|
| `.sync` | `.infrastructure.sync.sync` | `git mv sync.py infrastructure/sync/sync.py` |
| `.http` | `.infrastructure.http.handler` | `git mv http.py infrastructure/http/handler.py` |
| `.compat` | `.infrastructure.compat` | `git mv compat.py infrastructure/compat.py` |
| `.framework` | `.infrastructure.framework` | `git mv framework.py infrastructure/framework.py` |
| `.connection` | `.infrastructure.connection` | `git mv connection.py infrastructure/connection.py` |
| `.trace` | `.infrastructure.trace` | `git mv trace.py infrastructure/trace.py` |
| `.profile` | `.application.profile` | `git mv profile.py application/profile.py` |
| `.utils` | `.utils` (unchanged) | KEPT in place this phase. TypedDicts additionally re-exported via `.domain.entities` / `.domain.value_objects`. |
| `.rpc` | `.rpc` (unchanged) | KEPT at package root (matches x64dbg). |
| `.zeromcp` | `.zeromcp` (unchanged) | KEPT untouched. |

## Symbol -> canonical import path

### sync  (`.infrastructure.sync.sync`)
| Symbol | Canonical import |
|--------|------------------|
| `idasync` | `from ida_pro_mcp.ida_mcp.infrastructure.sync.sync import idasync` |
| `keep_batch` | `...infrastructure.sync.sync import keep_batch` |
| `get_pre_call_batch` | `...infrastructure.sync.sync import get_pre_call_batch` |
| `sync_wrapper` | `...infrastructure.sync.sync import sync_wrapper` |
| `tool_timeout` | `...infrastructure.sync.sync import tool_timeout` |
| `IDAError` | `...infrastructure.sync.sync import IDAError` |
| `IDASyncError` | `...infrastructure.sync.sync import IDASyncError` |
| `CancelledError` | `...infrastructure.sync.sync import CancelledError` |
| `is_window_active` | `...infrastructure.sync.sync import is_window_active` |
| `ida_major`, `ida_minor` | `...infrastructure.sync.sync import ida_major, ida_minor` |

### http  (`.infrastructure.http.handler`)
| Symbol | Canonical import |
|--------|------------------|
| `IdaMcpHttpRequestHandler` | `...infrastructure.http.handler import IdaMcpHttpRequestHandler` |
| `config_json_get` / `config_json_set` | `...infrastructure.http.handler import config_json_get, config_json_set` |
| `handle_enabled_tools` | `...infrastructure.http.handler import handle_enabled_tools` |
| `get_cors_policy` | `...infrastructure.http.handler import get_cors_policy` |
| `DEFAULT_CORS_POLICY` | `...infrastructure.http.handler import DEFAULT_CORS_POLICY` |
| `ORIGINAL_TOOLS` | `...infrastructure.http.handler import ORIGINAL_TOOLS` |

### compat  (`.infrastructure.compat`)
| Symbol | Canonical import |
|--------|------------------|
| module (`from . import compat`) | `from ida_pro_mcp.ida_mcp.infrastructure import compat` |
| `IDA_VERSION`, `IDA_GE_90`, `IDA_GE_85`, `IDA_GE_84` | `...infrastructure.compat import ...` |
| `get_entry_qty`, `get_entry_ordinal`, `get_entry`, `get_entry_name` | `...infrastructure.compat import ...` |
| `get_ordinal_limit` | `...infrastructure.compat import get_ordinal_limit` |
| `inf_get_min_ea`, `inf_get_max_ea`, `inf_get_omin_ea`, `inf_get_omax_ea`, `inf_is_64bit` | `...infrastructure.compat import ...` |
| `get_func_name`, `get_func_prototype` | `...infrastructure.compat import ...` |
| `raw_bin_search`, `make_bytes_searcher`, `guess_tinfo` | `...infrastructure.compat import ...` |

### framework  (`.infrastructure.framework`)
| Symbol | Canonical import |
|--------|------------------|
| `test`, `skip_test`, `run_tests` | `...infrastructure.framework import test, skip_test, run_tests` |
| `TestInfo`, `TestResult`, `TestResults`, `TESTS`, `SkipTest` | `...infrastructure.framework import ...` |
| `optional`, `list_of`, `one_of`, `is_hex_address` | `...infrastructure.framework import ...` |
| `assert_valid_address`, `assert_non_empty`, `assert_is_list`, `assert_has_keys`, `assert_shape`, `assert_typed_dict`, `assert_ok`, `assert_error` | `...infrastructure.framework import ...` |
| `get_any_function`, `get_named_function`, `get_named_address`, `get_string_address_containing`, `get_any_string`, `get_first_segment`, `get_data_address`, `get_unmapped_address`, `get_current_binary_name` | `...infrastructure.framework import ...` |

### connection  (`.infrastructure.connection`)
| Symbol | Canonical import |
|--------|------------------|
| `connection_file_path` | `...infrastructure.connection import connection_file_path` |
| `generate_token` | `...infrastructure.connection import generate_token` |
| `write_connection_file` | `...infrastructure.connection import write_connection_file` |
| `read_connection_file` | `...infrastructure.connection import read_connection_file` |
| `remove_connection_file` | `...infrastructure.connection import remove_connection_file` |
| `tokens_match` | `...infrastructure.connection import tokens_match` |

> NOTE: `connection` is also imported from OUTSIDE the package
> (`ida_pro_mcp/server.py` does `from ida_pro_mcp.ida_mcp import connection`,
> and `ida_pro_mcp/ida_mcp.py` does `from .ida_mcp.connection import ...` /
> `from ida_mcp.connection import ...`). The flat shim `.connection` MUST be kept
> until those external references are updated to `.infrastructure.connection`.

### trace  (`.infrastructure.trace`)
| Symbol | Canonical import |
|--------|------------------|
| `configure_idb` | `...infrastructure.trace import configure_idb` |
| `install_tracer` | `...infrastructure.trace import install_tracer` |
| `shutdown` | `...infrastructure.trace import shutdown` |
| `iter_idb_records` | `...infrastructure.trace import iter_idb_records` |
| `IDB_NETNODE_NAME` | `...infrastructure.trace import IDB_NETNODE_NAME` |

### profile  (`.application.profile`)
| Symbol | Canonical import |
|--------|------------------|
| `parse_profile` | `...application.profile import parse_profile` |
| `load_profile` | `...application.profile import load_profile` |
| `dump_profile` | `...application.profile import dump_profile` |
| `apply_profile` | `...application.profile import apply_profile` |

### Domain TypedDicts (re-exported from `.utils`, canonical path stays `.utils` until migration)

`from ..domain.entities import <Name>` (going-forward path; currently re-exports from `.utils`):

`Metadata, Function, Global, Import, String, Segment, DisassemblyLine, Argument,
StackFrameVariable, DisassemblyFunction, Xref, StructureMember,
StructureDefinition, RegisterValue, ThreadRegisters, Breakpoint,
FunctionAnalysis, BasicBlock, MemoryRead, MemoryPatch, IntRead, IntWrite,
CommentOp, CommentAppendOp, AsmPatchOp, FunctionRename, GlobalRename,
LocalRename, StackRename, RenameBatch, BreakpointOp, BreakpointConditionBase,
StackVarDecl, StackVarDelete, DefineOp, UndefineOp, TypeEdit, EnumMemberUpsert,
EnumUpsert, TypeApplyBatch, StructFieldQuery, XrefQuery, ListQuery,
FunctionQuery, EntityQuery, FuncProfileQuery, AnalyzeBatchQuery, ImportQuery,
TypeInspectQuery, TypeQuery, StructRead`

`from ..domain.value_objects import <Name>`:

`ConvertedNumber, NumberConversion, PatternMatch, CodePattern, InsnPattern,
Page, T`

> The plain helper functions still in `utils` (e.g. `parse_address`,
> `normalize_list_input`, `normalize_dict_list`, `looks_like_address`,
> `get_function`, `get_prototype`, `get_type_by_name`, `paginate`,
> `get_image_size`, etc.) are NOT relocated this phase. Keep importing them via
> `from .utils import ...` (or `from ..utils import ...`). The tool-migration
> phase will decide their final home (likely `domain/services` or
> `application/services`).

## DI container (`.container`)

`ida_pro_mcp.ida_mcp.container` exposes `register_factory(name, factory)`,
`get(name)`, `has(name)`, `reset_container()`, `reset_all()`. The
tool-migration phase registers the real application services / adapters here.

## Shim status (all still present after this phase)

| Old flat path | Still a shim? | Remove when |
|---------------|---------------|-------------|
| `.sync` | yes | all `api_*` / tests import `.infrastructure.sync.sync` |
| `.http` | yes | all consumers import `.infrastructure.http.handler` |
| `.compat` | yes | all `api_*` import `.infrastructure.compat` |
| `.framework` | yes | all tests import `.infrastructure.framework` |
| `.connection` | yes | external `server.py` / `ida_mcp.py` import `.infrastructure.connection` |
| `.trace` | yes | `__init__` / consumers import `.infrastructure.trace` (already done in `__init__`) |
| `.profile` | yes | consumers import `.application.profile` (already done in `__init__`) |
| `.utils` | n/a (real module, not moved) | superseded by `domain/` when TypedDicts relocate |

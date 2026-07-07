"""Headless idalib MCP WORKER.

A worker owns exactly ONE idalib database and serves MCP over its own HTTP
endpoint. The idalib supervisor (ida_pro_mcp.idalib_supervisor) spawns one
worker per session and routes tools/call to it. This module is the per-DB
worker; it is NOT the client-facing entry point anymore (that is the
supervisor).

N-copies model
--------------
IDA/idalib locks a database by its input path: two processes opening the SAME
path concurrently make the second fail ("Database initialization failed",
open_rc=4). To let multiple agents analyze the SAME binary in parallel, each
fresh worker opens a PRIVATE working copy of the binary under
``{scratch}/{session_id}/`` instead of the shared original. This also keeps
per-copy annotations (renames/comments/types) isolated in that copy's own IDB,
which is exactly what divergent parallel analysis requires. Cleanup of a
worker's database is therefore scoped to its own working directory and never
touches the shared original.
"""

import argparse
import logging
import os
import shutil
import signal
import tempfile
import time
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

# idapro must go first to initialize idalib
import idapro

from ida_pro_mcp.ida_mcp import MCP_SERVER, MCP_UNSAFE, IdaMcpHttpRequestHandler
from ida_pro_mcp.ida_mcp.application.profile import apply_profile, load_profile
from ida_pro_mcp.ida_mcp.discovery import register_instance, unregister_instance
from ida_pro_mcp.ida_mcp.interface.tools.core_tools import server_warmup
from ida_pro_mcp.ida_mcp.rpc import set_download_base_url, tool
from ida_pro_mcp.idalib_session_manager import get_session_manager
from ida_pro_mcp.worker_lifecycle import WorkerLifecycle

logger = logging.getLogger(__name__)


class IdalibSessionInfo(TypedDict):
    session_id: str
    input_path: str
    filename: str
    created_at: str
    last_accessed: str
    is_analyzing: bool
    metadata: dict[str, Any]


class IdalibSessionListInfo(IdalibSessionInfo, total=False):
    is_active: bool


class IdalibOpenResult(TypedDict, total=False):
    success: bool
    session: IdalibSessionInfo
    warmup: Optional[dict[str, Any]]
    working_copy: str
    source_path: str
    message: str
    error: str


class IdalibListResult(TypedDict, total=False):
    sessions: list[IdalibSessionListInfo]
    count: int
    error: str


IDB_MANAGEMENT_TOOLS = {
    "idb_open",
    "idb_list",
}


_LIFECYCLE = WorkerLifecycle()
_REGISTERED_PORT: Optional[int] = None
_BOUND_HOST: str = ""
_BOUND_PORT: int = 0
# session_id -> private working directory, so cleanup is scoped per copy.
_SESSION_WORKDIRS: dict[str, str] = {}


def _scratch_root() -> str:
    """Root directory that holds per-session private working copies."""
    root = os.environ.get("IDA_MCP_WORKER_SCRATCH")
    if not root:
        root = os.path.join(tempfile.gettempdir(), "ida-mcp-workers")
    os.makedirs(root, exist_ok=True)
    return root


def _make_private_copy(source: Path, session_id: str) -> Path:
    """Copy `source` into a private per-session dir and return the copy path.

    This is the core N-copies mechanic: it gives this worker its own lockable
    database file so concurrent workers of the same binary do not contend for
    a single DB lock, and so a cleanup here can never delete a sibling copy.
    """
    workdir = os.path.join(_scratch_root(), session_id)
    os.makedirs(workdir, exist_ok=True)
    _SESSION_WORKDIRS[session_id] = workdir
    dst = os.path.join(workdir, source.name)
    # If an existing .i64/.idb sits next to the source, cloning it lets this
    # copy inherit prior analysis instead of re-running it; otherwise copy the
    # raw binary and analyze fresh.
    for ext in (".i64", ".idb"):
        sibling = source.with_suffix(ext)
        if sibling.is_file():
            dst_idb = os.path.join(workdir, sibling.name)
            shutil.copy2(sibling, dst_idb)
            logger.info("Cloned existing IDB for session %s: %s", session_id, dst_idb)
            return Path(dst_idb)
    shutil.copy2(source, dst)
    logger.info("Copied binary for session %s: %s", session_id, dst)
    return Path(dst)


def _cleanup_session_workdir(session_id: str) -> None:
    """Remove a session's private working dir (scoped; never the original)."""
    workdir = _SESSION_WORKDIRS.pop(session_id, None)
    if not workdir:
        return
    try:
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        logger.debug("Failed to remove workdir %s", workdir, exc_info=True)


def _cleanup_all_workdirs() -> None:
    for session_id in list(_SESSION_WORKDIRS):
        _cleanup_session_workdir(session_id)


def _register_in_discovery(
    host: str, port: int, input_path: Path, session_id: Optional[str] = None
) -> None:
    global _REGISTERED_PORT
    try:
        register_instance(
            host=host,
            port=port,
            pid=os.getpid(),
            binary=input_path.name,
            idb_path=str(input_path),
            backend="worker",
            session_id=session_id,
        )
        _REGISTERED_PORT = port
        logger.info(
            "Registered idalib worker in discovery (port %d, session %s)",
            port,
            session_id,
        )
    except Exception:
        logger.exception("Failed to register worker in discovery")


def _deregister_from_discovery() -> None:
    global _REGISTERED_PORT
    if _REGISTERED_PORT is None:
        return
    try:
        unregister_instance(_REGISTERED_PORT)
    except Exception:
        logger.debug("Failed to unregister worker", exc_info=True)
    _REGISTERED_PORT = None


@tool
def idb_open(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    build_caches: Annotated[bool, "Build core caches after open"] = True,
    init_hexrays: Annotated[bool, "Initialize Hex-Rays decompiler after open"] = True,
    idle_ttl_sec: Annotated[
        int,
        "Minimum idle TTL in seconds before the headless worker self-exits.",
    ] = 600,
    preferred_session_id: Annotated[
        str,
        "Session ID minted by the supervisor; also names this copy's private working dir.",
    ] = "",
    private_copy: Annotated[
        bool,
        "Open a private per-session copy of the binary (required for parallel "
        "copies of the same binary). Set False only for single-owner opens.",
    ] = True,
) -> IdalibOpenResult:
    """Open a binary into THIS worker's single database and warm subsystems.

    For N-copies parallelism the binary is copied into a private per-session
    working directory before opening, so multiple workers of the same binary
    never contend for one database lock.
    """

    try:
        manager = get_session_manager()
        source_path = Path(input_path).resolve()
        if not source_path.exists():
            return {"error": f"Input file not found: {source_path}"}

        session_id = preferred_session_id or f"{source_path.stem}-{os.urandom(4).hex()}"

        open_target = source_path
        if private_copy:
            open_target = _make_private_copy(source_path, session_id)

        load_started_at = time.monotonic()
        opened_session_id = manager.open_binary(
            open_target,
            run_auto_analysis=run_auto_analysis,
            session_id=session_id,
        )
        session = manager.activate_session(opened_session_id)
        warmup: Optional[dict[str, Any]] = None
        if build_caches or init_hexrays:
            warmup = server_warmup(
                wait_auto_analysis=False,
                build_caches=build_caches,
                init_hexrays=init_hexrays,
            )
        _LIFECYCLE.set_idle_ttl(
            float(idle_ttl_sec), time.monotonic() - load_started_at
        )
        if _REGISTERED_PORT is None and _BOUND_HOST and _BOUND_PORT:
            _register_in_discovery(
                _BOUND_HOST, _BOUND_PORT, session.input_path, opened_session_id
            )
        return {
            "success": True,
            "session": session.to_dict(),
            "warmup": warmup,
            "working_copy": str(open_target) if private_copy else "",
            "source_path": str(source_path),
            "message": (
                f"Binary opened: {source_path.name} ({opened_session_id})"
            ),
        }
    except (FileNotFoundError, RuntimeError, ValueError) as e:
        _cleanup_session_workdir(preferred_session_id or "")
        return {"error": str(e)}
    except Exception as e:
        _cleanup_session_workdir(preferred_session_id or "")
        return {"error": f"Unexpected error: {e}"}


@tool
def idb_list() -> IdalibListResult:
    """List open IDA sessions in this worker."""

    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        return {"sessions": sessions, "count": len(sessions)}
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


def _install_dispatch_hook() -> None:
    """Wrap the registry dispatcher so every request bumps the watchdog timer."""
    original = MCP_SERVER.registry.dispatch

    def touching_dispatch(request):
        try:
            return original(request)
        finally:
            _LIFECYCLE.touch()

    MCP_SERVER.registry.dispatch = touching_dispatch


def main():
    parser = argparse.ArgumentParser(
        description="Headless idalib MCP worker (one database per process)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show debug messages"
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1", help="Host to listen on"
    )
    parser.add_argument(
        "--port", type=int, default=8745, help="Port to listen on"
    )
    parser.add_argument(
        "--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)"
    )
    parser.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Restrict exposed tools to those in a profile file (one name per "
            "line, # for comments). idb_* management tools are always kept."
        ),
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Session id for an initial CLI-provided binary (else auto).",
    )
    parser.add_argument(
        "input_path",
        type=Path,
        nargs="?",
        help="Optional initial binary to open on startup.",
    )
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        idapro.enable_console_messages(True)
    else:
        log_level = logging.INFO
        idapro.enable_console_messages(False)

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    global _BOUND_HOST, _BOUND_PORT
    _BOUND_HOST = args.host
    _BOUND_PORT = args.port

    session_manager = get_session_manager()

    if args.input_path is not None:
        if not args.input_path.exists():
            raise FileNotFoundError(f"Input file not found: {args.input_path}")
        logger.info("opening initial database: %s", args.input_path)
        source = args.input_path.resolve()
        session_id = args.session_id or f"{source.stem}-{os.urandom(4).hex()}"
        open_target = _make_private_copy(source, session_id)
        opened = session_manager.open_binary(
            open_target, run_auto_analysis=True, session_id=session_id
        )
        logger.info("Initial session created: %s", opened)
        _register_in_discovery(args.host, args.port, source, opened)
    else:
        logger.info(
            "No initial binary. Use idb_open() to load a binary into this worker."
        )

    def _on_lifecycle_exit(reason: str) -> None:
        logger.info("Worker lifecycle requesting shutdown: %s", reason)
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed during lifecycle shutdown")

    _LIFECYCLE.start(on_shutdown=_on_lifecycle_exit)
    _install_dispatch_hook()

    def cleanup_and_exit(signum, frame):
        logger.info("Signal %s received; shutting down", signum)
        try:
            MCP_SERVER.stop()
        except Exception:
            logger.exception("MCP_SERVER.stop() failed in signal handler")

    signal.signal(signal.SIGINT, cleanup_and_exit)
    signal.signal(signal.SIGTERM, cleanup_and_exit)

    if not args.unsafe:
        for name in MCP_UNSAFE:
            MCP_SERVER.tools.methods.pop(name, None)
        if MCP_UNSAFE:
            logger.info("Unsafe tools disabled (start with --unsafe to enable)")

    if args.profile is not None:
        try:
            whitelist = load_profile(args.profile)
        except (OSError, UnicodeDecodeError) as e:
            raise SystemExit(f"Failed to read profile '{args.profile}': {e}")
        kept, unknown = apply_profile(
            MCP_SERVER.tools.methods, whitelist, protected=IDB_MANAGEMENT_TOOLS
        )
        if unknown:
            logger.warning(
                "Profile references unknown tool(s) (ignored): %s", ", ".join(unknown)
            )
        logger.info(
            "Profile applied: %d whitelisted + %d management tool(s) active",
            len(kept),
            len(IDB_MANAGEMENT_TOOLS),
        )

    from ida_pro_mcp.ida_mcp import trace

    trace.install_tracer()
    logger.info("Tracing tools/call to IDB netnode %s", trace.IDB_NETNODE_NAME)

    if "IDA_MCP_URL" not in os.environ:
        set_download_base_url(f"http://{args.host}:{args.port}")

    try:
        MCP_SERVER.serve(
            host=args.host,
            port=args.port,
            background=False,
            request_handler=IdaMcpHttpRequestHandler,
        )
    finally:
        logger.info("Server loop exited; cleaning up")
        _LIFECYCLE.stop()
        _deregister_from_discovery()
        try:
            session_manager.close_all_sessions()
        except Exception:
            logger.exception("close_all_sessions raised during cleanup")
        _cleanup_all_workdirs()


if __name__ == "__main__":
    main()

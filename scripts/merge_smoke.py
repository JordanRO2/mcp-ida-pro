"""End-to-end smoke test for N-copies annotation MERGE-BACK.

Proves the "pass parallel edits back to a canonical IDB" flow: open one binary
as two independent copies, rename a function + set a comment in copy A only,
run idb_merge, and confirm the merged .i64 carries copy A's edits.

Usage (requires a real IDA 9.0+ install):
    IDADIR="E:\\IDA-Pro" python scripts/merge_smoke.py [path/to/binary]

Defaults to tests/crackme03.elf. Exits non-zero on any failed assertion.
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = REPO / "tests" / "crackme03.elf"
NEWNAME = "MERGED_FUNC_A"
CMT = "merged comment from copy A"


def _pick_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _rpc(port, method, params=None, timeout=180):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("POST", "/mcp", body,
                 {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    return json.loads(data) if data.strip() else None


def _call(port, name, args):
    res = (_rpc(port, "tools/call", {"name": name, "arguments": args}) or {}).get("result", {})
    return res.get("structuredContent", res), res.get("isError")


def _wait_listen(port, deadline):
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def _first_addr(obj):
    if isinstance(obj, dict):
        if "addr" in obj and "name" in obj:
            return obj["addr"]
        for v in obj.values():
            r = _first_addr(v)
            if r:
                return r
    if isinstance(obj, list):
        for v in obj:
            r = _first_addr(v)
            if r:
                return r
    return None


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TARGET
    if not target.is_file():
        print(f"Target binary not found: {target}")
        return 2
    if "IDADIR" not in os.environ:
        print("IDADIR is not set; point it at your IDA 9.0+ install.")
        return 2

    port = _pick_port()
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "ida_pro_mcp.idalib_supervisor",
         "--host", "127.0.0.1", "--port", str(port), "--max-workers", "8"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    into = str(Path(tempfile.mkdtemp(prefix="merge_out_")) / "merged.i64")
    try:
        if not _wait_listen(port, time.time() + 40):
            print("supervisor did not start listening")
            print(proc.stdout.read() if proc.stdout else "")
            return 1
        _rpc(port, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "merge-smoke", "version": "0"}})

        a = _call(port, "idb_open", {"input_path": str(target)})[0]["session"]["session_id"]
        b = _call(port, "idb_open", {"input_path": str(target)})[0]["session"]["session_id"]
        if a == b:
            print("FAIL: expected two distinct copies")
            return 1

        funcs, _ = _call(port, "list_funcs", {"queries": "", "database": a})
        addr = _first_addr(funcs)
        _call(port, "rename", {"database": a, "batch": {"func": [{"addr": str(addr), "name": NEWNAME}]}})
        _, cerr = _call(port, "set_comments", {"database": a, "items": [{"addr": str(addr), "comment": CMT}]})

        dry, _ = _call(port, "idb_merge", {"path": str(target), "dry_run": True})
        merged, merr = _call(port, "idb_merge", {"path": str(target), "into": into, "policy": "last"})
        merged_path = merged.get("into", into)

        check = subprocess.run(
            [sys.executable, "-c",
             "import os; os.environ.setdefault('IDADIR', os.environ.get('IDADIR',''));"
             "import idapro, idc, ida_name;"
             f"idapro.open_database(r'{merged_path}', False);"
             f"ea = ida_name.get_name_ea(0xffffffffffffffff, '{NEWNAME}');"
             "cmt = idc.get_cmt(ea, False) if ea != 0xffffffffffffffff else None;"
             "print('CHECK', ea != 0xffffffffffffffff, repr(cmt));"
             "idapro.close_database()"],
            env=env, capture_output=True, text=True)
        line = next((l for l in check.stdout.splitlines() if l.startswith("CHECK")), "")

        ok = (cerr is False and merged.get("ok") and "CHECK True" in line and CMT in line)
        if not ok:
            print("FAIL")
            print("  dry_run:", dry.get("merged_counts"), "conflicts:", len(dry.get("conflicts", []) or []))
            print("  merge:", merged)
            print("  merged-db check:", line or (check.stdout + check.stderr)[-400:])
            return 1
        print(f"PASS: merged {dry.get('merged_counts')} annotations from 2 parallel copies; "
              f"merged .i64 carries copy A's rename ({NEWNAME}) and comment.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

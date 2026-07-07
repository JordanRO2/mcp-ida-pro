"""End-to-end smoke test for the multi-process idalib supervisor (N-copies).

Proves that multiple agents can analyze the SAME binary in parallel: opening one
binary twice yields two distinct worker processes / private IDBs, tools route by
session id, edits (renames) in one copy stay invisible to the other, and passing
an existing session id shares a worker instead of spawning a new one.

Usage (requires a real IDA 9.0+ install):
    IDADIR="E:\\IDA-Pro" python scripts/ncopies_smoke.py [path/to/binary]

Defaults to tests/crackme03.elf. Exits non-zero on any failed assertion.
"""
import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = REPO / "tests" / "crackme03.elf"
NEWNAME = "RENAMED_ONLY_IN_A"


def _pick_port() -> int:
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


def _find_first_addr(obj):
    if isinstance(obj, dict):
        if "addr" in obj and "name" in obj:
            return obj["addr"], obj["name"]
        for value in obj.values():
            found = _find_first_addr(value)
            if found:
                return found
    if isinstance(obj, list):
        for value in obj:
            found = _find_first_addr(value)
            if found:
                return found
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
    failures = []
    try:
        if not _wait_listen(port, time.time() + 40):
            print("supervisor did not start listening")
            print(proc.stdout.read() if proc.stdout else "")
            return 1
        _rpc(port, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "ncopies-smoke", "version": "0"}})

        tools = {t["name"]: t for t in (_rpc(port, "tools/list") or {}).get("result", {}).get("tools", [])}
        has_db = "database" in tools.get("list_funcs", {}).get("inputSchema", {}).get("properties", {})
        if "idb_open" not in tools or not has_db:
            failures.append("tools/list missing idb_open or injected 'database' arg")

        # Two opens of ONE binary -> two distinct workers.
        sids = []
        for _ in range(2):
            sc, err = _call(port, "idb_open", {"input_path": str(target)})
            sids.append(sc.get("session", {}).get("session_id"))
        if len(set(sids)) != 2:
            failures.append(f"expected two distinct sessions, got {sids}")

        # Concurrent routed analysis on each.
        out = {}

        def analyze(sid):
            _, err = _call(port, "list_funcs", {"queries": "", "database": sid})
            out[sid] = err

        threads = [threading.Thread(target=analyze, args=(s,)) for s in sids]
        [t.start() for t in threads]
        [t.join() for t in threads]
        if not all(out.get(s) is False for s in sids):
            failures.append(f"concurrent list_funcs failed: {out}")

        # Annotation divergence: rename in copy A only.
        funcs_a, _ = _call(port, "list_funcs", {"queries": "", "database": sids[0]})
        addr, _old = _find_first_addr(funcs_a)
        _, rerr = _call(port, "rename",
                        {"database": sids[0], "batch": {"func": [{"addr": str(addr), "name": NEWNAME}]}})
        in_a = NEWNAME in json.dumps(_call(port, "list_funcs", {"queries": "", "database": sids[0]})[0])
        in_b = NEWNAME in json.dumps(_call(port, "list_funcs", {"queries": "", "database": sids[1]})[0])
        if rerr or not in_a or in_b:
            failures.append(f"divergence failed (rename_err={rerr}, in_A={in_a}, in_B={in_b})")

        # Share opt-in: reopening with an existing session id reuses it.
        sc, _ = _call(port, "idb_open", {"input_path": str(target), "preferred_session_id": sids[0]})
        if sc.get("session", {}).get("session_id") != sids[0]:
            failures.append("share-by-session-id did not reuse the worker")

        if failures:
            print("FAIL:")
            for f in failures:
                print("  -", f)
            return 1
        print("PASS: two parallel workers on one binary, routed tools, divergent "
              "annotations, and share-by-session-id all work.")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())

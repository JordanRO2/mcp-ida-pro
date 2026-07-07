"""N-copies supervisor tests (no IDA/idalib required).

These lock in the behavior that makes multiple agents able to analyze the SAME
binary in parallel: opening one path twice yields TWO distinct worker sessions
(no path dedup), routing is by session id, path_to_session is multi-valued, and
passing an existing session id SHARES a worker instead of spawning a new one.
"""

from pathlib import Path

import pytest

from ida_pro_mcp import idalib_supervisor as supmod


class _FakeProcess:
    pid = 12345
    returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class _FakeSupervisor(supmod.IdalibSupervisor):
    """Supervisor whose worker spawn/RPC are faked so tests need no IDA."""

    def __init__(self, max_workers=8):
        super().__init__(supmod.McpServer("test"), max_workers=max_workers)
        self.spawned = 0

    def _spawn_worker(self):
        self.spawned += 1
        # Each spawn is a distinct fake process/port so duplicate copies of one
        # binary are genuinely different workers.
        return supmod.WorkerSession(
            session_id="__stub__",
            input_path="",
            filename="",
            host="127.0.0.1",
            port=1000 + self.spawned,
            process=_FakeProcess(),
        )

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        if name == "idb_open":
            assert arguments is not None
            return {
                "success": True,
                "session": {
                    "session_id": arguments["preferred_session_id"],
                    "input_path": arguments["input_path"],
                    "filename": Path(arguments["input_path"]).name,
                    "created_at": "now",
                    "last_accessed": "now",
                    "is_analyzing": False,
                    "metadata": {},
                },
                "warmup": None,
            }
        return {"ok": True, "error": None}

    def _session_is_reachable(self, session):
        return session.is_alive()

    def _probe_session_health(self, session):
        reachable = session.is_alive()
        return {
            "backend": session.backend,
            "process_alive": session.is_alive(),
            "tcp_connect": reachable,
            "rpc_ping": reachable,
            "reachable": reachable,
            "failed_probe": None if reachable else "tcp_connect",
            "error": None,
        }


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "prog.bin"
    p.write_bytes(b"\x7fELFdummy")
    return p


def test_same_path_opened_twice_yields_distinct_workers(sample):
    """The core N-copies guarantee: no dedup by path."""
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    b = sup.open_session(str(sample))
    assert a.session_id != b.session_id
    assert a.port != b.port
    assert sup.spawned == 2
    assert a.session_id in sup.sessions and b.session_id in sup.sessions


def test_minted_session_ids_carry_binary_stem(sample):
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    assert a.session_id.startswith("prog-")


def test_reuse_by_session_id_shares_worker(sample):
    """Passing an existing reachable session id shares, does not spawn."""
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    again = sup.open_session(str(sample), session_id=a.session_id)
    assert again.session_id == a.session_id
    assert again.port == a.port
    assert sup.spawned == 1  # no second worker spawned for a share


def test_path_to_session_is_multivalued(sample):
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    b = sup.open_session(str(sample))
    key = sup._path_key(sup._normalize_input_path(str(sample)))
    ids = sup.path_to_session[key]
    assert isinstance(ids, set)
    assert {a.session_id, b.session_id} <= ids


def test_unregister_one_copy_keeps_sibling(sample):
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    b = sup.open_session(str(sample))
    with sup._lock:
        sup._unregister_session_locked(a.session_id)
    key = sup._path_key(sup._normalize_input_path(str(sample)))
    assert a.session_id not in sup.sessions
    assert b.session_id in sup.sessions
    # sibling's path mapping survives; the removed id is gone
    assert b.session_id in sup.path_to_session[key]
    assert a.session_id not in sup.path_to_session[key]


def test_routing_resolves_each_session_independently(sample):
    sup = _FakeSupervisor()
    a = sup.open_session(str(sample))
    b = sup.open_session(str(sample))
    assert sup.resolve_session(a.session_id).port == a.port
    assert sup.resolve_session(b.session_id).port == b.port


def test_headless_does_not_adopt_worker_by_path(sample, monkeypatch):
    """Even if a worker instance exists for this path, headless spawns fresh."""
    sup = _FakeSupervisor()
    calls = {"n": 0}

    def _find(*_a, **_k):
        calls["n"] += 1
        return {"host": "127.0.0.1", "port": 9, "idb_path": str(sample), "backend": "worker"}

    monkeypatch.setattr(sup, "_find_instance_for_path", _find)
    a = sup.open_session(str(sample))
    b = sup.open_session(str(sample))
    # spawned fresh workers, never adopted the pre-existing instance
    assert a.session_id != b.session_id
    assert sup.spawned == 2


def test_worker_rpc_forwards_bearer_token_for_adopted_gui(monkeypatch):
    """An adopted GUI may enforce a stable token; the supervisor must forward it."""
    captured = {}

    class _Resp:
        status = 200
        reason = "OK"

        def read(self):
            return b'{"jsonrpc":"2.0","id":1,"result":{}}'

    class _Conn:
        def __init__(self, host, port, timeout=None):
            pass

        def request(self, method, path, body, headers):
            captured["headers"] = headers

        def getresponse(self):
            return _Resp()

        def close(self):
            pass

    monkeypatch.setattr(supmod.http.client, "HTTPConnection", _Conn)
    sup = supmod.IdalibSupervisor(supmod.McpServer("t"))

    with_token = supmod.WorkerSession(
        session_id="gui", input_path="", filename="",
        host="127.0.0.1", port=1, backend="gui", token="abc123",
    )
    sup._worker_rpc(with_token, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert captured["headers"].get("Authorization") == "Bearer abc123"

    no_token = supmod.WorkerSession(
        session_id="w", input_path="", filename="", host="127.0.0.1", port=1,
    )
    sup._worker_rpc(no_token, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert "Authorization" not in captured["headers"]

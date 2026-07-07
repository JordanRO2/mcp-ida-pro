"""Discovery registry tests for N-copies (no IDA required).

The registry must disambiguate duplicate workers of the SAME binary by
session id, since idb_path is no longer unique under N-copies.
"""

import os
import socket
import threading

import pytest

# Import discovery in ISOLATION (as the supervisor does) so this test never
# triggers ida_pro_mcp.ida_mcp.__init__ (which imports idaapi). The supervisor
# already loads discovery via a file-spec loader that pulls no IDA modules.
from ida_pro_mcp import idalib_supervisor as _supmod

discovery = _supmod._discovery


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_USER_DIR", str(tmp_path))
    return tmp_path


class _Acceptor:
    """A real listening socket so probe_instance() succeeds."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                c, _ = self.sock.accept()
                c.close()
            except Exception:
                pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def test_duplicate_workers_same_path_distinct_session_files(registry):
    a, b = _Acceptor(), _Acceptor()
    try:
        discovery.register_instance("127.0.0.1", a.port, os.getpid(), "prog.bin", "/x/prog.bin",
                                    backend="worker", session_id="prog-aaaa1111")
        discovery.register_instance("127.0.0.1", b.port, os.getpid(), "prog.bin", "/x/prog.bin",
                                    backend="worker", session_id="prog-bbbb2222")
        found = discovery.discover_instances()
        assert len(found) == 2
        assert {i.get("session_id") for i in found} == {"prog-aaaa1111", "prog-bbbb2222"}
    finally:
        a.close()
        b.close()


def test_find_instance_for_session_disambiguates(registry):
    a, b = _Acceptor(), _Acceptor()
    try:
        discovery.register_instance("127.0.0.1", a.port, os.getpid(), "prog.bin", "/x/prog.bin",
                                    backend="worker", session_id="prog-aaaa1111")
        discovery.register_instance("127.0.0.1", b.port, os.getpid(), "prog.bin", "/x/prog.bin",
                                    backend="worker", session_id="prog-bbbb2222")
        hit = discovery.find_instance_for_session("prog-bbbb2222")
        assert hit is not None
        assert hit["port"] == b.port
        assert discovery.find_instance_for_session("prog-nope") is None
    finally:
        a.close()
        b.close()


def test_discovery_import_pulls_no_ida():
    # Run in a FRESH subprocess so sibling tests that stub idaapi in sys.modules
    # cannot pollute the check. This asserts the real property: importing the
    # discovery module (as the supervisor does) pulls in no IDA modules.
    import subprocess
    import sys as _sys
    from pathlib import Path

    repo_src = str(Path(__file__).resolve().parent.parent / "src")
    code = (
        "import sys, importlib.util, os;"
        "p=os.path.join(r'%s','ida_pro_mcp','ida_mcp','discovery.py');"
        "spec=importlib.util.spec_from_file_location('disc_probe',p);"
        "m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);"
        "bad=[x for x in sys.modules if x in ('idc','idaapi','idapro') or x.startswith('ida_')];"
        "print('LEAK' if bad else 'CLEAN')"
    ) % repo_src
    out = subprocess.run([_sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "CLEAN", out.stdout + out.stderr

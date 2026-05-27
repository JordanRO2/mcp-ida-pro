"""Connection file and session auth token helpers.

This module is intentionally stdlib-only (os, json, tempfile, secrets, hmac)
so it imports cleanly outside of IDA. It is shared by both sides:

- The plugin HTTP server writes the connection file on start (recording the
  actual bound port and a freshly generated session token) and removes it on
  stop.
- The bridge (server.py) reads the connection file to discover the live port
  and, when a token is present, attaches it as a Bearer token.

Backward compatibility: writing the connection file and accepting a correct
token is always done, but the plugin only *requires* a token when the user
opts in via the IDA_MCP_REQUIRE_TOKEN environment variable. With no env vars
set and no connection file, behavior is identical to before this module
existed.
"""

import hmac
import json
import os
import secrets
import tempfile


def connection_file_path() -> str:
    """Absolute path of the connection file under the system temp dir."""
    return os.path.join(tempfile.gettempdir(), "ida-pro-mcp", "connection.json")


def generate_token() -> str:
    """Return a fresh random session token (256 bits, hex-encoded)."""
    return secrets.token_hex(32)


def write_connection_file(port: int, token: str) -> str:
    """Write the connection file with the bound port, token and owning pid.

    The directory is created if missing. File permissions are tightened to
    0600 on a best-effort basis (Windows may not honor chmod, hence the
    try/except). Returns the path that was written.
    """
    path = connection_file_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {"port": port, "token": token, "pid": os.getpid()}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows (and some filesystems) may not honor POSIX permissions.
        pass
    return path


def read_connection_file() -> dict | None:
    """Return the parsed connection file, or None if absent/unreadable."""
    path = connection_file_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def remove_connection_file() -> None:
    """Delete the connection file if it exists (best effort)."""
    path = connection_file_path()
    try:
        os.remove(path)
    except OSError:
        pass


def tokens_match(expected: str | None, provided: str | None) -> bool:
    """Constant-time comparison of two tokens.

    Returns False if either value is missing.
    """
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)

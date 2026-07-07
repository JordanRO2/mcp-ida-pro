"""IDA-free unit tests for rpc.py output-truncation metadata schema validity (54b0566).

Regression guard: the pre-fix code injected underscore-prefixed download keys
(``_output_truncated``, ``_download_url``, ...) directly into ``structuredContent``,
which violates each tool's ``outputSchema`` (fatal with ``additionalProperties: false``
TypedDict schemas). The fix moves that metadata to a top-level ``_meta.ida_mcp`` block,
adds a ``content`` array, and leaves ``structuredContent`` holding only the truncated
preview.

rpc.py imports only from the IDA-free ``.zeromcp`` package, so we load it via a
synthetic parent package that bypasses the heavy ``ida_pro_mcp.ida_mcp.__init__``
(which pulls in idaapi). No IDA / idalib required.
"""

import importlib.util
import sys
import types
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_PKG_DIR = _REPO / "src" / "ida_pro_mcp" / "ida_mcp"


def _load_rpc():
    """Load ``ida_pro_mcp.ida_mcp.rpc`` without executing the package __init__.

    We register synthetic namespace packages for ``ida_pro_mcp`` and
    ``ida_pro_mcp.ida_mcp`` (with ``__path__`` pointing at the real dirs) so that
    rpc.py's ``from .zeromcp import ...`` resolves against the real, IDA-free
    zeromcp package, while the idaapi-importing ``__init__.py`` never runs.
    """
    for name, path in (
        ("ida_pro_mcp", _REPO / "src" / "ida_pro_mcp"),
        ("ida_pro_mcp.ida_mcp", _PKG_DIR),
    ):
        existing = sys.modules.get(name)
        if existing is None or not hasattr(existing, "__path__"):
            pkg = types.ModuleType(name)
            pkg.__path__ = [str(path)]
            sys.modules[name] = pkg

    mod_name = "ida_pro_mcp.ida_mcp.rpc"
    if mod_name in sys.modules:
        return sys.modules[mod_name]

    spec = importlib.util.spec_from_file_location(mod_name, str(_PKG_DIR / "rpc.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    return module


rpc = _load_rpc()


class BuildDownloadMetaTests(unittest.TestCase):
    def test_returns_schema_safe_non_underscore_keys(self):
        meta = rpc._build_download_meta("abc-123", 90000)
        self.assertEqual(
            set(meta.keys()),
            {
                "output_truncated",
                "total_chars",
                "output_id",
                "download_url",
                "download_hint",
            },
        )
        # No underscore-prefixed keys leak into the metadata block.
        self.assertFalse(any(k.startswith("_") for k in meta))
        self.assertIs(meta["output_truncated"], True)
        self.assertEqual(meta["total_chars"], 90000)
        self.assertEqual(meta["output_id"], "abc-123")
        self.assertIn("abc-123.json", meta["download_url"])
        self.assertIn("Output truncated", meta["download_hint"])

    def test_old_add_download_info_symbol_is_gone(self):
        # The schema-violating helper must no longer exist.
        self.assertFalse(hasattr(rpc, "_add_download_info"))


class PatchedToolsCallTruncationTests(unittest.TestCase):
    def _register_tool(self, name, func):
        rpc.MCP_SERVER.tools.methods[name] = func
        self.addCleanup(rpc.MCP_SERVER.tools.methods.pop, name, None)

    def test_oversized_output_moves_metadata_to_meta(self):
        # A result whose JSON serialization exceeds OUTPUT_LIMIT_MAX_CHARS.
        big = "x" * (rpc.OUTPUT_LIMIT_MAX_CHARS + 10000)
        self._register_tool("_tmp_big_tool", lambda: {"data": big})

        tools_call = rpc.MCP_SERVER.registry.methods["tools/call"]
        resp = tools_call("_tmp_big_tool", {})

        self.assertIs(resp["isError"], False)

        # structuredContent holds ONLY the truncated preview: no underscore /
        # download keys injected (the exact pre-fix schema violation).
        structured = resp["structuredContent"]
        self.assertIsInstance(structured, dict)
        self.assertIn("data", structured)
        self.assertFalse(
            any(k.startswith("_") for k in structured),
            f"structuredContent leaked underscore keys: {list(structured)}",
        )
        for banned in (
            "_output_truncated",
            "_download_url",
            "_download_hint",
            "_output_id",
            "_total_chars",
            "_preview",
        ):
            self.assertNotIn(banned, structured)

        # Download metadata now lives under a top-level _meta.ida_mcp block.
        meta = resp["_meta"]["ida_mcp"]
        self.assertIs(meta["output_truncated"], True)
        self.assertGreater(meta["total_chars"], rpc.OUTPUT_LIMIT_MAX_CHARS)
        self.assertIn("output_id", meta)
        self.assertIn("download_url", meta)

        # content array carries the preview text plus the download hint.
        content = resp["content"]
        self.assertIsInstance(content, list)
        self.assertGreaterEqual(len(content), 2)
        self.assertTrue(
            any("Output truncated" in item.get("text", "") for item in content)
        )

        # The cached full output is retrievable by the advertised id.
        self.assertEqual(rpc.get_cached_output(meta["output_id"]), {"data": big})

    def test_small_output_is_passed_through_untouched(self):
        self._register_tool("_tmp_small_tool", lambda: {"ok": True, "n": 1})

        tools_call = rpc.MCP_SERVER.registry.methods["tools/call"]
        resp = tools_call("_tmp_small_tool", {})

        self.assertIs(resp["isError"], False)
        self.assertEqual(resp["structuredContent"], {"ok": True, "n": 1})
        # No truncation metadata for outputs under the limit.
        self.assertNotIn("_meta", resp)


if __name__ == "__main__":
    unittest.main()

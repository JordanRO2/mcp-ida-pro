"""Application service for memory reading/writing operations.

Orchestration logic moved verbatim from the legacy flat ``api_memory`` module.
The 6 memory tools delegate here; raw IDA SDK access lives in ``MemoryAdapter``.
"""

from __future__ import annotations

import re

from ...infrastructure.adapters.memory_adapter import MemoryAdapter
from ...utils import (
    normalize_list_input,
    parse_address,
    looks_like_address,
)

_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


class MemoryService:
    """High-level service for memory read/write tools."""

    def __init__(self, adapter: MemoryAdapter):
        self.adapter = adapter

    # -- internal helpers (moved verbatim) -------------------------------

    @staticmethod
    def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
        if not text:
            raise ValueError("Missing integer class")

        cleaned = text.strip().lower()
        match = _INT_CLASS_RE.match(cleaned)
        if not match:
            raise ValueError(f"Invalid integer class: {text}")

        bits = int(match.group("bits"))
        signed = match.group("sign") == "i"
        endian = match.group("endian") or "le"
        byte_order = "little" if endian == "le" else "big"
        normalized = f"{'i' if signed else 'u'}{bits}{endian}"
        return bits, signed, byte_order, normalized

    @staticmethod
    def _parse_int_value(text: str, signed: bool, bits: int) -> int:
        if text is None:
            raise ValueError("Missing integer value")

        value_text = str(text).strip()
        try:
            value = int(value_text, 0)
        except ValueError:
            raise ValueError(f"Invalid integer value: {text}")

        if not signed and value < 0:
            raise ValueError(f"Negative value not allowed for u{bits}")

        return value

    # -- tool orchestration ----------------------------------------------

    def get_bytes(self, regions) -> list[dict]:
        if isinstance(regions, dict):
            regions = [regions]

        results = []
        for item in regions:
            addr = item.get("addr", "")
            size = item.get("size", 0)

            try:
                ea = parse_address(addr)
                raw = self.adapter.read_bytes_bss_safe(ea, size)
                data = " ".join(f"{x:#02x}" for x in raw)
                results.append({"addr": addr, "data": data})
            except Exception as e:
                results.append({"addr": addr, "data": None, "error": str(e)})

        return results

    def get_int(self, queries) -> list[dict]:
        if isinstance(queries, dict):
            queries = [queries]

        results = []
        for item in queries:
            addr = item.get("addr", "")
            ty = item.get("ty", "")

            try:
                bits, signed, byte_order, normalized = self._parse_int_class(ty)
                ea = parse_address(addr)
                size = bits // 8
                data = self.adapter.read_bytes_bss_safe(ea, size)
                if len(data) != size:
                    raise ValueError(f"Failed to read {size} bytes at {addr}")

                value = int.from_bytes(data, byte_order, signed=signed)
                results.append(
                    {"addr": addr, "ty": normalized, "value": value, "error": None}
                )
            except Exception as e:
                results.append({"addr": addr, "ty": ty, "value": None, "error": str(e)})

        return results

    def get_string(self, addrs) -> list[dict]:
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                raw = self.adapter.get_strlit_contents(ea)
                if not raw:
                    results.append(
                        {"addr": addr, "value": None, "error": "No string at address"}
                    )
                    continue
                value = raw.decode("utf-8", errors="replace")
                results.append({"addr": addr, "value": value})
            except Exception as e:
                results.append({"addr": addr, "value": None, "error": str(e)})

        return results

    def get_global_value(self, queries) -> list[dict]:
        queries = normalize_list_input(queries)
        results = []

        for query in queries:
            try:
                ea = self.adapter.BADADDR

                # Try as address first if it looks like one
                if looks_like_address(query):
                    try:
                        ea = parse_address(query)
                    except Exception:
                        ea = self.adapter.BADADDR

                # Fall back to name lookup
                if ea == self.adapter.BADADDR:
                    ea = self.adapter.get_name_ea(query)

                if ea == self.adapter.BADADDR:
                    results.append({"query": query, "value": None, "error": "Not found"})
                    continue

                value = self.adapter.get_global_variable_value_internal(ea)
                results.append({"query": query, "value": value, "error": None})
            except Exception as e:
                results.append({"query": query, "value": None, "error": str(e)})

        return results

    def patch(self, patches) -> list[dict]:
        if isinstance(patches, dict):
            patches = [patches]

        results = []

        for patch in patches:
            try:
                ea = parse_address(patch["addr"])
                data = bytes.fromhex(patch["data"])

                if not self.adapter.is_mapped(ea):
                    raise ValueError(f"Address not mapped: {patch['addr']}")

                self.adapter.patch_bytes(ea, data)
                results.append(
                    {"addr": patch["addr"], "size": len(data), "ok": True, "error": None}
                )

            except Exception as e:
                results.append({"addr": patch.get("addr"), "size": 0, "error": str(e)})

        return results

    def put_int(self, items) -> list[dict]:
        if isinstance(items, dict):
            items = [items]

        results = []
        for item in items:
            addr = item.get("addr", "")
            ty = item.get("ty", "")
            value_text = item.get("value")

            try:
                bits, signed, byte_order, normalized = self._parse_int_class(ty)
                value = self._parse_int_value(value_text, signed, bits)
                size = bits // 8
                try:
                    data = value.to_bytes(size, byte_order, signed=signed)
                except OverflowError:
                    raise ValueError(f"Value {value_text} does not fit in {normalized}")

                ea = parse_address(addr)
                if not self.adapter.is_mapped(ea):
                    raise ValueError(f"Address not mapped: {addr}")
                self.adapter.patch_bytes(ea, data)
                results.append(
                    {
                        "addr": addr,
                        "ty": normalized,
                        "value": str(value_text),
                        "ok": True,
                        "error": None,
                    }
                )
            except Exception as e:
                results.append(
                    {
                        "addr": addr,
                        "ty": ty,
                        "value": str(value_text) if value_text is not None else None,
                        "ok": False,
                        "error": str(e),
                    }
                )

        return results

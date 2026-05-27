"""Application service for IDA stack-frame operations.

Orchestration logic moved faithfully from the former ``api_stack.py`` tool
bodies. Raw SDK access is delegated to ``StackAdapter``.

``get_type_by_name`` is a plain helper still living in ``utils`` (resolves a
type name into a ``tinfo_t``); it is imported there per the DDD import map.
"""

from __future__ import annotations

from ...infrastructure.adapters.stack_adapter import StackAdapter
from ...utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
)


class StackService:
    """High-level service for IDA stack-frame operations."""

    def __init__(self, adapter: StackAdapter):
        self.adapter = adapter

    def stack_frame(self, addrs) -> list[dict]:
        addrs = normalize_list_input(addrs)
        results = []

        for addr in addrs:
            try:
                ea = parse_address(addr)
                vars = self.adapter.get_stack_frame_variables(ea, True)
                results.append({"addr": addr, "vars": vars})
            except Exception as e:
                results.append({"addr": addr, "vars": None, "error": str(e)})

        return results

    def declare_stack(self, items):
        items = normalize_dict_list(items)
        results = []
        for item in items:
            fn_addr = item.get("addr", "")
            offset = item.get("offset", "")
            var_name = item.get("name", "")
            type_name = item.get("ty", "")

            try:
                func = self.adapter.get_func(parse_address(fn_addr))
                if not func:
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "No function found"}
                    )
                    continue

                ea = parse_address(offset)

                frame_tif = self.adapter.new_tinfo()
                if not self.adapter.get_func_frame(frame_tif, func):
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                    )
                    continue

                tif = get_type_by_name(type_name)
                if not self.adapter.define_stkvar(func, var_name, ea, tif):
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "Failed to define"}
                    )
                    continue

                results.append({"addr": fn_addr, "name": var_name, "ok": True})
            except Exception as e:
                results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

        return results

    def delete_stack(self, items):
        items = normalize_dict_list(items)
        results = []
        for item in items:
            fn_addr = item.get("addr", "")
            var_name = item.get("name", "")

            try:
                func = self.adapter.get_func(parse_address(fn_addr))
                if not func:
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "No function found"}
                    )
                    continue

                frame_tif = self.adapter.new_tinfo()
                if not self.adapter.get_func_frame(frame_tif, func):
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "No frame returned"}
                    )
                    continue

                idx, udm = self.adapter.get_udm(frame_tif, var_name)
                if not udm:
                    results.append(
                        {
                            "addr": fn_addr,
                            "name": var_name,
                            "error": f"{var_name} not found",
                        }
                    )
                    continue

                tid = self.adapter.get_udm_tid(frame_tif, idx)
                if self.adapter.is_special_frame_member(tid):
                    results.append(
                        {
                            "addr": fn_addr,
                            "name": var_name,
                            "error": f"{var_name} is special frame member",
                        }
                    )
                    continue

                udm = self.adapter.new_udm()
                self.adapter.get_udm_by_tid(frame_tif, udm, tid)
                offset = udm.offset // 8
                size = udm.size // 8
                if self.adapter.is_funcarg_off(func, offset):
                    results.append(
                        {
                            "addr": fn_addr,
                            "name": var_name,
                            "error": f"{var_name} is argument member",
                        }
                    )
                    continue

                if not self.adapter.delete_frame_members(func, offset, offset + size):
                    results.append(
                        {"addr": fn_addr, "name": var_name, "error": "Failed to delete"}
                    )
                    continue

                results.append({"addr": fn_addr, "name": var_name, "ok": True})
            except Exception as e:
                results.append({"addr": fn_addr, "name": var_name, "error": str(e)})

        return results

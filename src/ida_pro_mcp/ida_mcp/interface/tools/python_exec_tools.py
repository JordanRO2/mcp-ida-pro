"""Python evaluation tool for IDA Pro MCP."""

from typing import Annotated

from ...rpc import tool, unsafe
from ...infrastructure.sync.sync import idasync, tool_timeout
from ...container import get_python_exec_service

# ============================================================================
# Python Evaluation
# ============================================================================


@tool
@idasync
@tool_timeout(120)
@unsafe
def py_eval(
    code: Annotated[str, "Python code"],
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Execute Python in IDA context and return result/stdout/stderr."""
    return get_python_exec_service().py_eval(code, timeout)


@tool
@idasync
@tool_timeout(120)
@unsafe
def py_exec_file(
    file_path: Annotated[str, "Absolute path to a Python script to execute"],
) -> dict:
    """Execute a Python script file in IDA context and return result/stdout/stderr.

    Unlike py_eval, this runs the entire file with exec() using a single shared
    globals dict (no locals split), so top-level definitions are visible to all
    code in the script. Handles large scripts that would be unwieldy as inline code.
    """
    return get_python_exec_service().py_exec_file(file_path)

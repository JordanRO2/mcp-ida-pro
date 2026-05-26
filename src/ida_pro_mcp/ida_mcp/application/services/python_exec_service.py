"""Application service for in-IDA Python evaluation.

Orchestration logic moved verbatim from the legacy flat ``api_python`` module.
The ``py_eval`` tool delegates here; the IDA SDK globals namespace is provided
by ``PythonExecAdapter``.
"""

from __future__ import annotations

import ast
import io
import sys

from ...infrastructure.adapters.python_exec_adapter import PythonExecAdapter


class PythonExecService:
    """High-level service for the ``py_eval`` tool."""

    def __init__(self, adapter: PythonExecAdapter):
        self.adapter = adapter

    def py_eval(self, code: str, timeout=None) -> dict:
        # Capture stdout/stderr
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        try:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture

            exec_globals = self.adapter.build_exec_globals()

            result_value = None
            exec_locals = {}

            # Parse code with AST to properly handle execution
            try:
                tree = ast.parse(code)
            except SyntaxError:
                # If parsing fails, fall back to direct exec
                exec(code, exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                if "result" in exec_locals:
                    result_value = str(exec_locals["result"])
                elif exec_locals:
                    last_key = list(exec_locals.keys())[-1]
                    result_value = str(exec_locals[last_key])
            else:
                if not tree.body:
                    # Empty code
                    pass
                elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                    # Single expression - use eval
                    result_value = str(eval(code, exec_globals))
                elif isinstance(tree.body[-1], ast.Expr):
                    # Multiple statements, last one is an expression (Jupyter-style)
                    # Execute all statements except the last
                    if len(tree.body) > 1:
                        exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                        exec(
                            compile(exec_tree, "<string>", "exec"),
                            exec_globals,
                            exec_locals,
                        )
                        exec_globals.update(exec_locals)
                    # Eval only the last expression
                    eval_tree = ast.Expression(body=tree.body[-1].value)
                    result_value = str(
                        eval(compile(eval_tree, "<string>", "eval"), exec_globals)
                    )
                else:
                    # All statements (no trailing expression)
                    exec(code, exec_globals, exec_locals)
                    exec_globals.update(exec_locals)
                    # Return 'result' variable if explicitly set
                    if "result" in exec_locals:
                        result_value = str(exec_locals["result"])
                    # Return last assigned variable
                    elif exec_locals:
                        last_key = list(exec_locals.keys())[-1]
                        result_value = str(exec_locals[last_key])

            # Collect output (cap at 100KB per field to prevent token waste)
            _MAX_OUTPUT = 100_000
            stdout_text = stdout_capture.getvalue()
            stderr_text = stderr_capture.getvalue()
            result_str = result_value or ""

            truncated = False
            if len(result_str) > _MAX_OUTPUT:
                result_str = result_str[:_MAX_OUTPUT] + f"\n... [{len(result_str)} chars total, truncated]"
                truncated = True
            if len(stdout_text) > _MAX_OUTPUT:
                stdout_text = stdout_text[:_MAX_OUTPUT] + f"\n... [{len(stdout_text)} chars total, truncated]"
                truncated = True

            response = {
                "result": result_str,
                "stdout": stdout_text,
                "stderr": stderr_text,
            }
            if truncated:
                response["truncated"] = True
            return response

        except Exception:
            import traceback

            return {
                "result": "",
                "stdout": "",
                "stderr": traceback.format_exc(),
            }
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

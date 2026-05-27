"""Security analysis tools for vulnerability detection and reverse engineering.

Provides automated detection of common vulnerability patterns, crypto algorithm
identification, and taint-like data flow analysis from sources to sinks.

Thin MCP tool layer: each ``@tool`` preserves the original public name,
signature, decorators and docstring, and delegates to ``SecurityService``
resolved from the DI container.
"""

from __future__ import annotations

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync, tool_timeout
from ...container import get_security_service


@tool
@idasync
@tool_timeout(120)
def detect_vulns(
    addrs: Annotated[
        list[str] | str | None,
        "Function addresses/names to scan (comma-separated). Omit to scan all functions."
    ] = None,
    vuln_types: Annotated[
        list[str] | str | None,
        "Filter by vuln type: buffer_overflow, format_string, command_injection, use_after_free, integer_overflow, toctou, untrusted_input"
    ] = None,
    severity: Annotated[
        str | None,
        "Minimum severity: critical, high, medium, low"
    ] = None,
    offset: Annotated[int, "Skip first N findings (default 0)"] = 0,
    count: Annotated[int, "Max findings to return (default 100, 0=all)"] = 100,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Scan functions for dangerous API calls and common vulnerability patterns.

    Returns categorized findings with call sites, severity, and remediation notes.
    Scans imports and direct calls for known dangerous sinks like strcpy, sprintf, system, etc.
    """
    return get_security_service().detect_vulns(
        addrs=addrs,
        vuln_types=vuln_types,
        severity=severity,
        offset=offset,
        count=count,
    )


@tool
@idasync
@tool_timeout(120)
def find_crypto(
    scan_constants: Annotated[bool, "Scan for magic constants in code"] = True,
    scan_tables: Annotated[bool, "Scan binary for known S-box/lookup tables"] = True,
    offset: Annotated[int, "Skip first N findings (default 0)"] = 0,
    count: Annotated[int, "Max findings per algorithm (default 50, 0=all)"] = 50,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Detect cryptographic algorithms by finding known constants, S-boxes, and lookup tables.

    Identifies AES, DES, MD5, SHA-1/256, RC4, Blowfish, TEA/XTEA, CRC32, Whirlpool
    by matching byte signatures and magic constants in the binary.
    """
    return get_security_service().find_crypto(
        scan_constants=scan_constants,
        scan_tables=scan_tables,
        offset=offset,
        count=count,
    )


@tool
@idasync
@tool_timeout(60)
def find_dangerous_callers(
    sink: Annotated[str, "Dangerous function name or address (e.g. 'strcpy', '0x401000')"],
    max_depth: Annotated[int, "How many call levels up to trace (default 3)"] = 3,
    offset: Annotated[int, "Skip first N edges (default 0)"] = 0,
    count: Annotated[int, "Max edges to return (default 200, 0=all)"] = 200,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 60)"] = None,
) -> dict:
    """Trace all call paths leading to a dangerous sink function.

    Given a dangerous function (e.g. strcpy, system), finds all callers recursively
    up to max_depth levels. Useful for finding which code paths reach dangerous sinks.
    """
    return get_security_service().find_dangerous_callers(
        sink=sink,
        max_depth=max_depth,
        offset=offset,
        count=count,
    )


@tool
@idasync
@tool_timeout(60)
def detect_stack_strings(
    addrs: Annotated[
        list[str] | str | None,
        "Function addresses/names to scan. Omit to scan all."
    ] = None,
    min_length: Annotated[int, "Minimum string length to report (default 4)"] = 4,
    offset: Annotated[int, "Skip first N results (default 0)"] = 0,
    count: Annotated[int, "Max results to return (default 200, 0=all)"] = 200,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 60)"] = None,
) -> dict:
    """Detect strings constructed on the stack (anti-analysis / obfuscation technique).

    Finds byte-by-byte or word-by-word string construction patterns where individual
    characters are moved to stack locations. Common in malware to evade static string detection.
    """
    return get_security_service().detect_stack_strings(
        addrs=addrs,
        min_length=min_length,
        offset=offset,
        count=count,
    )


@tool
@idasync
@tool_timeout(120)
def trace_source_to_sink(
    sources: Annotated[
        list[str] | str,
        "Source function names/addrs (e.g. 'recv,ReadFile,InternetReadFile')"
    ],
    sinks: Annotated[
        list[str] | str,
        "Sink function names/addrs (e.g. 'strcpy,system,sprintf')"
    ],
    max_depth: Annotated[int, "Max call chain depth (default 5)"] = 5,
    offset: Annotated[int, "Skip first N paths (default 0)"] = 0,
    count: Annotated[int, "Max paths to return (default 100, 0=all)"] = 100,
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Find call chains connecting input sources to dangerous sinks.

    Traces forward from source functions (recv, ReadFile, etc.) and backward from
    sink functions (strcpy, system, etc.) to find functions that appear in both sets,
    indicating potential vulnerability paths where untrusted data reaches dangerous APIs.
    """
    return get_security_service().trace_source_to_sink(
        sources=sources,
        sinks=sinks,
        max_depth=max_depth,
        offset=offset,
        count=count,
    )

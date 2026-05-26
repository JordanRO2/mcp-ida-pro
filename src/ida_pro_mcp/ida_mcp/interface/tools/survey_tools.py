"""Binary survey tool -- complete triage in one call."""

from __future__ import annotations

from typing import Annotated

from ...rpc import tool
from ...infrastructure.sync.sync import idasync, tool_timeout
from ...container import get_survey_service


@tool
@idasync
@tool_timeout(120.0)
def survey_binary(
    detail_level: Annotated[str, "Detail level: 'standard' or 'minimal'"] = "standard",
    timeout: Annotated[int | float | None, "Override timeout in seconds (default: 120)"] = None,
) -> dict:
    """Get a compact overview of the binary in one call. Returns file metadata,
    segment layout, entry points, statistics, top 15 strings and functions ranked
    by xref count (functions include classification: thunk/wrapper/leaf/dispatcher/
    complex), imports by category, and call graph summary. Use this as your FIRST
    tool call when starting analysis. Do not call list_funcs, imports, or find_regex
    separately for triage — this returns all of that. Use detail_level='minimal'
    for binaries with >10k functions."""
    return get_survey_service().survey_binary(detail_level)

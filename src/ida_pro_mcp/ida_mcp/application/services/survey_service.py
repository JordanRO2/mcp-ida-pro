"""Application service for the binary-survey tool."""

from __future__ import annotations

from ...infrastructure.adapters.survey_adapter import SurveyAdapter


class SurveyService:
    """Orchestrates a one-call binary triage survey."""

    def __init__(self, adapter: SurveyAdapter):
        self.adapter = adapter

    def survey_binary(self, detail_level: str = "standard") -> dict:
        minimal = detail_level == "minimal"

        # Collect all function addresses once, cap at MAX_FUNC_ITER for large binaries.
        all_func_eas = self.adapter.list_functions()
        truncated = len(all_func_eas) > self.adapter.MAX_FUNC_ITER
        if truncated:
            func_eas = all_func_eas[: self.adapter.MAX_FUNC_ITER]
        else:
            func_eas = all_func_eas

        strings = self.adapter.get_strings_cache()
        segments = self.adapter.build_segments()

        result: dict = {
            "metadata": self.adapter.build_metadata(),
            "statistics": self.adapter.build_statistics(
                all_func_eas, len(strings), len(segments)
            ),
            "segments": segments,
            "entrypoints": self.adapter.build_entrypoints(),
        }

        if not minimal:
            result["interesting_strings"] = self.adapter.build_interesting_strings()
            result["interesting_functions"] = self.adapter.build_interesting_functions(
                func_eas, truncated
            )
            result["imports_by_category"] = self.adapter.build_imports_by_category()
            result["call_graph_summary"] = self.adapter.build_call_graph_summary(func_eas)

        if truncated:
            result["_note"] = (
                f"Binary has {len(all_func_eas)} functions; "
                f"xref analysis was limited to the first {self.adapter.MAX_FUNC_ITER} for performance."
            )

        return result

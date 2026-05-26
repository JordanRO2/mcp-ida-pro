"""Dependency injection container for the IDA Pro MCP server.

Mirrors the x64dbg MCP container pattern (lazily-created singletons reached
through ``get_*`` accessors), but adapted to IDA's IN-PROCESS execution model.

Unlike x64dbg, there is no HTTP client to a remote debugger: the plugin runs
inside IDA and tools call ``idaapi`` directly (on the main thread via the
``@idasync`` decorator). So the container does not own a transport client.
Instead it is a small registry of lazily-created singletons that the
tool-migration phase will populate with the application services / adapters
extracted from the ``api_*`` modules.

Design notes:
- No ``idaapi`` import at module load: this file must import cleanly outside of
  IDA (e.g. for py_compile / unit checks). Anything that touches ``idaapi`` is
  constructed lazily inside the getters, only when first requested at runtime.
- Singletons are stored in a private registry dict and created on demand by
  registered factory callables. ``reset_container()`` clears them (for tests).
"""

from __future__ import annotations

from typing import Any, Callable, Dict

# Registry of created singletons, keyed by a stable name.
_singletons: Dict[str, Any] = {}

# Registry of factories: name -> zero-arg callable producing the singleton.
# The tool-migration phase registers the real application services here.
_factories: Dict[str, Callable[[], Any]] = {}


def register_factory(name: str, factory: Callable[[], Any]) -> None:
    """Register (or replace) the factory used to lazily create ``name``.

    Replacing a factory also drops any previously cached instance so the next
    ``get(name)`` rebuilds it from the new factory.
    """
    _factories[name] = factory
    _singletons.pop(name, None)


def get(name: str) -> Any:
    """Return the singleton ``name``, creating it from its factory on first use.

    Raises ``KeyError`` if no factory has been registered for ``name``.
    """
    if name not in _singletons:
        try:
            factory = _factories[name]
        except KeyError:
            raise KeyError(
                f"No factory registered for container service '{name}'. "
                "Register one via container.register_factory()."
            )
        _singletons[name] = factory()
    return _singletons[name]


def has(name: str) -> bool:
    """Return whether a singleton or factory is registered under ``name``."""
    return name in _singletons or name in _factories


def reset_container() -> None:
    """Drop all cached singleton instances (for tests). Factories are kept."""
    _singletons.clear()


def reset_all() -> None:
    """Drop both cached instances and registered factories (full reset)."""
    _singletons.clear()
    _factories.clear()


# ============================================================================
# Service / adapter registrations (tool-migration phase)
# ============================================================================
#
# Adapters and application services are registered as lazily-created singletons.
# Factories defer the heavyweight imports (which transitively touch ``idaapi``)
# until first use, keeping module import clean outside of IDA.


def _make_debug_adapter():
    from .infrastructure.adapters.debug_adapter import DebugAdapter

    return DebugAdapter()


def _make_debug_service():
    from .application.services.debug_service import DebugService

    return DebugService(get("debug_adapter"))


def _make_stack_adapter():
    from .infrastructure.adapters.stack_adapter import StackAdapter

    return StackAdapter()


def _make_stack_service():
    from .application.services.stack_service import StackService

    return StackService(get("stack_adapter"))


def _make_core_adapter():
    from .infrastructure.adapters.core_adapter import CoreAdapter

    return CoreAdapter()


def _make_core_service():
    from .application.services.core_service import CoreService

    return CoreService(get("core_adapter"))


def _make_memory_adapter():
    from .infrastructure.adapters.memory_adapter import MemoryAdapter

    return MemoryAdapter()


def _make_memory_service():
    from .application.services.memory_service import MemoryService

    return MemoryService(get("memory_adapter"))


def _make_python_exec_adapter():
    from .infrastructure.adapters.python_exec_adapter import PythonExecAdapter

    return PythonExecAdapter()


def _make_python_exec_service():
    from .application.services.python_exec_service import PythonExecService

    return PythonExecService(get("python_exec_adapter"))


def _make_types_adapter():
    from .infrastructure.adapters.types_adapter import TypesAdapter

    return TypesAdapter()


def _make_types_service():
    from .application.services.types_service import TypesService

    return TypesService(get("types_adapter"))


def _make_modify_adapter():
    from .infrastructure.adapters.modify_adapter import ModifyAdapter

    return ModifyAdapter()


def _make_modify_service():
    from .application.services.modify_service import ModifyService

    return ModifyService(get("modify_adapter"))


def _make_security_adapter():
    from .infrastructure.adapters.security_adapter import SecurityAdapter

    return SecurityAdapter()


def _make_security_service():
    from .application.services.security_service import SecurityService

    return SecurityService(get("security_adapter"))


def _make_sigmaker_adapter():
    from .infrastructure.adapters.sigmaker_adapter import SigmakerAdapter

    return SigmakerAdapter()


def _make_sigmaker_service():
    from .application.services.sigmaker_service import SigmakerService

    return SigmakerService(get("sigmaker_adapter"))


def _make_resources_adapter():
    from .infrastructure.adapters.resources_adapter import ResourcesAdapter

    return ResourcesAdapter()


def _make_resources_service():
    from .application.services.resources_service import ResourcesService

    return ResourcesService(get("resources_adapter"))


def _make_analysis_adapter():
    from .infrastructure.adapters.analysis_adapter import AnalysisAdapter

    return AnalysisAdapter()


def _make_analysis_service():
    from .application.services.analysis_service import AnalysisService

    return AnalysisService(get("analysis_adapter"))


def _make_composite_adapter():
    from .infrastructure.adapters.composite_adapter import CompositeAdapter

    return CompositeAdapter()


def _make_composite_service():
    from .application.services.composite_service import CompositeService

    return CompositeService(get("composite_adapter"))


def _make_survey_adapter():
    from .infrastructure.adapters.survey_adapter import SurveyAdapter

    return SurveyAdapter()


def _make_survey_service():
    from .application.services.survey_service import SurveyService

    return SurveyService(get("survey_adapter"))


register_factory("debug_adapter", _make_debug_adapter)
register_factory("debug_service", _make_debug_service)
register_factory("stack_adapter", _make_stack_adapter)
register_factory("stack_service", _make_stack_service)
register_factory("core_adapter", _make_core_adapter)
register_factory("core_service", _make_core_service)
register_factory("memory_adapter", _make_memory_adapter)
register_factory("memory_service", _make_memory_service)
register_factory("python_exec_adapter", _make_python_exec_adapter)
register_factory("python_exec_service", _make_python_exec_service)
register_factory("types_adapter", _make_types_adapter)
register_factory("types_service", _make_types_service)
register_factory("modify_adapter", _make_modify_adapter)
register_factory("modify_service", _make_modify_service)
register_factory("security_adapter", _make_security_adapter)
register_factory("security_service", _make_security_service)
register_factory("sigmaker_adapter", _make_sigmaker_adapter)
register_factory("sigmaker_service", _make_sigmaker_service)
register_factory("resources_adapter", _make_resources_adapter)
register_factory("resources_service", _make_resources_service)
register_factory("analysis_adapter", _make_analysis_adapter)
register_factory("analysis_service", _make_analysis_service)
register_factory("composite_adapter", _make_composite_adapter)
register_factory("composite_service", _make_composite_service)
register_factory("survey_adapter", _make_survey_adapter)
register_factory("survey_service", _make_survey_service)


def get_debug_adapter():
    """Return the debugger SDK adapter singleton."""
    return get("debug_adapter")


def get_debug_service():
    """Return the debugger application service singleton."""
    return get("debug_service")


def get_stack_adapter():
    """Return the stack-frame SDK adapter singleton."""
    return get("stack_adapter")


def get_stack_service():
    """Return the stack-frame application service singleton."""
    return get("stack_service")


def get_core_adapter():
    """Return the core-metadata SDK adapter singleton."""
    return get("core_adapter")


def get_core_service():
    """Return the core-metadata application service singleton."""
    return get("core_service")


def get_memory_adapter():
    """Return the memory read/write SDK adapter singleton."""
    return get("memory_adapter")


def get_memory_service():
    """Return the memory read/write application service singleton."""
    return get("memory_service")


def get_python_exec_adapter():
    """Return the py_eval SDK adapter singleton."""
    return get("python_exec_adapter")


def get_python_exec_service():
    """Return the py_eval application service singleton."""
    return get("python_exec_service")


def get_types_adapter():
    """Return the type-system SDK adapter singleton (api_types domain)."""
    return get("types_adapter")


def get_types_service():
    """Return the type-system application service singleton (api_types domain)."""
    return get("types_service")


def get_modify_adapter():
    """Return the IDB-mutation SDK adapter singleton (api_modify domain)."""
    return get("modify_adapter")


def get_modify_service():
    """Return the IDB-mutation application service singleton (api_modify domain)."""
    return get("modify_service")


def get_security_adapter():
    """Return the security-analysis SDK adapter singleton (api_security domain)."""
    return get("security_adapter")


def get_security_service():
    """Return the security-analysis application service singleton (api_security domain)."""
    return get("security_service")


def get_sigmaker_adapter():
    """Return the sigmaker SDK adapter singleton (api_sigmaker domain)."""
    return get("sigmaker_adapter")


def get_sigmaker_service():
    """Return the sigmaker application service singleton (api_sigmaker domain)."""
    return get("sigmaker_service")


def get_resources_adapter():
    """Return the browsable-resources SDK adapter singleton (api_resources domain)."""
    return get("resources_adapter")


def get_resources_service():
    """Return the browsable-resources application service singleton (api_resources domain)."""
    return get("resources_service")


def get_analysis_adapter():
    """Return the code-analysis SDK adapter singleton (api_analysis domain)."""
    return get("analysis_adapter")


def get_analysis_service():
    """Return the code-analysis application service singleton (api_analysis domain)."""
    return get("analysis_service")


def get_composite_adapter():
    """Return the composite-analysis SDK adapter singleton (api_composite domain)."""
    return get("composite_adapter")


def get_composite_service():
    """Return the composite-analysis application service singleton (api_composite domain)."""
    return get("composite_service")


def get_survey_adapter():
    """Return the binary-survey SDK adapter singleton (api_survey domain)."""
    return get("survey_adapter")


def get_survey_service():
    """Return the binary-survey application service singleton (api_survey domain)."""
    return get("survey_service")


__all__ = [
    "register_factory",
    "get",
    "has",
    "reset_container",
    "reset_all",
    "get_debug_adapter",
    "get_debug_service",
    "get_stack_adapter",
    "get_stack_service",
    "get_core_adapter",
    "get_core_service",
    "get_memory_adapter",
    "get_memory_service",
    "get_python_exec_adapter",
    "get_python_exec_service",
    "get_types_adapter",
    "get_types_service",
    "get_modify_adapter",
    "get_modify_service",
    "get_security_adapter",
    "get_security_service",
    "get_sigmaker_adapter",
    "get_sigmaker_service",
    "get_resources_adapter",
    "get_resources_service",
    "get_analysis_adapter",
    "get_analysis_service",
    "get_composite_adapter",
    "get_composite_service",
    "get_survey_adapter",
    "get_survey_service",
]

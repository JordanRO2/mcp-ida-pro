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


__all__ = [
    "register_factory",
    "get",
    "has",
    "reset_container",
    "reset_all",
]

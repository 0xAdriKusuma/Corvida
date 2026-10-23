"""
core/registry.py — Global registries for loaders, backends, analyzers, reporters.

Design philosophy
-----------------
* Adding a new component = create a new file, decorate the class.
* The registry itself never changes.
* Three separate registries avoid name collisions between component types.

Usage
-----
# Registering (in e.g. analyzers/pwn/checksec.py)
    @register_analyzer
    class ChecksecAnalyzer(BaseAnalyzer):
        name = "checksec"
        ...

# Discovering (in pipeline.py)
    from corvida.core.registry import analyzer_registry
    for cls in analyzer_registry.all():
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from corvida.loaders.base import BaseLoader
    from corvida.backends.base import BaseBackend
    from corvida.analyzers.base import BaseAnalyzer
    from corvida.reporters.base import BaseReporter

T = TypeVar("T")


class Registry(dict[str, type]):
    """
    Simple name → class registry.

    Keys are the component's ``name`` class attribute.
    """

    def register(self, cls: type) -> type:
        """Register a class.  Used as a decorator or called directly."""
        key: str = getattr(cls, "name", None) or cls.__name__
        if key in self:
            raise ValueError(
                f"Duplicate registration: '{key}' already registered as {self[key]!r}"
            )
        self[key] = cls
        return cls

    def all(self) -> list[type]:
        return list(self.values())

    def get_or_raise(self, name: str) -> type:
        try:
            return self[name]
        except KeyError:
            available = ", ".join(self.keys()) or "<none>"
            raise KeyError(
                f"Component '{name}' not found in registry. Available: {available}"
            )


loader_registry:   Registry = Registry()
backend_registry:  Registry = Registry()
analyzer_registry: Registry = Registry()
reporter_registry: Registry = Registry()


def register_loader(cls: type) -> type:
    """Register an ELF/PE loader."""
    return loader_registry.register(cls)


def register_backend(cls: type) -> type:
    """Register a backend (rizin, etc.)."""
    return backend_registry.register(cls)


def register_analyzer(cls: type) -> type:
    """Register an analyzer."""
    return analyzer_registry.register(cls)


def register_reporter(cls: type) -> type:
    """Register a reporter."""
    return reporter_registry.register(cls)


def _import_all() -> None:
    """
    Import every module that contains registered components.

    Called once at startup (from pipeline.py or cli.py).
    """
    import importlib, traceback

    MODULES = [
        "corvida.loaders.elf",
        "corvida.backends.rizin",
        "corvida.analyzers.common.strings",
        "corvida.analyzers.pwn.binary_info",
        "corvida.analyzers.pwn.checksec",
        "corvida.analyzers.pwn.dangerous_funcs",
        "corvida.reporters.terminal",
        "corvida.reporters.json_out",
    ]

    for mod in MODULES:
        try:
            importlib.import_module(mod)
        except Exception as exc:          # noqa: BLE001
            import warnings
            warnings.warn(
                f"[registry] Could not import '{mod}': {exc}",
                stacklevel=2,
            )

"""
core/module_loader.py — Dynamic module discovery and loading.

Scans the modules/ directory for Python files, imports each one, finds
the class that subclasses BaseModule, and registers it.
Adding a new module = drop a .py file in modules/. No other changes needed.
"""
from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Type

from core.base_module import BaseModule

logger = logging.getLogger("red-team.loader")


def discover_modules(package_path: str = "modules") -> dict[str, BaseModule]:
    """
    Import all modules under `package_path`, instantiate every class
    that subclasses BaseModule, and return {module_id: instance}.
    """
    registry: dict[str, BaseModule] = {}

    pkg_dir = Path(__file__).resolve().parent.parent / package_path
    if not pkg_dir.is_dir():
        logger.warning("Module directory not found: %s", pkg_dir)
        return registry

    for info in pkgutil.iter_modules([str(pkg_dir)]):
        if info.name.startswith("_"):
            continue
        fqn = f"{package_path}.{info.name}"
        try:
            mod = importlib.import_module(fqn)
        except Exception as exc:
            logger.error("Failed to import %s: %s", fqn, exc)
            continue

        for attr_name, attr in inspect.getmembers(mod, inspect.isclass):
            if (
                issubclass(attr, BaseModule)
                and attr is not BaseModule
                and getattr(attr, "module_id", "")
            ):
                try:
                    instance = attr()
                    registry[instance.module_id] = instance
                    logger.info("Loaded module: %s (%s)", instance.module_id, instance.name)
                except Exception as exc:
                    logger.error("Failed to instantiate %s: %s", attr_name, exc)

    logger.info("Discovered %d attack modules.", len(registry))
    return registry

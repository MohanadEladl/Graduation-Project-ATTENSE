"""ATTENSE_app.blueteam — proxy package exposing the existing blueteam app

This package forwards imports to the top-level `blueteam` package so the
backend can be referenced via `ATTENSE_app.blueteam` without duplicating code.
"""
from .main import app

__all__ = ["app"]

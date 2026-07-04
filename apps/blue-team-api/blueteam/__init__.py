"""blueteam — Blue Team service package.

Built both ways from this one source tree: embedded in attense-app's own
process (see apps/control-api/controller.py, which imports blueteam.main
directly and runs it on its own uvicorn thread) and standalone, for per-room
containers (see Dockerfile + supervisord.conf in this same directory).
"""
from .main import app

__all__ = ["app"]

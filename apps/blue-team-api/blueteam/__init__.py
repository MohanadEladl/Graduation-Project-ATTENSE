"""blueteam — Blue Team service package.

Built both ways from this one source tree: embedded in attense-app's own
process (see apps/control-api/controller.py, which imports blueteam.main
directly and runs it on its own uvicorn thread) and standalone, for per-room
containers (see Dockerfile + supervisord.conf in this same directory).
"""
__all__ = ["app"]


def __getattr__(name: str):
    """Load the FastAPI application only when a caller explicitly requests it.

    Domain modules such as webhook translators must remain importable without
    constructing the API and all of its external-service dependencies.
    """
    if name == "app":
        from .main import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

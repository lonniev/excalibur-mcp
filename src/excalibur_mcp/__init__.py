"""eXcalibur-mcp: Sword-swift posting of pretty tweets to X."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version


def _resolve_version() -> str:
    """Single source of truth: pyproject [project].version. Installed metadata
    first, with a from-source pyproject.toml fallback for deploys that run the
    checkout without installing it."""
    try:
        return _pkg_version("excalibur-mcp")
    except PackageNotFoundError:
        pass
    try:
        from pathlib import Path

        import tomllib
        for parent in Path(__file__).resolve().parents:
            pp = parent / "pyproject.toml"
            if pp.is_file():
                with pp.open("rb") as fh:
                    return tomllib.load(fh)["project"]["version"]
    except Exception:
        pass
    return "0.0.0"


__version__ = _resolve_version()

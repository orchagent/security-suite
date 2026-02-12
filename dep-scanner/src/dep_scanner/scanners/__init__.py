"""Scanner modules for different package managers."""

from .npm import detect_npm, run_npm_audit, get_npm_package_count
from .pip import detect_python_deps, run_pip_audit, get_pip_package_count

__all__ = [
    "detect_npm",
    "run_npm_audit",
    "get_npm_package_count",
    "detect_python_deps",
    "run_pip_audit",
    "get_pip_package_count",
]

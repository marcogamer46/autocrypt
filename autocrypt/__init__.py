"""autocrypt — CLI CTF crypto auto-solver.

Fingerprints an unknown blob and runs a best-first layered decode search over
ciphers, encodings, and exact math attacks. The console entry point is
``autocrypt.cli:main``; ``autocrypt --update`` self-updates an installed copy.

The package ``__init__`` stays intentionally minimal: it only re-exports the
CLI entry points and registers the solver registry. It must NOT import
``autocrypt.ui`` eagerly (ui.py imports this package back, so an eager import
would create a circular-init crash).
"""

from autocrypt._version import __version__
from autocrypt.cli import build_parser, main, solve_data
from autocrypt import solvers as _solvers_reg  # noqa: F401  register built-ins

__all__ = ["__version__", "main", "solve_data", "build_parser"]

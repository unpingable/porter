"""Porter: a courier that runs commands on a declared substrate and keeps receipts."""

__version__ = "0.0.1"

from .api import run

__all__ = ["__version__", "run"]

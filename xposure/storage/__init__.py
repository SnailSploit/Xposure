"""Storage module for X-POSURE persistence."""

from .database import Database, get_database

__all__ = [
    'Database',
    'get_database',
]

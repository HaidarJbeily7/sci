"""
Version management for SCI.

This module provides the single source of truth for the package version.
The version is read by setuptools during build and can be imported at runtime.
"""

__version__ = "0.1.0"
__version_info__ = tuple(int(x) for x in __version__.split("."))

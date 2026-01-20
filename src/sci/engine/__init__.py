"""
SCI Engine module for orchestrating security scans.

This module provides the GarakEngine class that coordinates the complete
scan lifecycle including profile loading, probe/detector mapping,
scan execution, and result aggregation.
"""

from sci.engine.garak_engine import GarakEngine

__all__ = ["GarakEngine"]

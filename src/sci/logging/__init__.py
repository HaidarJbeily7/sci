"""
SCI Logging Infrastructure.

This package provides structured logging for the Security-Centered Intelligence framework,
optimized for both development (console output) and CI/CD (JSON output) environments.
"""

from sci.logging.setup import (
    get_logger,
    log_error,
    log_execution_context,
    log_execution_end,
    log_execution_start,
    setup_logging,
)

__all__ = [
    "setup_logging",
    "get_logger",
    "log_execution_start",
    "log_execution_end",
    "log_error",
    "log_execution_context",
]

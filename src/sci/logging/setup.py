"""
Logging setup and configuration for SCI.

This module configures structured logging using structlog, providing
both human-readable console output and machine-parseable JSON output
for CI/CD environments.
"""

import logging
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Generator, Optional

import structlog

# Session ID for correlating logs within a single execution
_session_id: Optional[str] = None

# Track if logging has been configured
_logging_configured = False


def get_session_id() -> str:
    """Get or create a session ID for the current execution."""
    global _session_id
    if _session_id is None:
        _session_id = str(uuid.uuid4())[:8]
    return _session_id


def setup_logging(
    level: str = "INFO",
    format_type: str = "console",
    output: str = "stdout",
) -> None:
    """
    Configure logging for SCI.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Output format ("json" for CI/CD, "console" for development)
        output: Output destination ("stdout", "stderr", or file path)
    """
    global _logging_configured

    # Convert level string to logging level
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Determine output stream
    if output == "stdout":
        stream = sys.stdout
    elif output == "stderr":
        stream = sys.stderr
    else:
        # File output
        stream = open(output, "a", encoding="utf-8")  # noqa: SIM115

    # Configure shared processors
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if format_type == "json":
        # JSON output for CI/CD
        processors = [
            *shared_processors,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console output for development
        processors = [
            *shared_processors,
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            ),
        ]

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=stream,
        level=log_level,
        force=True,
    )

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _logging_configured = True

    # Log initialization
    logger = get_logger(__name__)
    logger.debug(
        "logging_initialized",
        level=level,
        format=format_type,
        output=output,
        session_id=get_session_id(),
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured structlog logger with session context
    """
    if not _logging_configured:
        # Apply default configuration if not yet configured
        setup_logging()

    logger = structlog.get_logger(name)
    return logger.bind(session_id=get_session_id())


def log_execution_start(command: str, config: Optional[dict] = None) -> float:
    """
    Log the start of a command execution.

    Args:
        command: Command being executed
        config: Configuration dictionary (secrets will be masked)

    Returns:
        Start timestamp for duration calculation
    """
    logger = get_logger("sci.execution")
    start_time = time.perf_counter()

    # Mask any secrets in config
    safe_config = _mask_config(config) if config else None

    logger.info(
        "execution_started",
        command=command,
        config=safe_config,
        timestamp=datetime.now(tz=UTC).isoformat(),
    )

    return start_time


def log_execution_end(
    command: str,
    start_time: float,
    status: str = "success",
    result: Optional[dict] = None,
) -> None:
    """
    Log the end of a command execution.

    Args:
        command: Command that was executed
        start_time: Start timestamp from log_execution_start
        status: Execution status (success, failure, error)
        result: Optional result summary
    """
    logger = get_logger("sci.execution")
    duration_ms = (time.perf_counter() - start_time) * 1000

    logger.info(
        "execution_completed",
        command=command,
        status=status,
        duration_ms=round(duration_ms, 2),
        result=result,
        timestamp=datetime.now(tz=UTC).isoformat(),
    )


def log_error(
    error: Exception,
    context: Optional[dict] = None,
    command: Optional[str] = None,
) -> None:
    """
    Log an error with full context.

    Args:
        error: Exception that occurred
        context: Additional context information
        command: Command during which error occurred
    """
    logger = get_logger("sci.error")

    logger.error(
        "error_occurred",
        error_type=type(error).__name__,
        error_message=str(error),
        command=command,
        context=context,
        timestamp=datetime.now(tz=UTC).isoformat(),
        exc_info=error,
    )


@contextmanager
def log_execution_context(
    command: str,
    config: Optional[dict] = None,
) -> Generator[None, None, None]:
    """
    Context manager for logging command execution with timing.

    Usage:
        with log_execution_context("sci run"):
            # Command execution
            pass

    Args:
        command: Command being executed
        config: Configuration dictionary
    """
    start_time = log_execution_start(command, config)
    status = "success"
    error_result: Optional[dict[str, Any]] = None

    try:
        yield
    except Exception as e:
        status = "error"
        error_result = {
            "error_type": type(e).__name__,
            "error_message": str(e),
        }
        log_error(e, command=command)
        raise
    finally:
        log_execution_end(command, start_time, status, error_result)


def _mask_config(config: dict) -> dict:
    """Mask sensitive values in configuration for logging."""
    sensitive_keys = {
        "api_key",
        "secret",
        "password",
        "token",
        "access_key",
        "secret_key",
        "access_key_id",
        "secret_access_key",
        "credentials",
    }

    def mask_dict(d: dict) -> dict:
        masked = {}
        for key, value in d.items():
            key_lower = key.lower()
            if isinstance(value, dict):
                masked[key] = mask_dict(value)
            elif any(sensitive in key_lower for sensitive in sensitive_keys):
                masked[key] = "***"
            else:
                masked[key] = value
        return masked

    return mask_dict(config)

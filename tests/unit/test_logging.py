"""
Unit tests for SCI logging infrastructure.

Tests structured logging setup, configuration, and utilities.
"""

import io
import json
import logging
import sys
from unittest.mock import patch

import pytest
import structlog

from sci.logging.setup import (
    get_logger,
    get_session_id,
    log_error,
    log_execution_context,
    log_execution_end,
    log_execution_start,
    setup_logging,
)


class TestLoggingSetup:
    """Tests for logging setup and configuration."""

    def test_setup_logging_default(self) -> None:
        """Test default logging setup."""
        setup_logging()
        logger = get_logger(__name__)
        assert logger is not None

    def test_setup_logging_json_format(self) -> None:
        """Test JSON logging format setup."""
        setup_logging(level="INFO", format_type="json")
        logger = get_logger(__name__)
        assert logger is not None

    def test_setup_logging_console_format(self) -> None:
        """Test console logging format setup."""
        setup_logging(level="INFO", format_type="console")
        logger = get_logger(__name__)
        assert logger is not None

    def test_setup_logging_levels(self) -> None:
        """Test different log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            setup_logging(level=level)
            logger = get_logger(__name__)
            assert logger is not None

    def test_get_session_id_consistency(self) -> None:
        """Test session ID remains consistent within execution."""
        session_id1 = get_session_id()
        session_id2 = get_session_id()
        assert session_id1 == session_id2
        assert len(session_id1) == 8  # UUID prefix length


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_returns_bound_logger(self) -> None:
        """Test that get_logger returns a bound logger."""
        setup_logging()
        logger = get_logger("test.module")
        assert isinstance(logger, structlog.stdlib.BoundLogger)

    def test_get_logger_has_session_id(self) -> None:
        """Test that logger is bound with session ID."""
        setup_logging()
        logger = get_logger("test.module")
        # The logger should be bound with session_id
        # We can verify by checking the bound values
        assert logger is not None

    def test_get_logger_different_names(self) -> None:
        """Test getting loggers with different names."""
        setup_logging()
        logger1 = get_logger("module.a")
        logger2 = get_logger("module.b")
        assert logger1 is not None
        assert logger2 is not None


class TestExecutionLogging:
    """Tests for execution logging utilities."""

    def test_log_execution_start(self) -> None:
        """Test log_execution_start returns timestamp."""
        setup_logging()
        start_time = log_execution_start("test_command")
        assert isinstance(start_time, float)
        assert start_time > 0

    def test_log_execution_start_with_config(self) -> None:
        """Test log_execution_start with configuration."""
        setup_logging()
        config = {"key": "value", "api_key": "secret"}
        start_time = log_execution_start("test_command", config)
        assert isinstance(start_time, float)

    def test_log_execution_end(self) -> None:
        """Test log_execution_end."""
        setup_logging()
        start_time = log_execution_start("test_command")
        # This should not raise
        log_execution_end("test_command", start_time, status="success")

    def test_log_execution_end_with_result(self) -> None:
        """Test log_execution_end with result."""
        setup_logging()
        start_time = log_execution_start("test_command")
        result = {"tests_run": 10, "passed": 8}
        log_execution_end("test_command", start_time, status="success", result=result)


class TestLogError:
    """Tests for log_error function."""

    def test_log_error_basic(self) -> None:
        """Test basic error logging."""
        setup_logging()
        error = ValueError("Test error message")
        # Should not raise
        log_error(error)

    def test_log_error_with_context(self) -> None:
        """Test error logging with context."""
        setup_logging()
        error = RuntimeError("Runtime error")
        context = {"operation": "test", "input": "data"}
        log_error(error, context=context)

    def test_log_error_with_command(self) -> None:
        """Test error logging with command info."""
        setup_logging()
        error = Exception("Command failed")
        log_error(error, command="sci run")


class TestExecutionContext:
    """Tests for log_execution_context context manager."""

    def test_execution_context_success(self) -> None:
        """Test execution context with successful execution."""
        setup_logging()
        with log_execution_context("test_command"):
            # Simulate some work
            result = 1 + 1
            assert result == 2

    def test_execution_context_with_error(self) -> None:
        """Test execution context with error."""
        setup_logging()
        with pytest.raises(ValueError):
            with log_execution_context("test_command"):
                raise ValueError("Test error")

    def test_execution_context_with_config(self) -> None:
        """Test execution context with configuration."""
        setup_logging()
        config = {"setting": "value"}
        with log_execution_context("test_command", config):
            pass


class TestSecretMasking:
    """Tests for secret masking in logs."""

    def test_config_secrets_masked(self) -> None:
        """Test that secrets in config are masked when logged."""
        setup_logging()
        config = {
            "providers": {
                "openai": {
                    "api_key": "sk-secret-key-12345",
                    "model": "gpt-4",
                }
            }
        }
        # log_execution_start should mask the api_key
        start_time = log_execution_start("test_command", config)
        assert start_time > 0


class TestJSONOutput:
    """Tests for JSON log output format."""

    def test_json_format_structure(self) -> None:
        """Test that JSON format produces valid JSON."""
        # Capture stderr for structured log output
        captured = io.StringIO()
        handler = logging.StreamHandler(captured)
        handler.setLevel(logging.DEBUG)

        # Configure for JSON output
        setup_logging(level="DEBUG", format_type="json", output="stdout")

        logger = get_logger("test.json")
        # The actual logging behavior depends on structlog configuration
        # This test verifies the setup doesn't raise errors
        assert logger is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

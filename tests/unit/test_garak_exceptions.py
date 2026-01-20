"""
Unit tests for garak custom exceptions and utilities.

Tests the exception hierarchy, retry logic, timeout handling,
and validation utilities.
"""

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sci.engine.exceptions import (
    GarakConfigurationError,
    GarakConnectionError,
    GarakExecutionError,
    GarakInstallationError,
    GarakIntegrationError,
    GarakTimeoutError,
    GarakValidationError,
    ScanCheckpoint,
    TimeoutHandler,
    get_detector_suggestions,
    get_probe_suggestions,
    get_similar_names,
    is_transient_error,
    retry_on_transient_error,
    validate_api_key_format,
    validate_endpoint_url,
    validate_model_name,
    with_timeout,
)


class TestGarakIntegrationError:
    """Tests for the base GarakIntegrationError class."""

    def test_basic_error(self) -> None:
        """Test creating basic error."""
        error = GarakIntegrationError(
            message="Test error message",
            error_code="TEST_001",
        )

        assert "Test error message" in str(error)
        assert "TEST_001" in str(error)

    def test_error_with_tips(self) -> None:
        """Test error with troubleshooting tips."""
        error = GarakIntegrationError(
            message="Test error",
            error_code="TEST_002",
            troubleshooting_tips=["Try this", "Or try that"],
        )

        error_str = str(error)
        assert "Troubleshooting" in error_str
        assert "Try this" in error_str
        assert "Or try that" in error_str

    def test_error_with_context(self) -> None:
        """Test error with context dictionary."""
        error = GarakIntegrationError(
            message="Test error",
            context={"key1": "value1", "key2": "value2"},
        )

        error_str = str(error)
        assert "Context" in error_str
        assert "key1" in error_str

    def test_from_exception(self) -> None:
        """Test creating error from another exception."""
        original = ValueError("Original error")
        error = GarakIntegrationError.from_exception(
            original, context={"extra": "info"}
        )

        assert "Original error" in str(error)
        assert error.context["original_exception"] == "ValueError"


class TestGarakConfigurationError:
    """Tests for GarakConfigurationError class."""

    def test_basic_config_error(self) -> None:
        """Test creating basic configuration error."""
        error = GarakConfigurationError(
            message="Invalid configuration",
            field_name="api_key",
            expected_format="sk-xxx...",
        )

        assert error.field_name == "api_key"
        assert error.expected_format == "sk-xxx..."
        assert "CONFIG" in error.error_code

    def test_config_error_context(self) -> None:
        """Test that field info is added to context."""
        error = GarakConfigurationError(
            message="Test",
            field_name="endpoint",
            expected_format="https://...",
        )

        assert error.context["field_name"] == "endpoint"
        assert error.context["expected_format"] == "https://..."


class TestGarakConnectionError:
    """Tests for GarakConnectionError class."""

    def test_basic_connection_error(self) -> None:
        """Test creating basic connection error."""
        error = GarakConnectionError(
            message="Connection failed",
            provider="openai",
            retry_count=3,
        )

        assert error.provider == "openai"
        assert error.retry_count == 3
        assert "CONN" in error.error_code

    def test_connection_error_tips(self) -> None:
        """Test that connection error includes provider-specific tips."""
        error = GarakConnectionError(
            message="Auth failed",
            provider="openai",
        )

        error_str = str(error)
        assert "openai" in error_str.lower() or "api" in error_str.lower()


class TestGarakExecutionError:
    """Tests for GarakExecutionError class."""

    def test_basic_execution_error(self) -> None:
        """Test creating basic execution error."""
        error = GarakExecutionError(
            message="Execution failed",
            probe_name="test.Probe",
            exit_code=1,
            stderr="Error output",
        )

        assert error.probe_name == "test.Probe"
        assert error.exit_code == 1
        assert error.stderr == "Error output"
        assert "EXEC" in error.error_code

    def test_execution_error_truncates_stderr(self) -> None:
        """Test that long stderr is truncated in context."""
        long_stderr = "x" * 500
        error = GarakExecutionError(
            message="Failed",
            stderr=long_stderr,
        )

        assert len(error.context["stderr_preview"]) < len(long_stderr)


class TestGarakTimeoutError:
    """Tests for GarakTimeoutError class."""

    def test_basic_timeout_error(self) -> None:
        """Test creating basic timeout error."""
        error = GarakTimeoutError(
            message="Operation timed out",
            operation="scan",
            timeout_seconds=60,
            elapsed_seconds=65.5,
        )

        assert error.operation == "scan"
        assert error.timeout_seconds == 60
        assert error.elapsed_seconds == 65.5
        assert "TIMEOUT" in error.error_code


class TestGarakValidationError:
    """Tests for GarakValidationError class."""

    def test_basic_validation_error(self) -> None:
        """Test creating basic validation error."""
        error = GarakValidationError(
            message="Invalid probe",
            validation_type="probe",
            suggestions=["similar_probe1", "similar_probe2"],
        )

        assert error.validation_type == "probe"
        assert len(error.suggestions) == 2
        assert "VAL" in error.error_code

    def test_validation_error_includes_suggestions(self) -> None:
        """Test that suggestions are included in tips."""
        error = GarakValidationError(
            message="Test",
            suggestions=["option1", "option2", "option3"],
        )

        error_str = str(error)
        assert "option1" in error_str or "Did you mean" in error_str


class TestGarakInstallationError:
    """Tests for GarakInstallationError class."""

    def test_basic_installation_error(self) -> None:
        """Test creating basic installation error."""
        error = GarakInstallationError(
            message="Garak not found",
            required_version=">=2.0.0",
            installed_version="1.5.0",
        )

        assert error.required_version == ">=2.0.0"
        assert error.installed_version == "1.5.0"
        assert "INSTALL" in error.error_code

    def test_installation_error_tips(self) -> None:
        """Test that installation tips are included."""
        error = GarakInstallationError(message="Not installed")

        error_str = str(error)
        assert "pip" in error_str.lower() or "install" in error_str.lower()


class TestIsTransientError:
    """Tests for is_transient_error function."""

    def test_connection_error_is_transient(self) -> None:
        """Test that ConnectionError is transient."""
        assert is_transient_error(ConnectionError("Network error"))

    def test_timeout_error_is_transient(self) -> None:
        """Test that TimeoutError is transient."""
        assert is_transient_error(TimeoutError("Timeout"))

    def test_garak_connection_error_is_transient(self) -> None:
        """Test that GarakConnectionError is transient."""
        error = GarakConnectionError(message="Connection failed")
        assert is_transient_error(error)

    def test_garak_timeout_error_is_transient(self) -> None:
        """Test that GarakTimeoutError is transient."""
        error = GarakTimeoutError(message="Timeout")
        assert is_transient_error(error)

    def test_rate_limit_is_transient(self) -> None:
        """Test that rate limit errors are transient."""
        assert is_transient_error(Exception("Error 429: Rate limit exceeded"))
        assert is_transient_error(Exception("rate limit reached"))

    def test_server_errors_are_transient(self) -> None:
        """Test that 5xx errors are transient."""
        assert is_transient_error(Exception("Error 502: Bad Gateway"))
        assert is_transient_error(Exception("503 Service Unavailable"))
        assert is_transient_error(Exception("504 Gateway Timeout"))

    def test_value_error_is_not_transient(self) -> None:
        """Test that ValueError is not transient."""
        assert not is_transient_error(ValueError("Invalid value"))

    def test_garak_validation_error_is_not_transient(self) -> None:
        """Test that GarakValidationError is not transient."""
        error = GarakValidationError(message="Invalid probe")
        assert not is_transient_error(error)


class TestRetryOnTransientError:
    """Tests for retry_on_transient_error decorator."""

    def test_successful_function_no_retry(self) -> None:
        """Test that successful function doesn't retry."""
        call_count = 0

        @retry_on_transient_error(max_attempts=3)
        def successful_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = successful_func()

        assert result == "success"
        assert call_count == 1

    def test_retry_on_transient_error(self) -> None:
        """Test retry on transient error."""
        call_count = 0

        @retry_on_transient_error(max_attempts=3, initial_delay=0.01)
        def flaky_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Network error")
            return "success"

        result = flaky_func()

        assert result == "success"
        assert call_count == 3

    def test_no_retry_on_permanent_error(self) -> None:
        """Test no retry on permanent errors."""
        call_count = 0

        @retry_on_transient_error(max_attempts=3)
        def permanent_error_func() -> str:
            nonlocal call_count
            call_count += 1
            raise ValueError("Permanent error")

        with pytest.raises(ValueError):
            permanent_error_func()

        assert call_count == 1

    def test_max_attempts_exceeded(self) -> None:
        """Test that exception is raised after max attempts."""
        call_count = 0

        @retry_on_transient_error(max_attempts=3, initial_delay=0.01)
        def always_fails() -> None:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Always fails")

        with pytest.raises(ConnectionError):
            always_fails()

        assert call_count == 3


class TestTimeoutHandler:
    """Tests for TimeoutHandler context manager."""

    def test_no_timeout(self) -> None:
        """Test operation completes before timeout."""
        with TimeoutHandler(timeout_seconds=10, operation="test"):
            time.sleep(0.01)
        # Should not raise

    def test_timeout_check(self) -> None:
        """Test timeout check method."""
        handler = TimeoutHandler(timeout_seconds=0, operation="test")
        handler._timed_out = True
        handler._start_time = time.time()

        with pytest.raises(GarakTimeoutError):
            handler.check_timeout()

    def test_elapsed_property(self) -> None:
        """Test elapsed time property."""
        with TimeoutHandler(timeout_seconds=10, operation="test") as handler:
            time.sleep(0.05)
            elapsed = handler.elapsed

        assert elapsed >= 0.05


class TestWithTimeoutDecorator:
    """Tests for with_timeout decorator."""

    def test_function_completes_in_time(self) -> None:
        """Test function that completes within timeout."""

        @with_timeout(timeout_seconds=5, operation="test")
        def quick_func() -> str:
            return "done"

        result = quick_func()
        assert result == "done"

    def test_function_raises_exception(self) -> None:
        """Test that exceptions are propagated."""

        @with_timeout(timeout_seconds=5, operation="test")
        def error_func() -> None:
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            error_func()


class TestValidationUtilities:
    """Tests for validation utility functions."""

    def test_validate_api_key_format_openai_valid(self) -> None:
        """Test validating valid OpenAI API key."""
        is_valid, error = validate_api_key_format(
            "sk-test1234567890abcdef1234567890abcdef1234",
            "openai",
        )
        assert is_valid
        assert error == ""

    def test_validate_api_key_format_openai_invalid_prefix(self) -> None:
        """Test validating OpenAI key with wrong prefix."""
        is_valid, error = validate_api_key_format(
            "invalid-key-format",
            "openai",
        )
        assert not is_valid
        assert "sk-" in error

    def test_validate_api_key_format_openai_too_short(self) -> None:
        """Test validating too short OpenAI key."""
        is_valid, error = validate_api_key_format("sk-short", "openai")
        assert not is_valid
        assert "short" in error.lower()

    def test_validate_api_key_format_anthropic_valid(self) -> None:
        """Test validating valid Anthropic API key."""
        is_valid, error = validate_api_key_format(
            "sk-ant-test1234567890abcdef1234567890abcdef1234567890",
            "anthropic",
        )
        assert is_valid

    def test_validate_api_key_format_huggingface_valid(self) -> None:
        """Test validating valid HuggingFace token."""
        is_valid, error = validate_api_key_format(
            "hf_test1234567890abcdef1234567890",
            "huggingface",
        )
        assert is_valid

    def test_validate_api_key_format_empty(self) -> None:
        """Test validating empty API key."""
        is_valid, error = validate_api_key_format("", "openai")
        assert not is_valid
        assert "empty" in error.lower()

    def test_validate_model_name_valid(self) -> None:
        """Test validating valid model name."""
        is_valid, suggestions = validate_model_name("gpt-4", "openai")
        assert is_valid

    def test_validate_model_name_empty(self) -> None:
        """Test validating empty model name."""
        is_valid, suggestions = validate_model_name("", "openai")
        assert not is_valid

    def test_validate_endpoint_url_valid(self) -> None:
        """Test validating valid endpoint URL."""
        is_valid, error = validate_endpoint_url(
            "https://api.example.com/v1"
        )
        assert is_valid
        assert error == ""

    def test_validate_endpoint_url_no_scheme(self) -> None:
        """Test validating URL without scheme."""
        is_valid, error = validate_endpoint_url("api.example.com")
        assert not is_valid
        assert "scheme" in error.lower()

    def test_validate_endpoint_url_invalid_scheme(self) -> None:
        """Test validating URL with invalid scheme."""
        is_valid, error = validate_endpoint_url("ftp://api.example.com")
        assert not is_valid
        assert "http" in error.lower()

    def test_validate_endpoint_url_empty(self) -> None:
        """Test validating empty URL."""
        is_valid, error = validate_endpoint_url("")
        assert not is_valid


class TestFuzzyMatching:
    """Tests for fuzzy matching utilities."""

    def test_get_similar_names_basic(self) -> None:
        """Test basic fuzzy matching."""
        candidates = ["promptinject", "jailbreak", "encoding", "leakreplay"]
        similar = get_similar_names("promptinjekt", candidates)

        assert "promptinject" in similar

    def test_get_similar_names_threshold(self) -> None:
        """Test fuzzy matching with threshold."""
        candidates = ["abc", "xyz", "123"]
        similar = get_similar_names("completely_different", candidates, threshold=0.8)

        assert len(similar) == 0

    def test_get_similar_names_max_results(self) -> None:
        """Test that max_results is respected."""
        candidates = ["test1", "test2", "test3", "test4", "test5"]
        similar = get_similar_names("test", candidates, max_results=3)

        assert len(similar) <= 3

    def test_get_probe_suggestions(self) -> None:
        """Test probe suggestions."""
        available = [
            "promptinject.HumanJailbreaks",
            "promptinject.AutoDAN",
            "dan.DAN",
        ]
        suggestions = get_probe_suggestions("promptinject.HumanJailbreak", available)

        assert "promptinject.HumanJailbreaks" in suggestions

    def test_get_detector_suggestions(self) -> None:
        """Test detector suggestions."""
        available = ["toxicity_basic", "toxicity_advanced", "leakage_basic"]
        suggestions = get_detector_suggestions("toxicity_basik", available)

        assert "toxicity_basic" in suggestions


class TestScanCheckpoint:
    """Tests for ScanCheckpoint class."""

    def test_create_checkpoint(self) -> None:
        """Test creating a checkpoint."""
        checkpoint = ScanCheckpoint(
            scan_id="test-001",
            completed_probes=["probe1"],
            pending_probes=["probe2", "probe3"],
        )

        assert checkpoint.scan_id == "test-001"
        assert len(checkpoint.completed_probes) == 1
        assert len(checkpoint.pending_probes) == 2

    def test_checkpoint_to_dict(self) -> None:
        """Test serializing checkpoint to dict."""
        checkpoint = ScanCheckpoint(
            scan_id="test-001",
            completed_probes=["probe1"],
        )

        data = checkpoint.to_dict()

        assert data["scan_id"] == "test-001"
        assert "checkpoint_time" in data

    def test_checkpoint_from_dict(self) -> None:
        """Test deserializing checkpoint from dict."""
        data = {
            "scan_id": "test-001",
            "completed_probes": ["probe1"],
            "failed_probes": [],
            "pending_probes": ["probe2"],
            "partial_results": {},
            "checkpoint_time": "2024-01-15T10:00:00+00:00",
        }

        checkpoint = ScanCheckpoint.from_dict(data)

        assert checkpoint.scan_id == "test-001"
        assert checkpoint.completed_probes == ["probe1"]

    def test_add_completed_probe(self) -> None:
        """Test adding completed probe to checkpoint."""
        checkpoint = ScanCheckpoint(
            scan_id="test-001",
            pending_probes=["probe1", "probe2"],
        )

        checkpoint.add_completed_probe("probe1", {"result": "success"})

        assert "probe1" in checkpoint.completed_probes
        assert "probe1" not in checkpoint.pending_probes
        assert "probe1" in checkpoint.partial_results

    def test_add_failed_probe(self) -> None:
        """Test adding failed probe to checkpoint."""
        checkpoint = ScanCheckpoint(
            scan_id="test-001",
            pending_probes=["probe1", "probe2"],
        )

        checkpoint.add_failed_probe("probe1", "Timeout error")

        assert "probe1" not in checkpoint.pending_probes
        assert len(checkpoint.failed_probes) == 1
        assert checkpoint.failed_probes[0]["probe_name"] == "probe1"
        assert checkpoint.failed_probes[0]["error"] == "Timeout error"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

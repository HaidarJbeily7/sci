"""
Custom exception hierarchy for garak integration.

This module provides a structured exception hierarchy for handling
garak-related errors with actionable troubleshooting guidance.
"""

import functools
import random
import signal
import threading
import time
from difflib import SequenceMatcher
from typing import Any, Callable, Optional, TypeVar
from urllib.parse import urlparse

from sci.logging.setup import get_logger

logger = get_logger(__name__)

# Type variable for generic return types
T = TypeVar("T")


# =============================================================================
# Exception Hierarchy
# =============================================================================


class GarakIntegrationError(Exception):
    """
    Base exception for all garak-related errors.

    Provides structured error information with troubleshooting guidance.

    Attributes:
        message: Human-readable error message.
        error_code: Unique error code for categorization.
        troubleshooting_tips: List of actionable suggestions.
        context: Additional context dictionary.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "GARAK_000",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.troubleshooting_tips = troubleshooting_tips or []
        self.context = context or {}
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Format error message with troubleshooting guidance."""
        parts = [f"[{self.error_code}] {self.message}"]

        if self.troubleshooting_tips:
            parts.append("\n\nTroubleshooting:")
            for i, tip in enumerate(self.troubleshooting_tips, 1):
                parts.append(f"  {i}. {tip}")

        if self.context:
            context_items = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"\n\nContext: {context_items}")

        return "\n".join(parts) if len(parts) > 1 else parts[0]

    def __str__(self) -> str:
        return self._format_message()

    @classmethod
    def from_exception(
        cls,
        exc: Exception,
        context: Optional[dict[str, Any]] = None,
        error_code: Optional[str] = None,
    ) -> "GarakIntegrationError":
        """
        Create a GarakIntegrationError from a standard exception.

        Args:
            exc: The original exception.
            context: Additional context to include.
            error_code: Optional error code override.

        Returns:
            GarakIntegrationError instance wrapping the original exception.
        """
        ctx = context or {}
        ctx["original_exception"] = type(exc).__name__

        return cls(
            message=str(exc),
            error_code=error_code or "GARAK_001",
            troubleshooting_tips=["Check the original error message for details"],
            context=ctx,
        )


class GarakConfigurationError(GarakIntegrationError):
    """
    Configuration validation failures.

    Raised when configuration is invalid, missing required fields,
    or contains unsupported values.

    Attributes:
        field_name: Name of the invalid field.
        expected_format: Description of expected format.
    """

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        expected_format: Optional[str] = None,
        error_code: str = "CONFIG_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.field_name = field_name
        self.expected_format = expected_format

        ctx = context or {}
        if field_name:
            ctx["field_name"] = field_name
        if expected_format:
            ctx["expected_format"] = expected_format

        tips = troubleshooting_tips or []
        if not tips:
            tips = [
                "Check your configuration file for syntax errors",
                "Verify all required fields are present",
                "See documentation for configuration examples",
            ]

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


class GarakConnectionError(GarakIntegrationError):
    """
    Network/connectivity issues.

    Raised when there are API connection failures, authentication
    errors, or network timeouts.

    Attributes:
        provider: Name of the provider that failed.
        retry_count: Number of retry attempts made.
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        retry_count: int = 0,
        error_code: str = "CONN_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.provider = provider
        self.retry_count = retry_count

        ctx = context or {}
        if provider:
            ctx["provider"] = provider
        ctx["retry_count"] = retry_count

        tips = troubleshooting_tips or []
        if not tips:
            tips = _get_connection_troubleshooting_tips(provider)

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


class GarakExecutionError(GarakIntegrationError):
    """
    Scan execution failures.

    Raised when probe execution fails, detector errors occur,
    or garak CLI returns non-zero exit code.

    Attributes:
        probe_name: Name of the probe that failed.
        exit_code: CLI exit code if applicable.
        stderr: Standard error output from CLI.
    """

    def __init__(
        self,
        message: str,
        probe_name: Optional[str] = None,
        exit_code: Optional[int] = None,
        stderr: Optional[str] = None,
        error_code: str = "EXEC_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.probe_name = probe_name
        self.exit_code = exit_code
        self.stderr = stderr

        ctx = context or {}
        if probe_name:
            ctx["probe_name"] = probe_name
        if exit_code is not None:
            ctx["exit_code"] = exit_code
        if stderr:
            ctx["stderr_preview"] = stderr[:200] + "..." if len(stderr) > 200 else stderr

        tips = troubleshooting_tips or []
        if not tips:
            tips = _get_execution_troubleshooting_tips(stderr)

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


class GarakTimeoutError(GarakIntegrationError):
    """
    Timeout-related errors.

    Raised when operations exceed their time limits.

    Attributes:
        operation: Name of the operation that timed out.
        timeout_seconds: Configured timeout limit.
        elapsed_seconds: Time elapsed before timeout.
    """

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        elapsed_seconds: Optional[float] = None,
        error_code: str = "TIMEOUT_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.operation = operation
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds

        ctx = context or {}
        if operation:
            ctx["operation"] = operation
        if timeout_seconds is not None:
            ctx["timeout_seconds"] = timeout_seconds
        if elapsed_seconds is not None:
            ctx["elapsed_seconds"] = round(elapsed_seconds, 2)

        tips = troubleshooting_tips or []
        if not tips:
            tips = [
                f"Increase the timeout value (current: {timeout_seconds}s)",
                "Reduce the number of probes in the scan",
                "Check network connectivity to the LLM provider",
                "Consider running with fewer parallel executions",
            ]

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


class GarakValidationError(GarakIntegrationError):
    """
    Pre-execution validation failures.

    Raised when probes, detectors, or configurations are not available
    or incompatible.

    Attributes:
        validation_type: Type of validation that failed.
        suggestions: List of suggested alternatives.
    """

    def __init__(
        self,
        message: str,
        validation_type: Optional[str] = None,
        suggestions: Optional[list[str]] = None,
        error_code: str = "VAL_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.validation_type = validation_type
        self.suggestions = suggestions or []

        ctx = context or {}
        if validation_type:
            ctx["validation_type"] = validation_type
        if suggestions:
            ctx["suggestions"] = suggestions[:5]  # Limit to 5 suggestions

        tips = troubleshooting_tips or []
        if not tips and suggestions:
            tips = [f"Did you mean: {', '.join(suggestions[:3])}?"]
        if not tips:
            tips = [
                "Check the spelling of probe/detector names",
                "Run 'sci run probes' to see available probes",
                "Run 'sci run detectors' to see available detectors",
            ]

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


class GarakInstallationError(GarakIntegrationError):
    """
    Garak installation/version issues.

    Raised when garak is not installed or version is incompatible.

    Attributes:
        required_version: Minimum required version.
        installed_version: Currently installed version (if any).
    """

    def __init__(
        self,
        message: str,
        required_version: str = ">=2.0.0",
        installed_version: Optional[str] = None,
        error_code: str = "INSTALL_001",
        troubleshooting_tips: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> None:
        self.required_version = required_version
        self.installed_version = installed_version

        ctx = context or {}
        ctx["required_version"] = required_version
        if installed_version:
            ctx["installed_version"] = installed_version

        tips = troubleshooting_tips or []
        if not tips:
            tips = [
                f"Install garak with: pip install 'garak{required_version}'",
                f"Or with uv: uv add 'garak{required_version}'",
                "Ensure you have Python 3.10 or later installed",
                "Check https://github.com/leondz/garak for installation instructions",
            ]

        super().__init__(
            message=message,
            error_code=error_code,
            troubleshooting_tips=tips,
            context=ctx,
        )


# =============================================================================
# Retry Logic with Exponential Backoff
# =============================================================================


def is_transient_error(exc: Exception) -> bool:
    """
    Determine if an exception represents a transient error that can be retried.

    Args:
        exc: The exception to check.

    Returns:
        True if the error is transient and can be retried.
    """
    # Check exception type
    transient_exception_types = (
        ConnectionError,
        TimeoutError,
        ConnectionResetError,
        BrokenPipeError,
    )
    if isinstance(exc, transient_exception_types):
        return True

    # Check for HTTP status codes in the message
    error_message = str(exc).lower()

    # Rate limiting (429)
    if "429" in error_message or "rate limit" in error_message:
        return True

    # Server errors (5xx)
    server_error_patterns = [
        "502",
        "503",
        "504",
        "bad gateway",
        "service unavailable",
        "gateway timeout",
    ]
    if any(pattern in error_message for pattern in server_error_patterns):
        return True

    # Connection/network errors
    connection_patterns = [
        "timeout",
        "connection reset",
        "temporarily unavailable",
        "connection refused",
        "network unreachable",
        "connection timed out",
        "read timed out",
    ]
    if any(pattern in error_message for pattern in connection_patterns):
        return True

    # GarakConnectionError is always transient
    if isinstance(exc, GarakConnectionError):
        return True

    # GarakTimeoutError is transient
    if isinstance(exc, GarakTimeoutError):
        return True

    return False


def retry_on_transient_error(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    backoff_factor: float = 2.0,
    retriable_exceptions: Optional[tuple[type[Exception], ...]] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that retries a function on transient errors with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts.
        initial_delay: Initial delay between retries in seconds.
        max_delay: Maximum delay between retries in seconds.
        backoff_factor: Multiplier for exponential backoff.
        retriable_exceptions: Tuple of exception types to retry on.
            If None, uses is_transient_error() to determine.

    Returns:
        Decorated function that retries on transient errors.

    Example:
        >>> @retry_on_transient_error(max_attempts=3, initial_delay=1.0)
        ... def call_api():
        ...     # API call that might fail transiently
        ...     pass
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception: Optional[Exception] = None

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    last_exception = exc

                    # Check if exception is retriable
                    should_retry = False
                    if retriable_exceptions:
                        should_retry = isinstance(exc, retriable_exceptions)
                    else:
                        should_retry = is_transient_error(exc)

                    if not should_retry or attempt >= max_attempts - 1:
                        raise

                    # Calculate delay with exponential backoff and jitter
                    delay = min(initial_delay * (backoff_factor**attempt), max_delay)
                    jitter = random.uniform(0, delay * 0.1)
                    total_delay = delay + jitter

                    logger.warning(
                        "retry_attempt",
                        attempt=attempt + 1,
                        max_attempts=max_attempts,
                        delay_seconds=round(total_delay, 2),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:200],
                        function=func.__name__,
                    )

                    time.sleep(total_delay)

            # Should never reach here, but just in case
            if last_exception:
                raise last_exception
            raise RuntimeError("Unexpected retry loop exit")

        return wrapper

    return decorator


# =============================================================================
# Timeout Handling
# =============================================================================


class TimeoutHandler:
    """Context manager for handling timeouts in a cross-platform way."""

    def __init__(self, timeout_seconds: int, operation: str = "operation") -> None:
        self.timeout_seconds = timeout_seconds
        self.operation = operation
        self._timer: Optional[threading.Timer] = None
        self._timed_out = False
        self._start_time: Optional[float] = None

    def _timeout_handler(self) -> None:
        """Handle timeout by setting the flag."""
        self._timed_out = True

    def __enter__(self) -> "TimeoutHandler":
        self._start_time = time.time()
        self._timed_out = False
        self._timer = threading.Timer(self.timeout_seconds, self._timeout_handler)
        self._timer.daemon = True
        self._timer.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if self._timer:
            self._timer.cancel()
        return False

    def check_timeout(self) -> None:
        """Check if timeout has occurred and raise if so."""
        if self._timed_out:
            elapsed = time.time() - (self._start_time or 0)
            raise GarakTimeoutError(
                message=f"Operation '{self.operation}' timed out after {self.timeout_seconds}s",
                operation=self.operation,
                timeout_seconds=self.timeout_seconds,
                elapsed_seconds=elapsed,
            )

    @property
    def elapsed(self) -> float:
        """Get elapsed time since entering context."""
        if self._start_time is None:
            return 0.0
        return time.time() - self._start_time


def with_timeout(
    timeout_seconds: int,
    operation: Optional[str] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator that adds timeout handling to a function.

    Uses signal-based timeout on Unix systems and threading-based
    timeout on Windows.

    Args:
        timeout_seconds: Maximum time allowed for the function to execute.
        operation: Name of the operation (for error messages).

    Returns:
        Decorated function with timeout handling.

    Example:
        >>> @with_timeout(60, operation="scan_execution")
        ... def long_running_scan():
        ...     # Scan logic
        ...     pass
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            op_name = operation or func.__name__
            start_time = time.time()

            # Try signal-based timeout on Unix
            if hasattr(signal, "SIGALRM"):
                return _timeout_with_signal(
                    func, args, kwargs, timeout_seconds, op_name, start_time
                )
            else:
                # Fall back to threading-based timeout on Windows
                return _timeout_with_threading(
                    func, args, kwargs, timeout_seconds, op_name, start_time
                )

        return wrapper

    return decorator


def _timeout_with_signal(
    func: Callable[..., T],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    timeout_seconds: int,
    operation: str,
    start_time: float,
) -> T:
    """Implement timeout using Unix signals."""

    def handler(signum: int, frame: Any) -> None:
        elapsed = time.time() - start_time
        raise GarakTimeoutError(
            message=f"Operation '{operation}' timed out after {timeout_seconds}s",
            operation=operation,
            timeout_seconds=timeout_seconds,
            elapsed_seconds=elapsed,
        )

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout_seconds)

    try:
        return func(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def _timeout_with_threading(
    func: Callable[..., T],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    timeout_seconds: int,
    operation: str,
    start_time: float,
) -> T:
    """Implement timeout using threading (for Windows compatibility)."""
    result: list[T] = []
    exception: list[Exception] = []

    def target() -> None:
        try:
            result.append(func(*args, **kwargs))
        except Exception as e:
            exception.append(e)

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout=timeout_seconds)

    if thread.is_alive():
        elapsed = time.time() - start_time
        raise GarakTimeoutError(
            message=f"Operation '{operation}' timed out after {timeout_seconds}s",
            operation=operation,
            timeout_seconds=timeout_seconds,
            elapsed_seconds=elapsed,
        )

    if exception:
        raise exception[0]

    if not result:
        raise RuntimeError(f"Function {func.__name__} returned no result")

    return result[0]


# =============================================================================
# Validation Utilities
# =============================================================================


def validate_api_key_format(api_key: str, provider: str) -> tuple[bool, str]:
    """
    Validate API key format for a given provider.

    Args:
        api_key: The API key to validate.
        provider: Provider name (openai, anthropic, etc.).

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not api_key or not api_key.strip():
        return False, "API key cannot be empty"

    provider_lower = provider.lower()

    # Provider-specific format validation
    format_rules = {
        "openai": {
            "prefix": "sk-",
            "min_length": 40,
            "description": "OpenAI API keys start with 'sk-' and are at least 40 characters",
        },
        "anthropic": {
            "prefix": "sk-ant-",
            "min_length": 50,
            "description": "Anthropic API keys start with 'sk-ant-' and are at least 50 characters",
        },
        "huggingface": {
            "prefix": "hf_",
            "min_length": 30,
            "description": "HuggingFace tokens start with 'hf_' and are at least 30 characters",
        },
    }

    if provider_lower in format_rules:
        rule = format_rules[provider_lower]
        if not api_key.startswith(rule["prefix"]):
            return False, f"Invalid format: {rule['description']}"
        if len(api_key) < rule["min_length"]:
            return False, f"API key too short: {rule['description']}"

    return True, ""


def validate_model_name(model_name: str, provider: str) -> tuple[bool, list[str]]:
    """
    Validate model name format and suggest corrections.

    Args:
        model_name: The model name to validate.
        provider: Provider name for context.

    Returns:
        Tuple of (is_valid, suggestions).
    """
    if not model_name or not model_name.strip():
        return False, ["Model name cannot be empty"]

    # Known model patterns by provider
    known_models = {
        "openai": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo", "gpt-4o", "gpt-4o-mini"],
        "anthropic": [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
            "claude-2.0",
        ],
        "google": ["gemini-pro", "gemini-1.5-pro", "gemini-1.5-flash"],
    }

    provider_lower = provider.lower()

    # Check if model matches known patterns
    if provider_lower in known_models:
        models = known_models[provider_lower]
        if model_name in models:
            return True, []

        # Find similar models
        suggestions = get_similar_names(model_name, models, threshold=0.5)
        if suggestions:
            return True, suggestions  # Valid but might be a typo

    return True, []  # Accept unknown models (could be valid custom models)


def validate_endpoint_url(url: str) -> tuple[bool, str]:
    """
    Validate endpoint URL format.

    Args:
        url: The URL to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not url or not url.strip():
        return False, "Endpoint URL cannot be empty"

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            return False, "URL must include scheme (http:// or https://)"
        if parsed.scheme not in ("http", "https"):
            return False, "URL scheme must be http or https"
        if not parsed.netloc:
            return False, "URL must include a host"
        return True, ""
    except Exception as e:
        return False, f"Invalid URL format: {e}"


def get_similar_names(
    name: str,
    candidates: list[str],
    threshold: float = 0.6,
    max_results: int = 5,
) -> list[str]:
    """
    Find similar names using fuzzy matching.

    Uses SequenceMatcher for Levenshtein-like distance calculation.

    Args:
        name: The name to find matches for.
        candidates: List of candidate names to compare against.
        threshold: Minimum similarity ratio (0.0 to 1.0).
        max_results: Maximum number of suggestions to return.

    Returns:
        List of similar names sorted by similarity.
    """
    if not name or not candidates:
        return []

    name_lower = name.lower()
    scored: list[tuple[float, str]] = []

    for candidate in candidates:
        ratio = SequenceMatcher(None, name_lower, candidate.lower()).ratio()
        if ratio >= threshold:
            scored.append((ratio, candidate))

    # Sort by similarity (descending)
    scored.sort(key=lambda x: x[0], reverse=True)

    return [s[1] for s in scored[:max_results]]


def get_probe_suggestions(probe_name: str, available_probes: list[str]) -> list[str]:
    """
    Get probe name suggestions using fuzzy matching.

    Args:
        probe_name: The probe name that wasn't found.
        available_probes: List of available probe names.

    Returns:
        List of similar probe names.
    """
    return get_similar_names(probe_name, available_probes, threshold=0.4)


def get_detector_suggestions(
    detector_name: str, available_detectors: list[str]
) -> list[str]:
    """
    Get detector name suggestions using fuzzy matching.

    Args:
        detector_name: The detector name that wasn't found.
        available_detectors: List of available detector names.

    Returns:
        List of similar detector names.
    """
    return get_similar_names(detector_name, available_detectors, threshold=0.4)


# =============================================================================
# Helper Functions for Troubleshooting Tips
# =============================================================================


def _get_connection_troubleshooting_tips(provider: Optional[str]) -> list[str]:
    """Get provider-specific connection troubleshooting tips."""
    base_tips = [
        "Check your internet connectivity",
        "Verify the API endpoint is accessible",
    ]

    provider_tips: dict[str, list[str]] = {
        "openai": [
            "Verify your OpenAI API key is valid and active",
            "Check if your API key has the required permissions",
            "Ensure you haven't exceeded your API rate limits",
            "See https://platform.openai.com/docs for OpenAI documentation",
        ],
        "anthropic": [
            "Verify your Anthropic API key is valid",
            "Check your account status at https://console.anthropic.com",
            "Ensure the API key has not expired",
            "See https://docs.anthropic.com for Anthropic documentation",
        ],
        "azure": [
            "Verify your Azure OpenAI endpoint URL is correct",
            "Check that your deployment name is correct",
            "Ensure your API key and endpoint match the same resource",
            "See Azure OpenAI documentation for setup instructions",
        ],
        "aws": [
            "Verify your AWS credentials (access key and secret key)",
            "Check that your IAM role has Bedrock permissions",
            "Ensure the model is available in your AWS region",
            "See AWS Bedrock documentation for setup instructions",
        ],
        "google": [
            "Verify your Google Cloud API key or credentials",
            "Check that the Vertex AI API is enabled in your project",
            "Ensure your project has billing enabled",
            "See Google Cloud AI documentation for setup instructions",
        ],
        "huggingface": [
            "Verify your HuggingFace API token is valid",
            "Check if the model is available on HuggingFace Hub",
            "Ensure you have access to the model (some require approval)",
            "See https://huggingface.co/docs for HuggingFace documentation",
        ],
    }

    if provider and provider.lower() in provider_tips:
        return provider_tips[provider.lower()] + base_tips

    return base_tips + [
        "Verify your API credentials are correct",
        "Check the provider's status page for outages",
    ]


def _get_execution_troubleshooting_tips(stderr: Optional[str]) -> list[str]:
    """Get execution troubleshooting tips based on stderr output."""
    tips = []

    if stderr:
        stderr_lower = stderr.lower()

        if "authentication" in stderr_lower or "api key" in stderr_lower:
            tips.append("Check that your API key is valid and properly configured")
            tips.append("Ensure the API key is set as an environment variable or in config")

        if "model" in stderr_lower and "not found" in stderr_lower:
            tips.append("Verify the model name is correct")
            tips.append("Check if the model is available for your account/tier")

        if "rate" in stderr_lower or "limit" in stderr_lower:
            tips.append("Wait a few minutes and try again")
            tips.append("Reduce the parallelism setting in your configuration")

        if "permission" in stderr_lower or "access" in stderr_lower:
            tips.append("Check that your API key has the required permissions")
            tips.append("Verify your account has access to the requested features")

    if not tips:
        tips = [
            "Check the error message for specific details",
            "Verify garak is properly installed (pip install 'garak>=2.0.0')",
            "Ensure all probe names are valid",
            "Check the garak documentation for probe-specific requirements",
        ]

    return tips


# =============================================================================
# Checkpoint and Recovery
# =============================================================================


class ScanCheckpoint:
    """
    Represents a checkpoint in a scan for recovery purposes.

    Attributes:
        scan_id: Unique identifier for the scan.
        completed_probes: List of probes that completed successfully.
        failed_probes: List of probes that failed with error details.
        pending_probes: List of probes yet to be executed.
        partial_results: Results collected so far.
        checkpoint_time: ISO timestamp of when checkpoint was created.
    """

    def __init__(
        self,
        scan_id: str,
        completed_probes: Optional[list[str]] = None,
        failed_probes: Optional[list[dict[str, Any]]] = None,
        pending_probes: Optional[list[str]] = None,
        partial_results: Optional[dict[str, Any]] = None,
    ) -> None:
        from datetime import UTC, datetime

        self.scan_id = scan_id
        self.completed_probes = completed_probes or []
        self.failed_probes = failed_probes or []
        self.pending_probes = pending_probes or []
        self.partial_results = partial_results or {}
        self.checkpoint_time = datetime.now(tz=UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert checkpoint to dictionary for serialization."""
        return {
            "scan_id": self.scan_id,
            "completed_probes": self.completed_probes,
            "failed_probes": self.failed_probes,
            "pending_probes": self.pending_probes,
            "partial_results": self.partial_results,
            "checkpoint_time": self.checkpoint_time,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanCheckpoint":
        """Create checkpoint from dictionary."""
        checkpoint = cls(
            scan_id=data["scan_id"],
            completed_probes=data.get("completed_probes", []),
            failed_probes=data.get("failed_probes", []),
            pending_probes=data.get("pending_probes", []),
            partial_results=data.get("partial_results", {}),
        )
        checkpoint.checkpoint_time = data.get("checkpoint_time", checkpoint.checkpoint_time)
        return checkpoint

    def add_completed_probe(self, probe_name: str, results: dict[str, Any]) -> None:
        """Mark a probe as completed with its results."""
        self.completed_probes.append(probe_name)
        if probe_name in self.pending_probes:
            self.pending_probes.remove(probe_name)
        self.partial_results[probe_name] = results

    def add_failed_probe(self, probe_name: str, error: str) -> None:
        """Mark a probe as failed with error details."""
        self.failed_probes.append({
            "probe_name": probe_name,
            "error": error,
        })
        if probe_name in self.pending_probes:
            self.pending_probes.remove(probe_name)


__all__ = [
    # Base exceptions
    "GarakIntegrationError",
    "GarakConfigurationError",
    "GarakConnectionError",
    "GarakExecutionError",
    "GarakTimeoutError",
    "GarakValidationError",
    "GarakInstallationError",
    # Retry logic
    "is_transient_error",
    "retry_on_transient_error",
    # Timeout handling
    "TimeoutHandler",
    "with_timeout",
    # Validation utilities
    "validate_api_key_format",
    "validate_model_name",
    "validate_endpoint_url",
    "get_similar_names",
    "get_probe_suggestions",
    "get_detector_suggestions",
    # Checkpoint
    "ScanCheckpoint",
]

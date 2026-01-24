"""
Garak client wrapper for SCI.

This module provides a Python wrapper around the garak CLI, enabling
programmatic access to garak's security testing capabilities.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import time
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from sci.config.models import GarakConfig
from sci.engine.exceptions import (
    GarakConnectionError,
    GarakExecutionError,
    GarakInstallationError,
    GarakTimeoutError,
    GarakValidationError,
    TimeoutHandler,
    retry_on_transient_error,
)
from sci.logging.setup import get_logger, log_error


class GarakClientWrapper:
    """
    Wrapper for the garak security testing framework.

    This class provides a Python API for running garak probes against LLM
    providers. It handles environment setup, command execution, and result
    parsing.

    Attributes:
        config: GarakConfig instance with framework settings.
        logger: Structured logger for operations.

    Example:
        >>> config = GarakConfig(parallelism=5, timeout=120)
        >>> client = GarakClientWrapper(config)
        >>> results = client.run_scan(
        ...     generator_type="openai",
        ...     model_name="gpt-4",
        ...     probes=["encoding.InjectBase64"],
        ...     env_vars={"OPENAI_API_KEY": "sk-..."},
        ... )
    """

    def __init__(self, config: GarakConfig) -> None:
        """
        Initialize the garak client wrapper.

        Args:
            config: GarakConfig instance with framework settings.

        Raises:
            ImportError: If garak is not installed or version is incompatible.
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.logger.info(
            "garak_client_initialized",
            parallelism=config.parallelism,
            timeout=config.timeout,
            extended_detectors=config.extended_detectors,
        )

        # Validate garak installation on initialization
        self.validate_installation()

    def validate_installation(self) -> bool:
        """
        Validate that garak is properly installed.

        Checks if the garak package is installed and verifies the version
        is compatible (>= 0.13.3).

        Returns:
            True if garak is properly installed.

        Raises:
            GarakInstallationError: If garak is not available or version is incompatible.
        """
        try:
            import garak
            from garak import cli as garak_cli  # noqa: F401

            # Check version
            version = getattr(garak, "__version__", "0.0.0")

            self.logger.debug(
                "garak_installation_validated",
                version=version,
            )

            # Parse version and check >= 0.13.3
            version_parts = version.split(".")
            major = int(version_parts[0]) if len(version_parts) > 0 else 0
            minor = int(version_parts[1]) if len(version_parts) > 1 else 0
            patch = int(version_parts[2].split("-")[0]) if len(version_parts) > 2 else 0

            # Check if version is < 0.13.3
            version_tuple = (major, minor, patch)
            min_version = (0, 13, 3)

            if version_tuple < min_version:
                self.logger.warning(
                    "garak_version_warning",
                    version=version,
                    required=">=0.13.3",
                    message="Garak version may not be fully compatible",
                )

            return True

        except ImportError as e:
            self.logger.error(
                "garak_not_installed",
                error=str(e),
            )
            raise GarakInstallationError(
                message="Garak is not installed or could not be imported",
                required_version=">=0.13.3",
                installed_version=None,
                error_code="INSTALL_001",
            ) from e

    def run_scan(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
        env_vars: dict[str, str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Run a garak security scan against an LLM.

        This method sets up the environment, builds CLI arguments, executes
        garak, and parses the results.

        Args:
            generator_type: Type of generator (e.g., "openai", "anthropic").
            model_name: Name of the model to test.
            probes: List of probe identifiers to execute.
            env_vars: Environment variables for authentication.
            **kwargs: Additional arguments passed to garak.

        Returns:
            Dictionary containing scan results with keys:
            - scan_id: Unique identifier for the scan
            - status: Execution status (success, failure, error)
            - start_time: ISO timestamp of scan start
            - end_time: ISO timestamp of scan end
            - duration_ms: Scan duration in milliseconds
            - generator_type: Type of generator used
            - model_name: Model that was tested
            - probes_executed: List of probes that were run
            - findings: List of vulnerability findings
            - summary: Summary statistics
            - report_path: Path to the detailed report file

        Raises:
            GarakExecutionError: If garak execution fails.
            GarakTimeoutError: If scan exceeds timeout.
            GarakConnectionError: If there are authentication or connectivity issues.
        """
        import uuid

        scan_id = str(uuid.uuid4())[:8]
        start_time = time.perf_counter()
        start_timestamp = datetime.now(tz=UTC).isoformat()

        self.logger.info(
            "scan_started",
            scan_id=scan_id,
            generator_type=generator_type,
            model_name=model_name,
            probes=probes,
            parallelism=self.config.parallelism,
        )

        # Set up output directory (pop to avoid passing twice to _build_cli_args)
        output_dir = _setup_output_directory(
            Path(kwargs.pop("output_dir", tempfile.gettempdir())),
            scan_id,
        )

        # Store original environment
        original_env = os.environ.copy()

        try:
            # Validate CLI arguments before execution
            self.validate_cli_args(generator_type, model_name, probes)

            # Set up environment variables (mask in logs)
            masked_vars = {k: "***" for k in env_vars}
            self.logger.debug(
                "environment_setup",
                env_vars=masked_vars,
            )
            os.environ.update(env_vars)

            # Build CLI arguments
            args = self._build_cli_args(
                generator_type=generator_type,
                model_name=model_name,
                probes=probes,
                output_dir=output_dir,
                **kwargs,
            )

            self.logger.debug(
                "garak_cli_invocation",
                args=_mask_sensitive_args(args),
            )

            # Execute garak with retry logic and timeout
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()

            # Use scan timeout from config
            scan_timeout = getattr(self.config, "scan_timeout", 600)

            with TimeoutHandler(scan_timeout, operation="garak_scan") as timeout:
                exit_code = self._execute_garak_with_retry(
                    args, stdout_capture, stderr_capture, generator_type
                )
                timeout.check_timeout()

            stdout_output = stdout_capture.getvalue()
            stderr_output = stderr_capture.getvalue()

            if exit_code != 0:
                self.logger.error(
                    "garak_execution_failed",
                    exit_code=exit_code,
                    stderr=stderr_output[:1000],  # Truncate for logging
                )
                # Analyze stderr to determine error type
                raise _classify_execution_error(
                    exit_code=exit_code,
                    stderr=stderr_output,
                    generator_type=generator_type,
                    model_name=model_name,
                    probes=probes,
                )

            # Parse results
            report_path = self._find_report_file(output_dir)
            findings = self._parse_garak_report(report_path)

            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000

            result = {
                "scan_id": scan_id,
                "status": "success",
                "start_time": start_timestamp,
                "end_time": datetime.now(tz=UTC).isoformat(),
                "duration_ms": round(duration_ms, 2),
                "generator_type": generator_type,
                "model_name": model_name,
                "probes_executed": probes,
                "findings": findings.get("findings", []),
                "summary": findings.get("summary", {}),
                "report_path": str(report_path) if report_path else None,
            }

            self.logger.info(
                "scan_completed",
                scan_id=scan_id,
                status="success",
                duration_ms=result["duration_ms"],
                findings_count=len(result["findings"]),
            )

            return result

        except (GarakExecutionError, GarakTimeoutError, GarakConnectionError):
            # Re-raise garak-specific exceptions
            raise

        except Exception as e:
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000

            log_error(
                e,
                context={
                    "scan_id": scan_id,
                    "generator_type": generator_type,
                    "model_name": model_name,
                },
                command="garak.run_scan",
            )

            return {
                "scan_id": scan_id,
                "status": "error",
                "start_time": start_timestamp,
                "end_time": datetime.now(tz=UTC).isoformat(),
                "duration_ms": round(duration_ms, 2),
                "generator_type": generator_type,
                "model_name": model_name,
                "probes_executed": probes,
                "findings": [],
                "summary": {},
                "error": {
                    "type": type(e).__name__,
                    "message": str(e),
                },
                "report_path": None,
            }

        finally:
            # Restore original environment
            os.environ.clear()
            os.environ.update(original_env)

    def validate_cli_args(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
    ) -> None:
        """
        Validate CLI arguments before execution.

        Args:
            generator_type: Type of generator.
            model_name: Name of the model.
            probes: List of probe names.

        Raises:
            GarakValidationError: If arguments are invalid.
        """
        errors: list[str] = []

        # Validate generator type
        if not generator_type or not generator_type.strip():
            errors.append("Generator type cannot be empty")

        # Validate model name
        if not model_name or not model_name.strip():
            errors.append("Model name cannot be empty")

        # Validate probes
        if not probes:
            errors.append("At least one probe must be specified")
        else:
            for probe in probes:
                if not probe or not probe.strip():
                    errors.append("Probe names cannot be empty")
                    break

        if errors:
            raise GarakValidationError(
                message=f"Invalid CLI arguments: {'; '.join(errors)}",
                validation_type="cli_args",
                error_code="VAL_002",
                troubleshooting_tips=[
                    "Check that generator_type is a valid provider name",
                    "Ensure model_name is specified",
                    "Verify probe names are valid garak probe identifiers",
                ],
                context={
                    "generator_type": generator_type,
                    "model_name": model_name,
                    "probes_count": len(probes) if probes else 0,
                },
            )

    @retry_on_transient_error(max_attempts=3, initial_delay=1.0, max_delay=30.0)
    def _execute_garak_with_retry(
        self,
        args: list[str],
        stdout: io.StringIO,
        stderr: io.StringIO,
        generator_type: str,
    ) -> int:
        """
        Execute garak CLI with retry logic for transient errors.

        Args:
            args: CLI arguments.
            stdout: StringIO for stdout capture.
            stderr: StringIO for stderr capture.
            generator_type: Type of generator (for error context).

        Returns:
            Exit code from garak execution.
        """
        return self._execute_garak(args, stdout, stderr)

    def _build_cli_args(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
        output_dir: Path,
        **kwargs: Any,
    ) -> list[str]:
        """Build command-line arguments for garak CLI."""
        # Use a simple prefix name, garak will handle the full path
        scan_prefix = f"sci_scan_{output_dir.name}"

        # Use --target_type and --target_name (garak 0.13.x syntax)
        # --model_type and --model_name are deprecated
        args = [
            "--target_type",
            generator_type,
            "--target_name",
            model_name,
            "--probes",
            ",".join(probes),
            "--parallel_attempts",
            str(self.config.parallelism),
            "--report_prefix",
            scan_prefix,
        ]

        # Add extended detectors flag if enabled
        if self.config.extended_detectors:
            args.append("--extended_detectors")

        # Add sample limit if configured
        if self.config.limit_samples is not None:
            args.extend(["--generations", str(self.config.limit_samples)])

        # Skip kwargs that are not valid garak CLI args
        skip_keys = {"output_dir", "api_base", "model_name"}

        # Add any additional kwargs as CLI args
        for key, value in kwargs.items():
            if key not in skip_keys:
                arg_name = f"--{key}"
                if isinstance(value, bool):
                    if value:
                        args.append(arg_name)
                else:
                    args.extend([arg_name, str(value)])

        return args

    def _execute_garak(
        self,
        args: list[str],
        stdout: io.StringIO,
        stderr: io.StringIO,
    ) -> int:
        """
        Execute garak CLI as a subprocess.

        Returns the exit code (0 for success).
        """
        import subprocess

        try:
            # Run garak as a subprocess to avoid multiprocessing/pickling issues
            cmd = [sys.executable, "-m", "garak"] + args

            self.logger.debug(
                "garak_subprocess_starting",
                cmd=cmd[:6],  # Log first few args
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.scan_timeout or 600,
                env=os.environ.copy(),
            )

            # Write output to the StringIO objects
            stdout.write(result.stdout)
            stderr.write(result.stderr)

            if result.returncode != 0:
                self.logger.warning(
                    "garak_exit_nonzero",
                    exit_code=result.returncode,
                    stderr_preview=result.stderr[:500] if result.stderr else None,
                )

            return result.returncode

        except subprocess.TimeoutExpired as e:
            stderr.write(f"Garak execution timed out after {self.config.scan_timeout}s\n")
            self.logger.error(
                "garak_execution_timeout",
                timeout=self.config.scan_timeout,
            )
            return 124  # Standard timeout exit code

        except Exception as e:
            stderr.write(f"Garak execution error: {str(e)}\n")
            self.logger.error(
                "garak_execution_exception",
                error=str(e),
                error_type=type(e).__name__,
            )
            return 1

    def _find_report_file(self, output_dir: Path) -> Optional[Path]:
        """Find the garak report file in garak's output directory."""
        # Garak stores reports in its default location: ~/.local/share/garak/garak_runs/
        garak_runs_dir = Path.home() / ".local" / "share" / "garak" / "garak_runs"

        # Search in garak's default output location first
        search_dirs = [garak_runs_dir, output_dir]

        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            # Look for report files with our scan prefix or recent reports
            for pattern in ["**/sci_scan_*.jsonl", "**/sci_scan_*.json", "**/*.report.jsonl", "**/report*.jsonl", "**/report*.json"]:
                matches = list(search_dir.glob(pattern))
                if matches:
                    # Return the most recently modified file
                    return max(matches, key=lambda p: p.stat().st_mtime)

        return None

    def _parse_garak_report(self, report_path: Optional[Path]) -> dict[str, Any]:
        """
        Parse a garak report file.

        Args:
            report_path: Path to the report file.

        Returns:
            Dictionary with findings and summary.
        """
        if report_path is None or not report_path.exists():
            self.logger.warning(
                "report_not_found",
                report_path=str(report_path),
            )
            return {"findings": [], "summary": {}}

        try:
            # Handle both JSON and JSONL formats
            findings = []
            if report_path.suffix == ".jsonl":
                with open(report_path, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line))
            else:
                with open(report_path, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        findings = data
                    elif isinstance(data, dict):
                        findings = data.get("results", data.get("findings", [data]))

            # Generate summary
            summary = self._generate_summary(findings)

            return {
                "findings": findings,
                "summary": summary,
            }

        except (json.JSONDecodeError, OSError) as e:
            self.logger.error(
                "report_parse_error",
                report_path=str(report_path),
                error=str(e),
            )
            return {"findings": [], "summary": {}}

    def _generate_summary(self, findings: list[dict]) -> dict[str, Any]:
        """Generate summary statistics from findings."""
        total = len(findings)
        passed = sum(1 for f in findings if f.get("passed", f.get("status") == "pass"))
        failed = total - passed

        # Count by probe
        probes_summary: dict[str, dict[str, int]] = {}
        for finding in findings:
            probe = finding.get("probe", finding.get("probe_name", "unknown"))
            if probe not in probes_summary:
                probes_summary[probe] = {"passed": 0, "failed": 0}
            if finding.get("passed", finding.get("status") == "pass"):
                probes_summary[probe]["passed"] += 1
            else:
                probes_summary[probe]["failed"] += 1

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(passed / total * 100, 2) if total > 0 else 0.0,
            "probes": probes_summary,
        }

    @lru_cache(maxsize=1)
    def list_available_probes(self) -> list[str]:
        """
        List all available garak probes.

        Returns:
            List of probe identifiers.
        """
        self.logger.debug("listing_available_probes")

        try:
            stdout = io.StringIO()
            stderr = io.StringIO()

            self._execute_garak(["--list_probes"], stdout, stderr)

            output = stdout.getvalue()
            probes = self._parse_list_output(output)

            self.logger.info(
                "probes_listed",
                count=len(probes),
            )

            return probes

        except Exception as e:
            self.logger.error(
                "probe_listing_failed",
                error=str(e),
            )
            return []

    @lru_cache(maxsize=1)
    def list_available_generators(self) -> list[str]:
        """
        List all available garak generators.

        Returns:
            List of generator identifiers.
        """
        self.logger.debug("listing_available_generators")

        try:
            stdout = io.StringIO()
            stderr = io.StringIO()

            self._execute_garak(["--list_generators"], stdout, stderr)

            output = stdout.getvalue()
            generators = self._parse_list_output(output)

            self.logger.info(
                "generators_listed",
                count=len(generators),
            )

            return generators

        except Exception as e:
            self.logger.error(
                "generator_listing_failed",
                error=str(e),
            )
            return []

    def _parse_list_output(self, output: str) -> list[str]:
        """Parse garak's list output to extract identifiers."""
        import re

        # Remove ANSI escape codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        items = []
        for line in output.strip().split("\n"):
            # Strip ANSI codes first
            line = ansi_escape.sub("", line).strip()
            # Skip empty lines, headers, and version info
            if not line or line.startswith("#") or line.startswith("="):
                continue
            if line.startswith("garak "):
                continue
            # Skip module headers (lines with 🌟) and unavailable probes (💤)
            if "🌟" in line or "💤" in line:
                continue
            # Extract the identifier after "probes:" or "detectors:" or "generators:"
            if ":" in line:
                item = line.split(":", 1)[1].strip()
            else:
                item = line.split()[0] if line.split() else ""
            if item and not item.startswith("-"):
                items.append(item)
        return items

    @retry_on_transient_error(max_attempts=2, initial_delay=1.0, max_delay=10.0)
    def validate_connection(
        self,
        generator_type: str,
        env_vars: dict[str, str],
    ) -> bool:
        """
        Validate connection to an LLM provider.

        Attempts a minimal test call to verify credentials and connectivity.

        Args:
            generator_type: Type of generator to test.
            env_vars: Environment variables for authentication.

        Returns:
            True if connection is successful.

        Raises:
            GarakConnectionError: If connection validation fails.
            GarakTimeoutError: If validation times out.
        """
        self.logger.info(
            "validating_connection",
            generator_type=generator_type,
        )

        # Store original environment
        original_env = os.environ.copy()

        # Get connection timeout from config
        connection_timeout = getattr(self.config, "connection_timeout", 30)

        try:
            os.environ.update(env_vars)

            # Use a minimal probe for connection testing
            args = [
                "--model_type",
                generator_type,
                "--model_name",
                "test",  # Will be overridden by most generators
                "--probes",
                "test.Blank",  # Minimal probe
                "--generations",
                "1",  # Single sample
            ]

            stdout = io.StringIO()
            stderr = io.StringIO()

            # Set a short timeout for validation
            with TimeoutHandler(connection_timeout, operation="connection_validation") as timeout:
                exit_code = self._execute_garak(args, stdout, stderr)
                timeout.check_timeout()

            stderr_output = stderr.getvalue()

            # Check for authentication errors
            auth_errors = [
                "authentication",
                "unauthorized",
                "invalid api key",
                "api key",
                "credentials",
            ]

            if any(err in stderr_output.lower() for err in auth_errors):
                self.logger.warning(
                    "connection_validation_failed",
                    generator_type=generator_type,
                    reason="authentication_error",
                )
                raise GarakConnectionError(
                    message=f"Authentication failed for provider '{generator_type}'",
                    provider=generator_type,
                    error_code="CONN_002",
                    troubleshooting_tips=[
                        "Verify your API key is valid and not expired",
                        "Check that the API key has the required permissions",
                        "Ensure the API key is set correctly in environment or config",
                    ],
                )

            if exit_code == 0:
                self.logger.info(
                    "connection_validated",
                    generator_type=generator_type,
                )
                return True

            self.logger.warning(
                "connection_validation_failed",
                generator_type=generator_type,
                exit_code=exit_code,
            )
            raise GarakConnectionError(
                message=f"Connection validation failed for provider '{generator_type}'",
                provider=generator_type,
                error_code="CONN_003",
                context={"exit_code": exit_code, "stderr": stderr_output[:500]},
            )

        except (GarakConnectionError, GarakTimeoutError):
            # Re-raise garak-specific exceptions
            raise

        except Exception as e:
            self.logger.error(
                "connection_validation_error",
                generator_type=generator_type,
                error=str(e),
            )
            raise GarakConnectionError(
                message=f"Connection validation error for provider '{generator_type}': {e}",
                provider=generator_type,
                error_code="CONN_001",
            ) from e

        finally:
            os.environ.clear()
            os.environ.update(original_env)


def _setup_output_directory(base_dir: Path, scan_id: str) -> Path:
    """
    Create a timestamped output directory for scan results.

    Args:
        base_dir: Base directory for output.
        scan_id: Unique scan identifier.

    Returns:
        Path to the scan-specific output directory.
    """
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
    output_dir = base_dir / f"garak_scan_{timestamp}_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _validate_garak_output(output_path: Path) -> bool:
    """
    Validate that garak generated expected output files.

    Args:
        output_path: Path to check for output files.

    Returns:
        True if valid output files exist.
    """
    if not output_path.exists():
        return False

    # Check for any JSON output files
    json_files = list(output_path.glob("*.json")) + list(output_path.glob("*.jsonl"))
    return len(json_files) > 0


def _mask_sensitive_args(args: list[str]) -> list[str]:
    """Mask sensitive values in CLI arguments for logging."""
    sensitive_params = {"--api_key", "--token", "--secret"}
    masked = []
    skip_next = False

    for i, arg in enumerate(args):
        if skip_next:
            masked.append("***")
            skip_next = False
        elif arg.lower() in sensitive_params:
            masked.append(arg)
            skip_next = True
        else:
            masked.append(arg)

    return masked


def _classify_execution_error(
    exit_code: int,
    stderr: str,
    generator_type: str,
    model_name: str,
    probes: list[str],
) -> Exception:
    """
    Classify a garak execution error into the appropriate exception type.

    Args:
        exit_code: The CLI exit code.
        stderr: Standard error output.
        generator_type: Type of generator used.
        model_name: Model that was tested.
        probes: List of probes that were attempted.

    Returns:
        Appropriate exception instance (GarakConnectionError, GarakExecutionError, etc.)
    """
    stderr_lower = stderr.lower()

    # Check for authentication/connection errors
    auth_patterns = [
        "authentication",
        "unauthorized",
        "invalid api key",
        "api key",
        "credentials",
        "401",
        "403",
    ]
    if any(pattern in stderr_lower for pattern in auth_patterns):
        return GarakConnectionError(
            message=f"Authentication failed for provider '{generator_type}'",
            provider=generator_type,
            error_code="CONN_002",
            troubleshooting_tips=[
                "Verify your API key is valid and not expired",
                "Check that the API key has the required permissions",
                "Ensure the API key is set correctly in environment or config",
            ],
            context={
                "exit_code": exit_code,
                "model_name": model_name,
            },
        )

    # Check for connection/network errors
    network_patterns = [
        "connection refused",
        "connection reset",
        "network unreachable",
        "connection timed out",
        "timeout",
        "502",
        "503",
        "504",
    ]
    if any(pattern in stderr_lower for pattern in network_patterns):
        return GarakConnectionError(
            message=f"Network error while connecting to provider '{generator_type}'",
            provider=generator_type,
            error_code="CONN_004",
            troubleshooting_tips=[
                "Check your internet connectivity",
                "Verify the API endpoint is accessible",
                "Check the provider's status page for outages",
            ],
            context={
                "exit_code": exit_code,
                "model_name": model_name,
            },
        )

    # Check for rate limiting
    rate_patterns = ["rate limit", "429", "too many requests"]
    if any(pattern in stderr_lower for pattern in rate_patterns):
        return GarakConnectionError(
            message=f"Rate limit exceeded for provider '{generator_type}'",
            provider=generator_type,
            error_code="CONN_005",
            troubleshooting_tips=[
                "Wait a few minutes and try again",
                "Reduce the parallelism setting in your configuration",
                "Check your API tier and rate limits",
            ],
            context={
                "exit_code": exit_code,
                "model_name": model_name,
            },
        )

    # Check for model-related errors
    model_patterns = ["model not found", "model does not exist", "invalid model"]
    if any(pattern in stderr_lower for pattern in model_patterns):
        return GarakValidationError(
            message=f"Model '{model_name}' not found or unavailable",
            validation_type="model",
            error_code="VAL_003",
            troubleshooting_tips=[
                "Verify the model name is correct",
                "Check if the model is available for your account/tier",
                "Ensure you have access to the specified model",
            ],
            context={
                "model_name": model_name,
                "generator_type": generator_type,
            },
        )

    # Check for probe-related errors
    probe_patterns = ["probe not found", "invalid probe", "no such probe"]
    if any(pattern in stderr_lower for pattern in probe_patterns):
        return GarakValidationError(
            message="One or more specified probes are invalid or unavailable",
            validation_type="probe",
            error_code="VAL_004",
            troubleshooting_tips=[
                "Run 'sci run probes' to see available probes",
                "Check the probe names for typos",
                "Verify garak version supports the requested probes",
            ],
            context={
                "probes": probes[:5],  # Limit to first 5
            },
        )

    # Default to generic execution error
    return GarakExecutionError(
        message=f"Garak execution failed with exit code {exit_code}",
        exit_code=exit_code,
        stderr=stderr,
        error_code="EXEC_001",
        troubleshooting_tips=[
            "Check the error message for specific details",
            "Verify garak is properly installed (pip install 'garak>=0.13.3')",
            "Ensure all probe names are valid",
            "Check the garak documentation for probe-specific requirements",
        ],
        context={
            "generator_type": generator_type,
            "model_name": model_name,
            "probes_count": len(probes),
        },
    )

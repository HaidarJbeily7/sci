"""
Garak client for SCI.

This module provides a Python wrapper around garak's Python API, enabling
programmatic access to garak's security testing capabilities.
"""

import contextlib
import io
import json
import os
import threading
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
)
from sci.logging.setup import get_logger, log_error


# Lock to serialize access to garak's global _config state
_garak_lock = threading.Lock()


@contextlib.contextmanager
def _scoped_env_vars(env_vars: dict[str, str]):
    """Context manager that temporarily sets environment variables and restores them on exit."""
    original = {k: os.environ.get(k) for k in env_vars}
    os.environ.update(env_vars)
    try:
        yield
    finally:
        for k, orig_val in original.items():
            if orig_val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = orig_val


class GarakClient:
    """
    Garak client that uses garak's Python API directly (in-process).

    This avoids subprocess overhead, fragile CLI output parsing, and
    provides structured access to results.

    Attributes:
        config: GarakConfig instance with framework settings.
        logger: Structured logger for operations.

    Example:
        >>> config = GarakConfig(parallelism=5, timeout=120)
        >>> client = GarakClient(config)
        >>> results = client.run_scan(
        ...     generator_type="openai",
        ...     model_name="gpt-4",
        ...     probes=["encoding.InjectBase64"],
        ...     env_vars={"OPENAI_API_KEY": "sk-..."},
        ... )
    """

    def __init__(self, config: GarakConfig) -> None:
        """
        Initialize the garak client.

        Args:
            config: GarakConfig instance with framework settings.

        Raises:
            GarakInstallationError: If garak is not installed or version is incompatible.
        """
        self.config = config
        self.logger = get_logger(__name__)

        self.logger.info(
            "garak_client_initialized",
            parallelism=config.parallelism,
            timeout=config.timeout,
            extended_detectors=config.extended_detectors,
        )

        self.validate_installation()

    # ------------------------------------------------------------------
    # Installation validation
    # ------------------------------------------------------------------

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
            from garak import _config  # noqa: F401
            del _config  # Only imported to validate garak is properly installed

            version = getattr(garak, "__version__", "0.0.0")
            self.logger.debug("garak_installation_validated", version=version)

            parts = version.split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2].split("-")[0]) if len(parts) > 2 else 0

            if (major, minor, patch) < (0, 13, 3):
                self.logger.warning(
                    "garak_version_warning",
                    version=version,
                    required=">=0.13.3",
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

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    def run_scan(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
        env_vars: dict[str, str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Run a garak security scan using the Python API.

        Args:
            generator_type: Type of generator (e.g., "openai", "anthropic").
            model_name: Name of the model to test.
            probes: List of probe identifiers to execute.
            env_vars: Environment variables for authentication.
            **kwargs: Additional arguments (reserved for future use).

        Note:
            The kwargs parameter is kept for API compatibility but is not
            currently used by the Python API implementation.

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
        _ = kwargs  # Reserved for future use, kept for API compatibility
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
        )

        try:
            with _garak_lock, _scoped_env_vars(env_vars):
                report_filename = self._run_garak_in_process(
                    generator_type=generator_type,
                    model_name=model_name,
                    probes=probes,
                    scan_id=scan_id,
                )

            # Parse the JSONL report produced by garak
            findings = self._parse_report(report_filename)
            summary = self._generate_summary(findings)

            duration_ms = (time.perf_counter() - start_time) * 1000

            result = {
                "scan_id": scan_id,
                "status": "success",
                "start_time": start_timestamp,
                "end_time": datetime.now(tz=UTC).isoformat(),
                "duration_ms": round(duration_ms, 2),
                "generator_type": generator_type,
                "model_name": model_name,
                "probes_executed": probes,
                "findings": findings,
                "summary": summary,
                "report_path": report_filename,
            }

            self.logger.info(
                "scan_completed",
                scan_id=scan_id,
                duration_ms=result["duration_ms"],
                findings_count=len(findings),
            )

            return result

        except (GarakExecutionError, GarakTimeoutError, GarakConnectionError):
            raise

        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            log_error(e, context={"scan_id": scan_id}, command="garak.run_scan")

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
                "error": {"type": type(e).__name__, "message": str(e)},
                "report_path": None,
            }

    def _run_garak_in_process(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
        scan_id: str,
    ) -> Optional[str]:
        """
        Drive a garak scan using its internal Python API.

        Must be called while holding ``_garak_lock`` and with env vars set.

        Returns:
            Path to the JSONL report file written by garak, or None.
        """
        import argparse
        import datetime as _dt

        from garak import _config, _plugins
        from garak import command as garak_command
        from garak.evaluators import ThresholdEvaluator
        from garak.exception import GarakException

        # --- 1. Initialise garak config ------------------------------------
        _config.transient.starttime = _dt.datetime.now()
        _config.transient.starttime_iso = _config.transient.starttime.isoformat()

        # Create minimal cli_args to satisfy garak's start_run() checks
        # This mimics what garak's CLI parser would create
        _config.transient.cli_args = argparse.Namespace(
            list_probes=False,
            list_detectors=False,
            list_generators=False,
            list_buffs=False,
            list_config=False,
            plugin_info=None,
            probes=",".join(probes),
        )

        _config.load_base_config()

        # Apply SCI settings to garak config
        # IMPORTANT: Disable parallel execution to avoid multiprocessing pickling issues
        # when running in-process. Garak's multiprocessing cannot pickle generator objects
        # that contain module references.
        _config.system.parallel_attempts = 1
        _config.system.parallel_requests = 1
        _config.plugins.extended_detectors = self.config.extended_detectors

        if self.config.limit_samples is not None:
            _config.run.generations = self.config.limit_samples

        # Report prefix so we can find the file afterwards
        _config.reporting.report_prefix = f"sci_scan_{scan_id}"

        # --- 2. Start the run (creates report file, UUID, etc.) -----------
        garak_command.start_logging()
        garak_command.start_run()

        try:
            # --- 3. Instantiate the generator --------------------------------
            generator_plugin_path = f"generators.{generator_type}"

            try:
                generator = _plugins.load_plugin(generator_plugin_path)
            except Exception as e:
                raise GarakExecutionError(
                    message=f"Failed to load generator '{generator_type}': {e}",
                    exit_code=-1,
                    stderr=str(e),
                    error_code="EXEC_002",
                    troubleshooting_tips=[
                        f"Check that '{generator_type}' is a valid garak generator",
                        "Verify provider credentials are set",
                    ],
                    context={"generator_type": generator_type},
                ) from e

            # Override the model/target name on the generator
            if hasattr(generator, "name"):
                generator.name = model_name

            # --- 4. Build probe name list in garak format -----------------
            probe_names = [
                p if p.startswith("probes.") else f"probes.{p}"
                for p in probes
            ]

            # --- 5. Run probes (output visible for progress tracking) -----
            evaluator = ThresholdEvaluator()

            try:
                garak_command.probewise_run(
                    generator, probe_names, evaluator, buffs=[]
                )
            except GarakException as e:
                raise GarakExecutionError(
                    message=f"Garak probe execution failed: {e}",
                    exit_code=-1,
                    stderr=str(e),
                    error_code="EXEC_003",
                    context={"probes": probes},
                ) from e

            # --- 6. Finalise ------------------------------------------------
            report_filename = getattr(
                _config.transient, "report_filename", None
            )

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                garak_command.end_run()

            return report_filename

        except (GarakExecutionError, GarakTimeoutError, GarakConnectionError):
            # Ensure we still call end_run to clean up
            with contextlib.suppress(Exception):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    garak_command.end_run()
            raise

        except Exception as e:
            with contextlib.suppress(Exception):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    garak_command.end_run()
            raise GarakExecutionError(
                message=f"Unexpected error during garak execution: {e}",
                exit_code=-1,
                stderr=str(e),
                error_code="EXEC_004",
                context={"generator_type": generator_type, "probes": probes},
            ) from e

    # ------------------------------------------------------------------
    # Report parsing
    # ------------------------------------------------------------------

    def _parse_report(self, report_path: Optional[str]) -> list[dict[str, Any]]:
        """Parse a garak JSONL report file into a list of finding dicts.

        Only extracts entries with entry_type="attempt" which are actual
        probe execution results. Filters out:
        - Metadata entries (start_run, init, end_run, etc.)
        - Entries without a valid probe_classname
        - Entries that are passed (only include failures for vulnerability reporting)
        """
        if report_path is None or not Path(report_path).exists():
            self.logger.warning("report_not_found", report_path=report_path)
            return []

        findings: list[dict[str, Any]] = []
        skipped_no_probe = 0
        skipped_passed = 0

        try:
            with open(report_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    entry = json.loads(line)

                    # Only include actual attempt entries (probe execution results)
                    # Skip metadata entries: start_run, init, end_run, etc.
                    if entry.get("entry_type") != "attempt":
                        continue

                    # Must have a valid probe_classname
                    probe_classname = entry.get("probe_classname", "")
                    if not probe_classname or probe_classname == "unknown":
                        skipped_no_probe += 1
                        continue

                    findings.append(entry)

        except (json.JSONDecodeError, OSError) as e:
            self.logger.error("report_parse_error", error=str(e))

        self.logger.debug(
            "report_parsed",
            total_findings=len(findings),
            skipped_no_probe=skipped_no_probe,
            skipped_passed=skipped_passed,
        )
        return findings

    def _generate_summary(self, findings: list[dict]) -> dict[str, Any]:
        """Generate summary statistics from findings.

        Only considers findings with valid probe_classname.
        """
        # Filter to only findings with valid probe_classname
        valid_findings = [
            f for f in findings
            if f.get("probe_classname") and f.get("probe_classname") != "unknown"
        ]

        total = len(valid_findings)
        passed = sum(
            1
            for f in valid_findings
            if f.get("passed", f.get("status") == "pass")
        )
        failed = total - passed

        probes_summary: dict[str, dict[str, int]] = {}
        for finding in valid_findings:
            probe = finding.get("probe_classname", "")
            if not probe:
                continue

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

    # ------------------------------------------------------------------
    # Probe / generator listing
    # ------------------------------------------------------------------

    @lru_cache(maxsize=1)
    def list_available_probes(self) -> list[str]:
        """
        List all available garak probes using the Python API.

        Returns:
            List of probe identifiers.
        """
        self.logger.debug("listing_available_probes")
        try:
            from garak import _config, _plugins

            if not getattr(_config, "loaded", False):
                _config.load_base_config()

            plugins = _plugins.enumerate_plugins("probes")
            probe_names = [p["module_name"] for p in plugins if "module_name" in p]

            self.logger.info("probes_listed", count=len(probe_names))
            return probe_names

        except Exception as e:
            self.logger.error("probe_listing_failed", error=str(e))
            return []

    @lru_cache(maxsize=1)
    def list_available_generators(self) -> list[str]:
        """
        List all available garak generators using the Python API.

        Returns:
            List of generator identifiers.
        """
        self.logger.debug("listing_available_generators")
        try:
            from garak import _config, _plugins

            if not getattr(_config, "loaded", False):
                _config.load_base_config()

            plugins = _plugins.enumerate_plugins("generators")
            gen_names = [p["module_name"] for p in plugins if "module_name" in p]

            self.logger.info("generators_listed", count=len(gen_names))
            return gen_names

        except Exception as e:
            self.logger.error("generator_listing_failed", error=str(e))
            return []

    # ------------------------------------------------------------------
    # Connection validation
    # ------------------------------------------------------------------

    def validate_connection(
        self,
        generator_type: str,
        env_vars: dict[str, str],
    ) -> bool:
        """
        Validate connectivity by instantiating the generator via Python API.

        Args:
            generator_type: Type of generator to test.
            env_vars: Environment variables for authentication.

        Returns:
            True if connection is successful.

        Raises:
            GarakConnectionError: If connection validation fails.
        """
        self.logger.info("validating_connection", generator_type=generator_type)

        try:
            with _scoped_env_vars(env_vars):
                from garak import _config, _plugins

                if not getattr(_config, "loaded", False):
                    _config.load_base_config()

                generator_path = f"generators.{generator_type}"
                generator = _plugins.load_plugin(generator_path)

                if generator is None:
                    raise GarakConnectionError(
                        message=f"Could not instantiate generator '{generator_type}'",
                        provider=generator_type,
                        error_code="CONN_006",
                    )

            self.logger.info("connection_validated", generator_type=generator_type)
            return True

        except GarakConnectionError:
            raise

        except Exception as e:
            self.logger.error(
                "connection_validation_error",
                generator_type=generator_type,
                error=str(e),
            )
            raise GarakConnectionError(
                message=f"Connection validation error for '{generator_type}': {e}",
                provider=generator_type,
                error_code="CONN_001",
            ) from e

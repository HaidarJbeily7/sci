"""
GarakEngine - Main orchestration engine for SCI security scans.

This module provides the GarakEngine class that coordinates the complete
scan lifecycle including profile loading, probe/detector mapping,
scan execution, result processing, and report generation.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Optional

from sci.config.manager import ConfigManager
from sci.config.models import (
    AWSProviderConfig,
    AzureProviderConfig,
    GarakConfig,
    GoogleProviderConfig,
    OutputConfig,
    ProviderConfig,
    SCIConfig,
    TestProfile,
)
from sci.engine.exceptions import (
    GarakConfigurationError,
    GarakConnectionError,
    GarakExecutionError,
    GarakInstallationError,
    GarakTimeoutError,
    GarakValidationError,
    ScanCheckpoint,
    get_probe_suggestions,
    get_detector_suggestions,
    with_timeout,
)
from sci.engine.results import (
    GarakResultProcessor,
    ResultStorageManager,
    ScanReport,
    ResultProcessingError,
    StorageError,
)
from sci.garak.adapters import get_adapter_for_provider, validate_provider_config
from sci.garak.client import GarakClientWrapper
from sci.garak.mappings import (
    ComplianceMapper,
    DetectorMapper,
    ProbeMapper,
    get_probe_description,
    get_detector_description,
    DETECTOR_TYPE_MAPPING,
    EU_AI_ACT_MAPPING,
)
from sci.logging.setup import get_logger, log_error

# Type alias for progress callback
ProgressCallback = Callable[[str, float, str], None]


class GarakEngine:
    """
    Main orchestration engine for security scans.

    This class coordinates the complete scan lifecycle including:
    - Loading test profiles from configuration
    - Mapping SCI probe/detector names to garak identifiers
    - Adapting provider configurations for authentication
    - Executing scans via GarakClientWrapper
    - Aggregating and returning results

    Attributes:
        config: GarakConfig instance with framework settings.
        config_manager: ConfigManager for accessing configuration.
        client: GarakClientWrapper for executing scans.
        probe_mapper: ProbeMapper for translating probe names.
        detector_mapper: DetectorMapper for translating detector names.
        compliance_mapper: ComplianceMapper for EU AI Act mapping.
        logger: Structured logger for operations.

    Example:
        >>> from sci.config.manager import get_config
        >>> from sci.config.models import GarakConfig
        >>>
        >>> config_manager = get_config()
        >>> config_manager.load()
        >>> garak_config = GarakConfig(**config_manager.get("garak", {}))
        >>> engine = GarakEngine(garak_config, config_manager)
        >>>
        >>> results = engine.execute_scan(
        ...     provider_name="openai",
        ...     model_name="gpt-4",
        ...     profile_name="standard",
        ...     output_dir=Path("./results"),
        ... )
    """

    def __init__(
        self,
        config: GarakConfig,
        config_manager: ConfigManager,
    ) -> None:
        """
        Initialize the GarakEngine.

        Args:
            config: GarakConfig instance with framework settings.
            config_manager: ConfigManager for accessing configuration.

        Raises:
            ImportError: If garak is not installed.
        """
        self.config = config
        self.config_manager = config_manager
        self.logger = get_logger(__name__)

        # Initialize client and mappers
        self.client = GarakClientWrapper(config)
        self.probe_mapper = ProbeMapper(config)
        self.detector_mapper = DetectorMapper(config)
        self.compliance_mapper = ComplianceMapper()

        # Build SCIConfig for result processor
        sci_config = self._build_sci_config()

        # Initialize result processor and storage manager
        self.result_processor = GarakResultProcessor(sci_config)

        # Get output config from config_manager
        output_config_data = config_manager.get("output", {})
        if isinstance(output_config_data, dict):
            output_config = OutputConfig.model_validate(output_config_data)
        else:
            output_config = OutputConfig()
        self.storage_manager = ResultStorageManager(output_config)

        self.logger.info(
            "garak_engine_initialized",
            parallelism=config.parallelism,
            extended_detectors=config.extended_detectors,
        )

    def execute_scan(
        self,
        provider_name: str,
        model_name: str,
        profile_name: str,
        output_dir: Path,
        progress_callback: Optional[ProgressCallback] = None,
        resume_checkpoint: Optional[Path] = None,
    ) -> dict[str, Any]:
        """
        Execute a security scan against an LLM.

        This method orchestrates the complete scan workflow:
        1. Load and validate the test profile
        2. Validate probe/detector availability
        3. Map SCI probe names to garak identifiers
        4. Load and validate provider configuration
        5. Adapt provider config for authentication
        6. Execute scan via GarakClientWrapper
        7. Aggregate and return results with metadata

        Args:
            provider_name: Name of the LLM provider (e.g., "openai").
            model_name: Model identifier to test (e.g., "gpt-4").
            profile_name: Name of the test profile to use.
            output_dir: Directory for storing scan results.
            progress_callback: Optional callback for progress updates.
                Signature: (probe_name: str, completion: float, status: str) -> None
            resume_checkpoint: Optional path to a checkpoint file to resume from.

        Returns:
            Dictionary containing scan results with keys:
            - scan_id: Unique identifier for the scan
            - status: Execution status (success, partial_success, failure, error)
            - start_time: ISO timestamp of scan start
            - end_time: ISO timestamp of scan end
            - duration_ms: Scan duration in milliseconds
            - provider: Provider name
            - model: Model name
            - profile: Profile name used
            - probes_executed: List of probes that were run
            - findings: List of vulnerability findings
            - summary: Summary statistics
            - compliance_tags: EU AI Act articles covered
            - report_path: Path to detailed report file
            - failed_probes: List of probes that failed (if continue_on_error)
            - checkpoint_path: Path to checkpoint file (for recovery)

        Raises:
            GarakValidationError: If profile or configuration is invalid.
            GarakConfigurationError: If provider configuration is invalid.
            GarakExecutionError: If garak execution fails.
            GarakTimeoutError: If scan exceeds timeout.
            GarakConnectionError: If there are connectivity issues.
        """
        start_time = datetime.now(tz=UTC)
        checkpoint: Optional[ScanCheckpoint] = None
        failed_probes: list[dict[str, Any]] = []

        self.logger.info(
            "scan_execution_started",
            provider=provider_name,
            model=model_name,
            profile=profile_name,
            output_dir=str(output_dir),
        )

        # Resume from checkpoint if provided
        if resume_checkpoint and resume_checkpoint.exists():
            checkpoint = self._load_checkpoint(resume_checkpoint)
            self.logger.info(
                "resuming_from_checkpoint",
                scan_id=checkpoint.scan_id,
                completed_probes=len(checkpoint.completed_probes),
                pending_probes=len(checkpoint.pending_probes),
            )

        # Notify progress callback
        if progress_callback:
            progress_callback("Loading configuration", 0.0, "initializing")

        # Load test profile
        profile = self.get_profile(profile_name)
        if profile is None:
            available = self.list_available_profiles()
            raise GarakValidationError(
                message=f"Profile '{profile_name}' not found in configuration",
                validation_type="profile",
                suggestions=available,
                error_code="VAL_005",
                troubleshooting_tips=[
                    f"Available profiles: {', '.join(available)}",
                    "Check the spelling of the profile name",
                    "Define custom profiles in your configuration file",
                ],
                context={
                    "requested_profile": profile_name,
                    "available_profiles": available,
                },
            )

        # Validate probes are available
        if progress_callback:
            progress_callback("Validating probes", 0.05, "validating")

        self.validate_probes_available(profile.probes)

        # Map SCI probe names to garak identifiers
        if progress_callback:
            progress_callback("Mapping probes", 0.1, "mapping")

        garak_probes = self.probe_mapper.map_probe_list(profile.probes)
        if not garak_probes:
            raise GarakValidationError(
                message=f"No valid garak probes found for profile '{profile_name}'",
                validation_type="probe_mapping",
                error_code="VAL_006",
                troubleshooting_tips=[
                    "Check the probe names in the profile configuration",
                    "Run 'sci run probes' to see available probes",
                    "Verify probe_categories mapping in garak configuration",
                ],
                context={
                    "profile_probes": profile.probes,
                    "profile_name": profile_name,
                },
            )

        # Filter probes if resuming from checkpoint
        if checkpoint:
            garak_probes = [p for p in garak_probes if p not in checkpoint.completed_probes]
            failed_probes = checkpoint.failed_probes

        self.logger.debug(
            "probes_mapped",
            sci_probes=profile.probes,
            garak_probes=garak_probes,
        )

        # Load provider configuration
        if progress_callback:
            progress_callback("Loading provider config", 0.2, "configuring")

        provider_config = self._load_provider_config(provider_name)

        # Validate provider configuration
        validation_errors = validate_provider_config(provider_name, provider_config)
        if validation_errors:
            raise GarakConfigurationError(
                message=f"Provider configuration validation failed for '{provider_name}'",
                field_name="provider",
                error_code="CONFIG_003",
                troubleshooting_tips=validation_errors,
                context={
                    "provider": provider_name,
                    "errors_count": len(validation_errors),
                },
            )

        # Get adapter and prepare authentication
        adapter = get_adapter_for_provider(provider_name)
        generator_type, env_vars, additional_params = adapter(provider_config)

        # Override model name if specified in CLI (takes precedence over config)
        effective_model = model_name or provider_config.model
        if not effective_model:
            raise GarakConfigurationError(
                message="Model name is required",
                field_name="model",
                expected_format="Model identifier (e.g., 'gpt-4', 'claude-3-opus')",
                error_code="CONFIG_004",
                troubleshooting_tips=[
                    "Specify the model via --model flag",
                    "Add 'model' to your provider configuration",
                    "Check the provider's documentation for model names",
                ],
            )

        # Log scan initiation (mask credentials)
        self.logger.info(
            "scan_initiating",
            generator_type=generator_type,
            model=effective_model,
            probes_count=len(garak_probes),
            env_vars_count=len(env_vars),
        )

        # Create checkpoint for this scan
        import uuid
        scan_id = checkpoint.scan_id if checkpoint else str(uuid.uuid4())[:8]
        current_checkpoint = ScanCheckpoint(
            scan_id=scan_id,
            completed_probes=checkpoint.completed_probes if checkpoint else [],
            failed_probes=failed_probes,
            pending_probes=garak_probes.copy(),
        )

        # Execute scan
        if progress_callback:
            progress_callback("Executing probes", 0.3, "scanning")

        # Apply overall scan timeout
        scan_timeout = getattr(self.config, "scan_timeout", 600)
        continue_on_error = getattr(self.config, "continue_on_error", False)

        try:
            scan_results = self._execute_scan_with_recovery(
                generator_type=generator_type,
                model_name=effective_model,
                probes=garak_probes,
                env_vars=env_vars,
                output_dir=output_dir,
                additional_params=additional_params,
                checkpoint=current_checkpoint,
                continue_on_error=continue_on_error,
                scan_timeout=scan_timeout,
            )
        except (GarakExecutionError, GarakTimeoutError, GarakConnectionError) as e:
            # Save checkpoint for recovery
            checkpoint_path = self._save_checkpoint(current_checkpoint, output_dir)
            self.logger.error(
                "scan_failed_checkpoint_saved",
                scan_id=scan_id,
                checkpoint_path=str(checkpoint_path),
                error=str(e),
            )
            # Add checkpoint info to the exception context
            e.context["checkpoint_path"] = str(checkpoint_path)
            raise

        # Get failed probes from checkpoint
        failed_probes = current_checkpoint.failed_probes

        # Get compliance tags for the probes executed
        compliance_tags = self.compliance_mapper.get_compliance_tags(
            probes=profile.probes,
            detectors=profile.detectors,
        )

        # Aggregate results
        if progress_callback:
            progress_callback("Processing results", 0.85, "processing")

        end_time = datetime.now(tz=UTC)
        duration_ms = (end_time - start_time).total_seconds() * 1000

        # Determine overall status
        if scan_results.get("status") == "error":
            status = "error"
        elif failed_probes and scan_results.get("findings"):
            status = "partial_success"
        elif failed_probes:
            status = "failure"
        else:
            status = scan_results.get("status", "success")

        result = {
            "scan_id": scan_results.get("scan_id", scan_id),
            "status": status,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_ms": round(duration_ms, 2),
            "provider": provider_name,
            "model": effective_model,
            "profile": profile_name,
            "profile_description": profile.description,
            "probes_requested": profile.probes,
            "probes_executed": garak_probes,
            "detectors_configured": profile.detectors,
            "findings": scan_results.get("findings", []),
            "summary": scan_results.get("summary", {}),
            "compliance_tags": compliance_tags,
            "report_path": scan_results.get("report_path"),
            "error": scan_results.get("error"),
            "failed_probes": failed_probes,
        }

        # Save final checkpoint
        checkpoint_path = self._save_checkpoint(current_checkpoint, output_dir)
        result["checkpoint_path"] = str(checkpoint_path)

        # Process results through the result processor
        processed_report: Optional[ScanReport] = None
        processed_report_path: Optional[Path] = None

        try:
            if progress_callback:
                progress_callback("Analyzing results", 0.90, "analyzing")

            processed_report = self.result_processor.process_scan_result(result)

            # Store the processed report
            if progress_callback:
                progress_callback("Saving report", 0.95, "saving")

            processed_report_path = self.storage_manager.save_report(
                processed_report,
                scan_id=result["scan_id"],
            )

            # Also copy raw garak report if available
            raw_report_path = scan_results.get("report_path")
            if raw_report_path:
                self.storage_manager.save_raw_garak_report(
                    Path(raw_report_path),
                    scan_id=result["scan_id"],
                )

            self.logger.info(
                "processed_report_saved",
                scan_id=result["scan_id"],
                report_path=str(processed_report_path),
                security_score=processed_report.security_score.overall_score,
                risk_level=processed_report.security_score.risk_level.value,
            )

        except (ResultProcessingError, StorageError) as e:
            self.logger.warning(
                "result_processing_warning",
                scan_id=result["scan_id"],
                error=str(e),
            )
            # Continue without processed report - raw result still available

        # Add processed report data to result
        result["processed_report"] = processed_report
        result["processed_report_path"] = str(processed_report_path) if processed_report_path else None

        if progress_callback:
            progress_callback("Complete", 1.0, "done")

        self.logger.info(
            "scan_execution_completed",
            scan_id=result["scan_id"],
            status=result["status"],
            duration_ms=result["duration_ms"],
            findings_count=len(result["findings"]),
            failed_probes_count=len(failed_probes),
            has_processed_report=processed_report is not None,
        )

        return result

    def _execute_scan_with_recovery(
        self,
        generator_type: str,
        model_name: str,
        probes: list[str],
        env_vars: dict[str, str],
        output_dir: Path,
        additional_params: dict[str, Any],
        checkpoint: ScanCheckpoint,
        continue_on_error: bool,
        scan_timeout: int,
    ) -> dict[str, Any]:
        """
        Execute scan with error recovery and checkpoint support.

        Args:
            generator_type: Type of generator to use.
            model_name: Name of the model to test.
            probes: List of probes to execute.
            env_vars: Environment variables for authentication.
            output_dir: Directory for results.
            additional_params: Additional parameters for the scan.
            checkpoint: Checkpoint for tracking progress.
            continue_on_error: Whether to continue if individual probes fail.
            scan_timeout: Overall scan timeout in seconds.

        Returns:
            Scan results dictionary.
        """
        # Remove model_name from additional_params to avoid duplicate keyword argument
        scan_params = {k: v for k, v in additional_params.items() if k != "model_name"}

        if not continue_on_error:
            # Execute all probes together
            return self.client.run_scan(
                generator_type=generator_type,
                model_name=model_name,
                probes=probes,
                env_vars=env_vars,
                output_dir=output_dir,
                **scan_params,
            )

        # Execute probes individually for error recovery
        all_findings: list[dict[str, Any]] = []
        all_summaries: dict[str, Any] = {}
        last_report_path: Optional[str] = None
        scan_id: Optional[str] = None

        for probe in probes:
            try:
                result = self.client.run_scan(
                    generator_type=generator_type,
                    model_name=model_name,
                    probes=[probe],
                    env_vars=env_vars,
                    output_dir=output_dir,
                    **scan_params,
                )

                if result.get("status") == "success":
                    checkpoint.add_completed_probe(probe, result)
                    all_findings.extend(result.get("findings", []))
                    if result.get("summary"):
                        all_summaries[probe] = result["summary"]
                    last_report_path = result.get("report_path")
                    scan_id = result.get("scan_id", scan_id)
                else:
                    error_msg = result.get("error", {}).get("message", "Unknown error")
                    checkpoint.add_failed_probe(probe, error_msg)

            except (GarakExecutionError, GarakTimeoutError, GarakConnectionError) as e:
                checkpoint.add_failed_probe(probe, str(e))
                self.logger.warning(
                    "probe_failed_continuing",
                    probe=probe,
                    error=str(e),
                )

            # Save checkpoint after each probe
            self._save_checkpoint(checkpoint, output_dir)

        # Aggregate results
        total = len(all_findings)
        passed = sum(1 for f in all_findings if f.get("passed", f.get("status") == "pass"))

        return {
            "scan_id": scan_id or checkpoint.scan_id,
            "status": "success" if not checkpoint.failed_probes else "partial_success",
            "findings": all_findings,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": total - passed,
                "pass_rate": round(passed / total * 100, 2) if total > 0 else 0.0,
                "probes": all_summaries,
            },
            "report_path": last_report_path,
        }

    def validate_probes_available(self, probes: list[str]) -> None:
        """
        Validate that requested probes are available.

        Args:
            probes: List of SCI probe names to validate.

        Raises:
            GarakValidationError: If any probes are unavailable.
        """
        # Get available garak probes
        available_probes = self.client.list_available_probes()
        if not available_probes:
            self.logger.warning(
                "probe_listing_unavailable",
                message="Could not retrieve available probes from garak",
            )
            return  # Skip validation if we can't get the list

        # Check each probe
        unavailable: list[str] = []
        suggestions: dict[str, list[str]] = {}

        for probe_name in probes:
            # Map to garak probe names
            try:
                garak_probes = self.probe_mapper.map_probe_name(probe_name)
                for garak_probe in garak_probes:
                    if garak_probe not in available_probes:
                        unavailable.append(garak_probe)
                        probe_suggestions = get_probe_suggestions(
                            garak_probe, available_probes
                        )
                        if probe_suggestions:
                            suggestions[garak_probe] = probe_suggestions
            except ValueError:
                # Probe name not in mapping
                unavailable.append(probe_name)
                probe_suggestions = get_probe_suggestions(probe_name, available_probes)
                if probe_suggestions:
                    suggestions[probe_name] = probe_suggestions

        if unavailable:
            tips = []
            for probe in unavailable:
                if probe in suggestions:
                    tips.append(f"'{probe}' - did you mean: {', '.join(suggestions[probe][:3])}?")
                else:
                    tips.append(f"'{probe}' is not available")

            raise GarakValidationError(
                message=f"Some probes are unavailable: {', '.join(unavailable)}",
                validation_type="probe_availability",
                suggestions=list(suggestions.values())[0] if suggestions else [],
                error_code="VAL_007",
                troubleshooting_tips=tips + [
                    "Run 'sci run probes' to see all available probes",
                    "Update garak to get the latest probes: pip install -U garak",
                ],
                context={
                    "unavailable_probes": unavailable,
                    "suggestions": suggestions,
                },
            )

    def validate_detectors_available(self, detectors: list[str]) -> None:
        """
        Validate that requested detectors are available.

        Args:
            detectors: List of SCI detector names to validate.

        Raises:
            GarakValidationError: If any detectors are unavailable.
        """
        # Get available detector names from mapping
        available_detectors = list(DETECTOR_TYPE_MAPPING.keys())

        unavailable: list[str] = []
        suggestions: dict[str, list[str]] = {}

        for detector_name in detectors:
            if detector_name not in DETECTOR_TYPE_MAPPING:
                unavailable.append(detector_name)
                detector_suggestions = get_detector_suggestions(
                    detector_name, available_detectors
                )
                if detector_suggestions:
                    suggestions[detector_name] = detector_suggestions

        if unavailable:
            tips = []
            for detector in unavailable:
                if detector in suggestions:
                    tips.append(f"'{detector}' - did you mean: {', '.join(suggestions[detector][:3])}?")
                else:
                    tips.append(f"'{detector}' is not available")

            raise GarakValidationError(
                message=f"Some detectors are unavailable: {', '.join(unavailable)}",
                validation_type="detector_availability",
                suggestions=list(suggestions.values())[0] if suggestions else [],
                error_code="VAL_008",
                troubleshooting_tips=tips + [
                    "Run 'sci run detectors' to see all available detectors",
                ],
                context={
                    "unavailable_detectors": unavailable,
                    "suggestions": suggestions,
                },
            )

    def _save_checkpoint(self, checkpoint: ScanCheckpoint, output_dir: Path) -> Path:
        """Save checkpoint to file."""
        checkpoint_path = output_dir / f"checkpoint_{checkpoint.scan_id}.json"
        with open(checkpoint_path, "w", encoding="utf-8") as f:
            json.dump(checkpoint.to_dict(), f, indent=2)
        return checkpoint_path

    def _load_checkpoint(self, checkpoint_path: Path) -> ScanCheckpoint:
        """Load checkpoint from file."""
        with open(checkpoint_path, encoding="utf-8") as f:
            data = json.load(f)
        return ScanCheckpoint.from_dict(data)

    def validate_configuration(
        self,
        provider_name: str,
        profile_name: str,
        validate_connectivity: bool = False,
    ) -> dict[str, Any]:
        """
        Validate configuration before scan execution.

        Checks that the profile and provider are properly configured
        with all required settings. Optionally tests provider connectivity.

        Args:
            provider_name: Name of the provider to validate.
            profile_name: Name of the profile to validate.
            validate_connectivity: If True, performs a quick connectivity test.

        Returns:
            Dictionary with validation results:
            - is_valid: True if configuration is valid
            - errors: List of error messages (blocking issues)
            - warnings: List of warning messages (non-blocking issues)
            - suggestions: List of actionable recommendations
        """
        errors: list[str] = []
        warnings: list[str] = []
        suggestions: list[str] = []

        # Check garak installation first
        try:
            self.client.validate_installation()
        except GarakInstallationError as e:
            errors.append(str(e.message))
            suggestions.extend(e.troubleshooting_tips)

        # Check if profile exists
        profile = self.get_profile(profile_name)
        if profile is None:
            available = self.list_available_profiles()
            errors.append(
                f"Profile '{profile_name}' not found. "
                f"Available profiles: {', '.join(available)}"
            )
            suggestions.append("Check the spelling of the profile name")
            suggestions.append("Define custom profiles in your configuration file")
        elif not profile.probes:
            errors.append(f"Profile '{profile_name}' has no probes configured.")
            suggestions.append("Add probes to the profile in your configuration")
        else:
            # Validate probes are available
            try:
                self.validate_probes_available(profile.probes)
            except GarakValidationError as e:
                warnings.append(f"Some probes may not be available: {e.message}")
                suggestions.extend(e.troubleshooting_tips)

            # Validate detectors are available
            if profile.detectors:
                try:
                    self.validate_detectors_available(profile.detectors)
                except GarakValidationError as e:
                    warnings.append(f"Some detectors may not be available: {e.message}")
                    suggestions.extend(e.troubleshooting_tips)

        # Check if provider exists
        try:
            provider_config = self._load_provider_config(provider_name)

            # Validate provider configuration
            validation_errors = validate_provider_config(provider_name, provider_config)
            errors.extend(validation_errors)

            # Check for missing API key (warning if might be in environment)
            if not provider_config.api_key:
                env_var_hints = {
                    "openai": "OPENAI_API_KEY",
                    "anthropic": "ANTHROPIC_API_KEY",
                    "google": "GOOGLE_API_KEY",
                    "azure": "AZURE_OPENAI_KEY",
                    "huggingface": "HF_TOKEN",
                }
                env_var = env_var_hints.get(provider_name.lower(), "API_KEY")
                warnings.append(
                    f"API key not found in config for {provider_name}. "
                    f"Ensure it's set via environment variable ({env_var})."
                )

            # Optional connectivity test
            if validate_connectivity and not errors:
                try:
                    adapter = get_adapter_for_provider(provider_name)
                    _, env_vars, _ = adapter(provider_config)
                    self.client.validate_connection(provider_name, env_vars)
                except GarakConnectionError as e:
                    errors.append(f"Provider connectivity test failed: {e.message}")
                    suggestions.extend(e.troubleshooting_tips)
                except GarakTimeoutError as e:
                    warnings.append(f"Connectivity test timed out: {e.message}")
                    suggestions.append("Check network connectivity to the provider")

        except GarakConfigurationError as e:
            errors.append(str(e.message))
            suggestions.extend(e.troubleshooting_tips)
        except ValueError as e:
            errors.append(str(e))

        is_valid = len(errors) == 0

        self.logger.debug(
            "configuration_validated",
            provider=provider_name,
            profile=profile_name,
            is_valid=is_valid,
            errors_count=len(errors),
            warnings_count=len(warnings),
        )

        return {
            "is_valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "suggestions": list(set(suggestions)),  # Remove duplicates
        }

    def get_profile(self, profile_name: Optional[str] = None) -> Optional[TestProfile]:
        """
        Load a test profile from configuration.

        Args:
            profile_name: Name of the profile to load.
                If None, returns the default "standard" profile.

        Returns:
            TestProfile instance or None if not found.
        """
        name = profile_name or "standard"

        # Try to get profile from config
        profile_data = self.config_manager.get(f"profiles.{name}")

        if profile_data is None:
            # Check if it's a built-in profile
            profile_data = self._get_builtin_profile(name)

        if profile_data is None:
            self.logger.warning(
                "profile_not_found",
                profile_name=name,
            )
            return None

        try:
            # Ensure name is in the data
            if isinstance(profile_data, dict):
                profile_data["name"] = name
                return TestProfile.model_validate(profile_data)
            else:
                self.logger.warning(
                    "invalid_profile_data",
                    profile_name=name,
                    data_type=type(profile_data).__name__,
                )
                return None
        except Exception as e:
            self.logger.error(
                "profile_parse_error",
                profile_name=name,
                error=str(e),
            )
            return None

    def list_available_profiles(self) -> list[str]:
        """
        List all available test profiles.

        Returns:
            List of profile names with their descriptions.
        """
        profiles = []

        # Get profiles from config
        config_profiles = self.config_manager.get("profiles", {})
        if isinstance(config_profiles, dict):
            profiles.extend(config_profiles.keys())

        # Add built-in profiles
        builtin = ["standard", "minimal", "comprehensive"]
        for name in builtin:
            if name not in profiles:
                profiles.append(name)

        return sorted(profiles)

    def list_probes(
        self,
        category: Optional[str] = None,
        compliance_tag: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        List available security probes.

        Args:
            category: Optional category filter.
            compliance_tag: Optional EU AI Act compliance tag filter.

        Returns:
            List of probe information dictionaries with keys:
            - sci_name: SCI probe name
            - garak_module: Garak module identifier
            - description: Human-readable description
            - compliance_tags: EU AI Act articles
            - category: Probe category
        """
        probes_list = []

        # Get all probe mappings from config
        probe_categories = self.config.probe_categories

        for sci_name, garak_module in probe_categories.items():
            # Extract category from probe name
            probe_category = sci_name.split("_")[0]

            # Apply category filter
            if category and probe_category != category:
                continue

            # Get compliance tags
            tags = self.compliance_mapper.get_articles_for_probe(sci_name)

            # Apply compliance tag filter
            if compliance_tag and compliance_tag not in tags:
                continue

            # Get garak probes for this mapping
            try:
                garak_probes = self.probe_mapper.map_probe_name(sci_name)
            except ValueError:
                garak_probes = []

            probes_list.append({
                "sci_name": sci_name,
                "garak_module": garak_module,
                "garak_probes": garak_probes,
                "description": get_probe_description(garak_module),
                "compliance_tags": tags,
                "category": probe_category,
            })

        return sorted(probes_list, key=lambda x: x["sci_name"])

    def list_detectors(
        self,
        category: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        List available response detectors.

        Args:
            category: Optional category filter.

        Returns:
            List of detector information dictionaries with keys:
            - sci_name: SCI detector name
            - garak_detectors: List of garak detector identifiers
            - description: Human-readable description
            - category: Detector category
            - level: Detection level (basic, advanced, subtle)
        """
        detectors_list = []

        for sci_name, config in DETECTOR_TYPE_MAPPING.items():
            # Extract category from detector name
            detector_category = sci_name.split("_")[0]

            # Apply category filter
            if category and detector_category != category:
                continue

            detectors_list.append({
                "sci_name": sci_name,
                "garak_detectors": config.get("detectors", []),
                "description": get_detector_description(config.get("detectors", [""])[0]),
                "category": detector_category,
                "level": config.get("level", "basic"),
                "threshold": config.get("threshold", 0.5),
            })

        return sorted(detectors_list, key=lambda x: x["sci_name"])

    def _load_provider_config(self, provider_name: str) -> ProviderConfig:
        """
        Load provider configuration from config manager.

        Args:
            provider_name: Name of the provider.

        Returns:
            ProviderConfig instance for the provider.

        Raises:
            ValueError: If provider configuration is missing or invalid.
        """
        provider_key = provider_name.lower().replace("-", "_")
        provider_data = self.config_manager.get(f"providers.{provider_key}", {})

        if not isinstance(provider_data, dict):
            provider_data = {}

        # Select appropriate config class based on provider
        if provider_key == "azure":
            return AzureProviderConfig.model_validate(provider_data)
        elif provider_key in ("aws", "bedrock"):
            return AWSProviderConfig.model_validate(provider_data)
        elif provider_key == "google":
            return GoogleProviderConfig.model_validate(provider_data)
        else:
            return ProviderConfig.model_validate(provider_data)

    def _build_sci_config(self) -> SCIConfig:
        """
        Build SCIConfig from config_manager data.

        Returns:
            SCIConfig instance.
        """
        # Try to build from config_manager data
        try:
            config_data = {}

            # Get output config
            output_data = self.config_manager.get("output", {})
            if isinstance(output_data, dict):
                config_data["output"] = output_data

            # Get logging config
            logging_data = self.config_manager.get("logging", {})
            if isinstance(logging_data, dict):
                config_data["logging"] = logging_data

            # Get compliance config
            compliance_data = self.config_manager.get("compliance", {})
            if isinstance(compliance_data, dict):
                config_data["compliance"] = compliance_data

            # Get garak config
            config_data["garak"] = self.config.model_dump()

            return SCIConfig.model_validate(config_data)

        except Exception as e:
            self.logger.warning(
                "sci_config_build_fallback",
                error=str(e),
            )
            # Return default config on error
            return SCIConfig(garak=self.config)

    def _get_builtin_profile(self, name: str) -> Optional[dict[str, Any]]:
        """
        Get built-in profile definitions.

        Args:
            name: Profile name.

        Returns:
            Profile data dictionary or None.
        """
        builtin_profiles = {
            "minimal": {
                "description": "Quick scan with minimal probes for fast validation",
                "probes": ["prompt_injection_basic"],
                "detectors": ["toxicity_basic"],
                "compliance_tags": ["article-15"],
                "max_parallel": 5,
                "timeout": 120,
            },
            "standard": {
                "description": "Standard security scan covering common vulnerabilities",
                "probes": [
                    "prompt_injection_basic",
                    "jailbreak_basic",
                    "extraction_system_prompt",
                ],
                "detectors": [
                    "toxicity_basic",
                    "leakage_basic",
                ],
                "compliance_tags": ["article-9", "article-15"],
                "max_parallel": 10,
                "timeout": 300,
            },
            "comprehensive": {
                "description": "Comprehensive security scan for EU AI Act compliance",
                "probes": [
                    "prompt_injection_basic",
                    "prompt_injection_advanced",
                    "jailbreak_basic",
                    "jailbreak_roleplay",
                    "jailbreak_encoding",
                    "extraction_system_prompt",
                    "extraction_training_data",
                    "manipulation_output",
                    "compliance_transparency",
                    "compliance_human_oversight",
                ],
                "detectors": [
                    "toxicity_basic",
                    "toxicity_advanced",
                    "leakage_basic",
                    "leakage_pii",
                    "bias_detection",
                    "hallucination_factual",
                ],
                "compliance_tags": [
                    "article-9",
                    "article-10",
                    "article-13",
                    "article-14",
                    "article-15",
                    "annex-iv",
                ],
                "max_parallel": 5,
                "timeout": 600,
            },
        }

        return builtin_profiles.get(name)

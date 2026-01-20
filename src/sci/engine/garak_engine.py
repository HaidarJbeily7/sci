"""
GarakEngine - Main orchestration engine for SCI security scans.

This module provides the GarakEngine class that coordinates the complete
scan lifecycle including profile loading, probe/detector mapping,
scan execution, result processing, and report generation.
"""

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
    ) -> dict[str, Any]:
        """
        Execute a security scan against an LLM.

        This method orchestrates the complete scan workflow:
        1. Load and validate the test profile
        2. Map SCI probe names to garak identifiers
        3. Load and validate provider configuration
        4. Adapt provider config for authentication
        5. Execute scan via GarakClientWrapper
        6. Aggregate and return results with metadata

        Args:
            provider_name: Name of the LLM provider (e.g., "openai").
            model_name: Model identifier to test (e.g., "gpt-4").
            profile_name: Name of the test profile to use.
            output_dir: Directory for storing scan results.
            progress_callback: Optional callback for progress updates.
                Signature: (probe_name: str, completion: float, status: str) -> None

        Returns:
            Dictionary containing scan results with keys:
            - scan_id: Unique identifier for the scan
            - status: Execution status (success, failure, error)
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

        Raises:
            ValueError: If profile or provider configuration is invalid.
            RuntimeError: If garak execution fails.
        """
        start_time = datetime.now(tz=UTC)

        self.logger.info(
            "scan_execution_started",
            provider=provider_name,
            model=model_name,
            profile=profile_name,
            output_dir=str(output_dir),
        )

        # Notify progress callback
        if progress_callback:
            progress_callback("Loading configuration", 0.0, "initializing")

        # Load test profile
        profile = self.get_profile(profile_name)
        if profile is None:
            raise ValueError(
                f"Profile '{profile_name}' not found in configuration. "
                f"Available profiles: {self.list_available_profiles()}"
            )

        # Map SCI probe names to garak identifiers
        if progress_callback:
            progress_callback("Mapping probes", 0.1, "mapping")

        garak_probes = self.probe_mapper.map_probe_list(profile.probes)
        if not garak_probes:
            raise ValueError(
                f"No valid garak probes found for profile '{profile_name}'. "
                f"Profile probes: {profile.probes}"
            )

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
            raise ValueError(
                f"Provider configuration validation failed: {'; '.join(validation_errors)}"
            )

        # Get adapter and prepare authentication
        adapter = get_adapter_for_provider(provider_name)
        generator_type, env_vars, additional_params = adapter(provider_config)

        # Override model name if specified in CLI (takes precedence over config)
        effective_model = model_name or provider_config.model
        if not effective_model:
            raise ValueError(
                f"Model name is required. Specify via --model flag or in provider config."
            )

        # Log scan initiation (mask credentials)
        self.logger.info(
            "scan_initiating",
            generator_type=generator_type,
            model=effective_model,
            probes_count=len(garak_probes),
            env_vars_count=len(env_vars),
        )

        # Execute scan
        if progress_callback:
            progress_callback("Executing probes", 0.3, "scanning")

        scan_results = self.client.run_scan(
            generator_type=generator_type,
            model_name=effective_model,
            probes=garak_probes,
            env_vars=env_vars,
            output_dir=output_dir,
            **additional_params,
        )

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

        result = {
            "scan_id": scan_results.get("scan_id", "unknown"),
            "status": scan_results.get("status", "error"),
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
        }

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
            has_processed_report=processed_report is not None,
        )

        return result

    def validate_configuration(
        self,
        provider_name: str,
        profile_name: str,
    ) -> dict[str, Any]:
        """
        Validate configuration before scan execution.

        Checks that the profile and provider are properly configured
        with all required settings.

        Args:
            provider_name: Name of the provider to validate.
            profile_name: Name of the profile to validate.

        Returns:
            Dictionary with validation results:
            - is_valid: True if configuration is valid
            - errors: List of error messages
            - warnings: List of warning messages
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Check if profile exists
        profile = self.get_profile(profile_name)
        if profile is None:
            errors.append(
                f"Profile '{profile_name}' not found. "
                f"Available profiles: {self.list_available_profiles()}"
            )
        elif not profile.probes:
            errors.append(f"Profile '{profile_name}' has no probes configured.")

        # Check if provider exists
        try:
            provider_config = self._load_provider_config(provider_name)

            # Validate provider configuration
            validation_errors = validate_provider_config(provider_name, provider_config)
            errors.extend(validation_errors)

            # Check for missing API key (warning if might be in environment)
            if not provider_config.api_key:
                warnings.append(
                    f"API key not found in config for {provider_name}. "
                    f"Ensure it's set via environment variable."
                )

        except ValueError as e:
            errors.append(str(e))

        # Validate garak is installed
        try:
            self.client.validate_installation()
        except ImportError as e:
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

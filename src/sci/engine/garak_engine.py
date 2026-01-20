"""
Garak Engine for orchestrating LLM security scans.

This module provides the GarakEngine class that manages the complete scan
lifecycle, including test profile loading, probe/detector mapping, scan
execution via GarakClientWrapper, and result aggregation with EU AI Act
compliance tagging.

Example:
    >>> from sci.config.models import SCIConfig
    >>> from sci.engine import GarakEngine
    >>>
    >>> config = SCIConfig.model_validate(config_dict)
    >>> engine = GarakEngine(config)
    >>>
    >>> result = engine.execute_scan(
    ...     provider_name="openai",
    ...     model_name="gpt-4",
    ...     profile_name="quick_scan"
    ... )
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional

from sci.config.models import (
    GarakConfig,
    ProviderConfig,
    SCIConfig,
    TestProfile,
)
from sci.garak.adapters import get_adapter_for_provider, validate_provider_config
from sci.garak.client import GarakClientWrapper
from sci.garak.mappings import (
    ComplianceMapper,
    DetectorMapper,
    ProbeMapper,
    list_available_detectors,
    list_available_probes,
)
from sci.logging.setup import (
    get_logger,
    log_error,
    log_execution_context,
    log_execution_end,
    log_execution_start,
)


class GarakEngine:
    """
    Orchestrates LLM security scans using the garak framework.

    This class manages the complete scan lifecycle:
    - Loading and validating test profiles
    - Translating SCI probe/detector names to garak identifiers
    - Configuring provider authentication
    - Executing scans via GarakClientWrapper
    - Aggregating and enriching results with compliance metadata

    Attributes:
        config: SCIConfig instance with all configuration settings.
        client: GarakClientWrapper for executing garak scans.
        probe_mapper: ProbeMapper for translating probe names.
        detector_mapper: DetectorMapper for translating detector names.
        compliance_mapper: ComplianceMapper for EU AI Act tagging.
        logger: Structured logger for operations.

    Example:
        >>> config = SCIConfig.model_validate(config_dict)
        >>> engine = GarakEngine(config)
        >>> result = engine.execute_scan("openai", "gpt-4", "quick_scan")
    """

    def __init__(self, config: SCIConfig) -> None:
        """
        Initialize the GarakEngine.

        Args:
            config: SCIConfig instance containing all configuration settings
                   including garak config, provider configs, and test profiles.

        Raises:
            ImportError: If garak is not installed or version is incompatible.
        """
        self.config = config
        self.logger = get_logger(__name__)

        # Initialize garak client wrapper
        self.client = GarakClientWrapper(config.garak)

        # Initialize mappers
        self.probe_mapper = ProbeMapper(config.garak)
        self.detector_mapper = DetectorMapper(config.garak)
        self.compliance_mapper = ComplianceMapper()

        self.logger.info(
            "garak_engine_initialized",
            profiles_count=len(config.profiles),
            garak_enabled=config.garak.enabled,
            parallelism=config.garak.parallelism,
        )

    def execute_scan(
        self,
        provider_name: str,
        model_name: str,
        profile_name: Optional[str] = None,
        output_dir: Optional[Path] = None,
        probes: Optional[list[str]] = None,
        detectors: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """
        Execute a complete security scan against an LLM.

        This is the primary method for running security assessments. It handles
        the full scan lifecycle including profile resolution, probe mapping,
        provider configuration, scan execution, and result enrichment.

        Args:
            provider_name: Provider identifier (e.g., "openai", "anthropic").
            model_name: Model to test (e.g., "gpt-4", "claude-3-opus").
            profile_name: Optional test profile name from config.profiles.
                         If not provided, uses default configuration.
            output_dir: Optional output directory override. If not provided,
                       uses config.output.directory.
            probes: Optional list of SCI probe names to override profile probes.
            detectors: Optional list of SCI detector names to override profile.

        Returns:
            Dictionary containing scan results with structure:
            {
                "scan_id": str,
                "status": "success" | "error",
                "profile": str,
                "provider": str,
                "model": str,
                "start_time": ISO timestamp,
                "end_time": ISO timestamp,
                "duration_ms": float,
                "probes_executed": list[str],  # Garak format
                "detectors_applied": list[dict],
                "findings": list[dict],
                "summary": dict,
                "compliance_tags": list[str],
                "report_path": str,
                "error": Optional[dict]
            }

        Example:
            >>> result = engine.execute_scan(
            ...     provider_name="openai",
            ...     model_name="gpt-4",
            ...     profile_name="quick_scan"
            ... )
            >>> print(result["status"])
            'success'
        """
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.now(tz=UTC)
        perf_start = log_execution_start(
            f"garak_scan:{scan_id}",
            {"provider": provider_name, "model": model_name, "profile": profile_name},
        )

        self.logger.info(
            "scan_execution_started",
            scan_id=scan_id,
            provider=provider_name,
            model=model_name,
            profile=profile_name,
        )

        try:
            # Step 1: Profile Resolution
            profile = self._resolve_profile(profile_name, probes, detectors)
            self.logger.debug(
                "profile_resolved",
                scan_id=scan_id,
                profile_name=profile.name,
                probes_count=len(profile.probes),
                detectors_count=len(profile.detectors),
            )

            # Step 2: Probe Translation
            garak_probes = self.probe_mapper.map_probe_list(profile.probes)
            if not garak_probes:
                raise ValueError(
                    f"No valid garak probes found for SCI probes: {profile.probes}"
                )
            self.logger.debug(
                "probes_translated",
                scan_id=scan_id,
                sci_probes=profile.probes,
                garak_probes=garak_probes,
            )

            # Step 3: Detector Translation
            garak_detectors = self.detector_mapper.map_detector_list(profile.detectors)
            detector_configs = [
                self.detector_mapper.get_detector_config(d) for d in profile.detectors
            ]
            self.logger.debug(
                "detectors_translated",
                scan_id=scan_id,
                sci_detectors=profile.detectors,
                garak_detectors=garak_detectors,
            )

            # Step 4: Provider Configuration
            provider_config = self._get_provider_config(provider_name)
            adapter = get_adapter_for_provider(provider_name)
            generator_type, env_vars, additional_params = adapter(provider_config)
            self.logger.debug(
                "provider_configured",
                scan_id=scan_id,
                provider=provider_name,
                generator_type=generator_type,
            )

            # Step 5: Validation
            validation_errors = validate_provider_config(provider_name, provider_config)
            if validation_errors:
                raise ValueError(
                    f"Provider configuration validation failed: {'; '.join(validation_errors)}"
                )

            # Step 6: Connection Test
            self.logger.info(
                "validating_connection",
                scan_id=scan_id,
                generator_type=generator_type,
            )
            connection_valid = self.client.validate_connection(generator_type, env_vars)
            if not connection_valid:
                self.logger.warning(
                    "connection_validation_failed",
                    scan_id=scan_id,
                    generator_type=generator_type,
                    message="Proceeding with scan despite connection validation failure",
                )

            # Step 7: Determine Output Directory
            scan_output_dir = self._resolve_output_dir(output_dir, scan_id)

            # Step 8: Execute Scan
            self.logger.info(
                "scan_executing",
                scan_id=scan_id,
                phase="probe_execution",
                probes_count=len(garak_probes),
            )

            scan_kwargs: dict[str, Any] = {
                "output_dir": scan_output_dir,
            }
            # Add profile-specific settings
            if profile.timeout:
                scan_kwargs["timeout"] = profile.timeout
            # Add additional params from provider adapter
            scan_kwargs.update(additional_params)

            raw_result = self.client.run_scan(
                generator_type=generator_type,
                model_name=model_name,
                probes=garak_probes,
                env_vars=env_vars,
                **scan_kwargs,
            )

            # Step 9: Result Enrichment
            end_time = datetime.now(tz=UTC)
            duration_ms = (end_time - start_time).total_seconds() * 1000

            # Get compliance tags for the probes executed
            compliance_tags = self.compliance_mapper.get_compliance_tags(
                profile.probes, profile.detectors
            )

            result = {
                "scan_id": scan_id,
                "status": raw_result.get("status", "success"),
                "profile": profile.name,
                "profile_description": profile.description,
                "provider": provider_name,
                "model": model_name,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_ms": round(duration_ms, 2),
                "probes_executed": garak_probes,
                "sci_probes": profile.probes,
                "detectors_applied": detector_configs,
                "findings": raw_result.get("findings", []),
                "summary": raw_result.get("summary", {}),
                "compliance_tags": compliance_tags,
                "report_path": raw_result.get("report_path"),
                "error": raw_result.get("error"),
            }

            log_execution_end(
                f"garak_scan:{scan_id}",
                perf_start,
                status=result["status"],
                result={
                    "findings_count": len(result["findings"]),
                    "compliance_tags": compliance_tags,
                },
            )

            self.logger.info(
                "scan_completed",
                scan_id=scan_id,
                status=result["status"],
                duration_ms=result["duration_ms"],
                findings_count=len(result["findings"]),
                compliance_tags_count=len(compliance_tags),
            )

            return result

        except Exception as e:
            end_time = datetime.now(tz=UTC)
            duration_ms = (end_time - start_time).total_seconds() * 1000

            log_error(
                e,
                context={
                    "scan_id": scan_id,
                    "provider": provider_name,
                    "model": model_name,
                    "profile": profile_name,
                },
                command=f"garak_scan:{scan_id}",
            )

            return {
                "scan_id": scan_id,
                "status": "error",
                "profile": profile_name or "default",
                "provider": provider_name,
                "model": model_name,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_ms": round(duration_ms, 2),
                "probes_executed": [],
                "detectors_applied": [],
                "findings": [],
                "summary": {},
                "compliance_tags": [],
                "report_path": None,
                "error": {
                    "type": type(e).__name__,
                    "message": str(e),
                    "troubleshooting": self._get_troubleshooting_hint(e),
                },
            }

    def execute_batch_scan(
        self,
        targets: list[dict[str, str]],
        profile_name: Optional[str] = None,
        output_dir: Optional[Path] = None,
    ) -> dict[str, Any]:
        """
        Execute scans across multiple models or providers.

        Iterates through the provided targets and executes scans for each,
        aggregating results into a batch report. Partial failures are handled
        gracefully - if one target fails, the others continue.

        Args:
            targets: List of target dictionaries with structure:
                    [{"provider": str, "model": str}, ...]
            profile_name: Optional test profile name to use for all scans.
            output_dir: Optional output directory override.

        Returns:
            Dictionary containing batch results:
            {
                "batch_id": str,
                "status": "success" | "partial" | "error",
                "start_time": ISO timestamp,
                "end_time": ISO timestamp,
                "duration_ms": float,
                "total_targets": int,
                "successful": int,
                "failed": int,
                "results": list[dict],  # Individual scan results
                "summary": dict
            }

        Example:
            >>> targets = [
            ...     {"provider": "openai", "model": "gpt-4"},
            ...     {"provider": "anthropic", "model": "claude-3-opus"},
            ... ]
            >>> batch_result = engine.execute_batch_scan(targets, "quick_scan")
        """
        batch_id = str(uuid.uuid4())[:8]
        start_time = datetime.now(tz=UTC)
        perf_start = log_execution_start(
            f"garak_batch_scan:{batch_id}",
            {"targets_count": len(targets), "profile": profile_name},
        )

        self.logger.info(
            "batch_scan_started",
            batch_id=batch_id,
            targets_count=len(targets),
            profile=profile_name,
        )

        results: list[dict[str, Any]] = []
        successful = 0
        failed = 0

        for idx, target in enumerate(targets):
            provider = target.get("provider", "")
            model = target.get("model", "")

            if not provider or not model:
                self.logger.warning(
                    "invalid_target_skipped",
                    batch_id=batch_id,
                    target_index=idx,
                    target=target,
                )
                failed += 1
                results.append({
                    "target": target,
                    "status": "error",
                    "error": {
                        "type": "InvalidTarget",
                        "message": "Target must have 'provider' and 'model' fields",
                    },
                })
                continue

            self.logger.info(
                "batch_target_executing",
                batch_id=batch_id,
                target_index=idx,
                total_targets=len(targets),
                provider=provider,
                model=model,
                progress_percent=round((idx / len(targets)) * 100, 1),
            )

            result = self.execute_scan(
                provider_name=provider,
                model_name=model,
                profile_name=profile_name,
                output_dir=output_dir,
            )

            results.append(result)

            if result["status"] == "success":
                successful += 1
            else:
                failed += 1

            self.logger.debug(
                "batch_target_completed",
                batch_id=batch_id,
                target_index=idx,
                status=result["status"],
            )

        end_time = datetime.now(tz=UTC)
        duration_ms = (end_time - start_time).total_seconds() * 1000

        # Determine overall status
        if failed == 0:
            overall_status = "success"
        elif successful == 0:
            overall_status = "error"
        else:
            overall_status = "partial"

        # Aggregate summary
        all_findings: list[dict] = []
        all_compliance_tags: set[str] = set()
        for r in results:
            all_findings.extend(r.get("findings", []))
            all_compliance_tags.update(r.get("compliance_tags", []))

        batch_result = {
            "batch_id": batch_id,
            "status": overall_status,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_ms": round(duration_ms, 2),
            "total_targets": len(targets),
            "successful": successful,
            "failed": failed,
            "results": results,
            "summary": {
                "total_findings": len(all_findings),
                "compliance_tags": sorted(all_compliance_tags),
                "success_rate": round((successful / len(targets)) * 100, 1)
                if targets
                else 0,
            },
        }

        log_execution_end(
            f"garak_batch_scan:{batch_id}",
            perf_start,
            status=overall_status,
            result={
                "successful": successful,
                "failed": failed,
                "total_findings": len(all_findings),
            },
        )

        self.logger.info(
            "batch_scan_completed",
            batch_id=batch_id,
            status=overall_status,
            duration_ms=round(duration_ms, 2),
            successful=successful,
            failed=failed,
            total_findings=len(all_findings),
        )

        return batch_result

    def validate_scan_config(
        self,
        provider_name: str,
        profile_name: Optional[str] = None,
        probes: Optional[list[str]] = None,
    ) -> tuple[bool, list[str]]:
        """
        Pre-flight validation before scan execution.

        Validates all configuration elements required for a successful scan
        without actually executing the scan.

        Args:
            provider_name: Provider identifier to validate.
            profile_name: Optional profile name to validate.
            probes: Optional list of SCI probe names to validate.

        Returns:
            Tuple of (is_valid: bool, errors: list[str]).
            If is_valid is True, errors will be empty.

        Example:
            >>> is_valid, errors = engine.validate_scan_config("openai", "quick_scan")
            >>> if not is_valid:
            ...     print("Validation errors:", errors)
        """
        errors: list[str] = []

        self.logger.debug(
            "validating_scan_config",
            provider=provider_name,
            profile=profile_name,
            probes=probes,
        )

        # 1. Validate provider exists
        try:
            provider_config = self._get_provider_config(provider_name)
        except ValueError as e:
            errors.append(str(e))
            return False, errors

        # 2. Validate provider config has required fields
        validation_errors = validate_provider_config(provider_name, provider_config)
        errors.extend(validation_errors)

        # 3. Validate profile exists if specified
        if profile_name and profile_name not in self.config.profiles:
            errors.append(
                f"Profile '{profile_name}' not found. "
                f"Available profiles: {list(self.config.profiles.keys())}"
            )

        # 4. Validate probes can be mapped
        probe_list = probes or []
        if profile_name and profile_name in self.config.profiles:
            profile = self.config.profiles[profile_name]
            probe_list = probes or profile.probes

        for probe in probe_list:
            try:
                self.probe_mapper.map_probe_name(probe)
            except ValueError as e:
                errors.append(f"Probe mapping error: {e}")

        # 5. Validate detectors can be mapped
        if profile_name and profile_name in self.config.profiles:
            profile = self.config.profiles[profile_name]
            for detector in profile.detectors:
                try:
                    self.detector_mapper.map_detector_name(detector)
                except ValueError as e:
                    errors.append(f"Detector mapping error: {e}")

        # 6. Validate output directory is writable
        output_path = Path(self.config.output.directory)
        try:
            output_path.mkdir(parents=True, exist_ok=True)
            # Test write permission
            test_file = output_path / ".sci_write_test"
            test_file.touch()
            test_file.unlink()
        except (OSError, PermissionError) as e:
            errors.append(f"Output directory not writable: {e}")

        is_valid = len(errors) == 0

        self.logger.info(
            "scan_config_validated",
            provider=provider_name,
            profile=profile_name,
            is_valid=is_valid,
            errors_count=len(errors),
        )

        return is_valid, errors

    def get_available_probes(
        self,
        category: Optional[str] = None,
        compliance_tag: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        List available probes with optional filtering.

        Args:
            category: Optional category filter (e.g., "prompt_injection").
            compliance_tag: Optional EU AI Act tag filter (e.g., "article-15").

        Returns:
            List of probe dictionaries with metadata:
            [
                {
                    "name": str,
                    "garak_probes": list[str],
                    "category": str,
                    "compliance_tags": list[str],
                    "description": str
                },
                ...
            ]

        Example:
            >>> probes = engine.get_available_probes(compliance_tag="article-15")
            >>> for p in probes:
            ...     print(f"{p['name']}: {p['compliance_tags']}")
        """
        self.logger.debug(
            "listing_available_probes",
            category=category,
            compliance_tag=compliance_tag,
        )

        # Get probes from garak client (grouped by module)
        garak_probes_by_module = list_available_probes(self.client)

        # Build list of SCI probes with metadata
        result: list[dict[str, Any]] = []

        for sci_name, garak_module in self.config.garak.probe_categories.items():
            # Extract category from sci_name
            probe_category = sci_name.split("_")[0]

            # Apply category filter
            if category and not sci_name.startswith(category):
                continue

            # Get compliance tags
            articles = self.compliance_mapper.get_articles_for_probe(sci_name)

            # Apply compliance tag filter
            if compliance_tag and compliance_tag not in articles:
                continue

            # Get garak probes for this SCI probe
            try:
                garak_probes = self.probe_mapper.map_probe_name(sci_name)
            except ValueError:
                garak_probes = []

            result.append({
                "name": sci_name,
                "garak_module": garak_module,
                "garak_probes": garak_probes,
                "category": probe_category,
                "compliance_tags": articles,
                "risk_level": self.compliance_mapper.get_risk_category(
                    sci_name
                ).value,
                "description": self.compliance_mapper.get_compliance_description(
                    probe_category
                ),
            })

        self.logger.info(
            "probes_listed",
            total_count=len(result),
            category_filter=category,
            compliance_filter=compliance_tag,
        )

        return result

    def get_available_detectors(
        self,
        category: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        List available detectors with optional filtering.

        Args:
            category: Optional category filter (e.g., "toxicity").

        Returns:
            List of detector dictionaries with metadata:
            [
                {
                    "name": str,
                    "garak_detectors": list[str],
                    "category": str,
                    "level": str,
                    "config": dict
                },
                ...
            ]

        Example:
            >>> detectors = engine.get_available_detectors(category="toxicity")
            >>> for d in detectors:
            ...     print(f"{d['name']}: level={d['level']}")
        """
        self.logger.debug(
            "listing_available_detectors",
            category=category,
        )

        # Get all available detectors
        all_detectors = list_available_detectors(self.client)

        # Build list with metadata from DETECTOR_TYPE_MAPPING
        from sci.garak.mappings import DETECTOR_TYPE_MAPPING

        result: list[dict[str, Any]] = []

        for sci_name, config in DETECTOR_TYPE_MAPPING.items():
            # Extract category from sci_name
            detector_category = sci_name.split("_")[0]

            # Apply category filter
            if category and not sci_name.startswith(category):
                continue

            result.append({
                "name": sci_name,
                "garak_detectors": config.get("detectors", []),
                "category": detector_category,
                "level": config.get("level", "basic"),
                "config": {
                    k: v for k, v in config.items() if k not in ("detectors", "level")
                },
            })

        self.logger.info(
            "detectors_listed",
            total_count=len(result),
            category_filter=category,
        )

        return result

    def _resolve_profile(
        self,
        profile_name: Optional[str],
        probes_override: Optional[list[str]],
        detectors_override: Optional[list[str]],
    ) -> TestProfile:
        """
        Resolve test profile with command-line overrides.

        Args:
            profile_name: Optional profile name to load.
            probes_override: Optional probes list to override profile probes.
            detectors_override: Optional detectors list to override profile.

        Returns:
            Resolved TestProfile instance.
        """
        # Load base profile or create default
        if profile_name and profile_name in self.config.profiles:
            base_profile = self.config.profiles[profile_name]
            profile_dict = base_profile.model_dump()
        else:
            # Use default profile settings
            profile_dict = {
                "name": profile_name or "default",
                "description": "Default scan profile",
                "probes": list(self.config.garak.probe_categories.keys())[:3],
                "detectors": ["toxicity_basic", "leakage_basic"],
                "compliance_tags": [],
                "max_parallel": self.config.garak.parallelism,
                "timeout": self.config.garak.timeout,
            }

        # Apply overrides
        if probes_override:
            profile_dict["probes"] = probes_override
        if detectors_override:
            profile_dict["detectors"] = detectors_override

        return TestProfile.model_validate(profile_dict)

    def _get_provider_config(self, provider_name: str) -> ProviderConfig:
        """
        Get provider configuration from config or environment.

        Args:
            provider_name: Provider name to look up.

        Returns:
            ProviderConfig instance.

        Raises:
            ValueError: If provider not found in configuration.
        """
        provider_key = provider_name.lower().replace("-", "_")

        # Try to get from config.providers
        if self.config.providers:
            provider_config = getattr(self.config.providers, provider_key, None)
            if provider_config:
                # Check for environment variable overrides
                return self._apply_env_overrides(provider_key, provider_config)

        # Try to build from environment variables
        env_config = self._build_provider_from_env(provider_key)
        if env_config:
            return env_config

        raise ValueError(
            f"Provider '{provider_name}' not found in configuration. "
            f"Configure it in the config file or set environment variables."
        )

    def _apply_env_overrides(
        self,
        provider_key: str,
        config: ProviderConfig,
    ) -> ProviderConfig:
        """Apply environment variable overrides to provider config."""
        config_dict = config.model_dump()

        # Map of provider to environment variable names
        env_mapping = {
            "openai": {"api_key": "OPENAI_API_KEY"},
            "anthropic": {"api_key": "ANTHROPIC_API_KEY"},
            "google": {"api_key": "GOOGLE_API_KEY"},
            "azure": {
                "api_key": "AZURE_OPENAI_API_KEY",
                "endpoint": "AZURE_OPENAI_ENDPOINT",
            },
            "aws": {
                "access_key_id": "AWS_ACCESS_KEY_ID",
                "secret_access_key": "AWS_SECRET_ACCESS_KEY",
                "region": "AWS_REGION",
            },
            "huggingface": {"api_key": "HUGGINGFACE_API_KEY"},
        }

        mapping = env_mapping.get(provider_key, {})
        for config_key, env_var in mapping.items():
            env_value = os.environ.get(env_var)
            if env_value and not config_dict.get(config_key):
                config_dict[config_key] = env_value

        return type(config).model_validate(config_dict)

    def _build_provider_from_env(self, provider_key: str) -> Optional[ProviderConfig]:
        """Build provider configuration from environment variables."""
        from sci.config.models import (
            AWSProviderConfig,
            AzureProviderConfig,
            GoogleProviderConfig,
        )

        env_configs = {
            "openai": (
                ProviderConfig,
                {"api_key": os.environ.get("OPENAI_API_KEY")},
            ),
            "anthropic": (
                ProviderConfig,
                {"api_key": os.environ.get("ANTHROPIC_API_KEY")},
            ),
            "google": (
                GoogleProviderConfig,
                {
                    "api_key": os.environ.get("GOOGLE_API_KEY"),
                    "project_id": os.environ.get("GOOGLE_CLOUD_PROJECT"),
                },
            ),
            "azure": (
                AzureProviderConfig,
                {
                    "api_key": os.environ.get("AZURE_OPENAI_API_KEY"),
                    "endpoint": os.environ.get("AZURE_OPENAI_ENDPOINT"),
                    "deployment_name": os.environ.get("AZURE_OPENAI_DEPLOYMENT"),
                },
            ),
            "aws": (
                AWSProviderConfig,
                {
                    "access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
                    "secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
                    "region": os.environ.get("AWS_REGION", "us-east-1"),
                },
            ),
            "bedrock": (
                AWSProviderConfig,
                {
                    "access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
                    "secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
                    "region": os.environ.get("AWS_REGION", "us-east-1"),
                },
            ),
            "huggingface": (
                ProviderConfig,
                {"api_key": os.environ.get("HUGGINGFACE_API_KEY")},
            ),
        }

        if provider_key not in env_configs:
            return None

        config_class, config_data = env_configs[provider_key]

        # Check if any required env vars are set
        if not any(v for v in config_data.values() if v):
            return None

        return config_class.model_validate(config_data)

    def _resolve_output_dir(
        self,
        output_dir_override: Optional[Path],
        scan_id: str,
    ) -> Path:
        """Resolve and create output directory for scan results."""
        base_dir = output_dir_override or Path(self.config.output.directory)

        if self.config.output.include_timestamps:
            timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
            output_dir = base_dir / f"scan_{timestamp}_{scan_id}"
        else:
            output_dir = base_dir / f"scan_{scan_id}"

        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _get_troubleshooting_hint(self, error: Exception) -> str:
        """Generate troubleshooting hint based on error type."""
        error_type = type(error).__name__
        error_msg = str(error).lower()

        hints = {
            "authentication": (
                "Check that your API key is correct and has not expired. "
                "Verify the key is set in your config file or environment variables."
            ),
            "connection": (
                "Check your network connection and firewall settings. "
                "Verify the provider's API endpoint is accessible."
            ),
            "timeout": (
                "The request timed out. Consider increasing the timeout setting "
                "or reducing the number of probes in parallel."
            ),
            "rate_limit": (
                "You've hit the provider's rate limit. Wait a few minutes "
                "and try again, or reduce parallelism settings."
            ),
            "invalid": (
                "Check your configuration values. Ensure provider name, "
                "model name, and probe names are spelled correctly."
            ),
        }

        for keyword, hint in hints.items():
            if keyword in error_msg or keyword in error_type.lower():
                return hint

        return (
            "Check the error message for details. Verify your configuration "
            "and ensure garak is properly installed with 'pip install garak>=2.0.0'."
        )

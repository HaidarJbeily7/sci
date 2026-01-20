"""
Garak framework integration for SCI.

This module provides integration with the garak security testing framework,
enabling SCI to leverage garak's probes and detectors for LLM security testing.

The integration uses garak programmatically by invoking `garak.cli.main()` with
appropriate arguments. Provider adapters map SCI's `ProviderConfig` models to
garak's expected environment variables and command-line parameters.

The mapping system bridges SCI's semantic probe/detector names with garak's
technical identifiers, and provides EU AI Act compliance tagging.

Example:
    >>> from sci.garak import GarakClientWrapper, ProbeMapper
    >>> from sci.config.models import GarakConfig
    >>>
    >>> config = GarakConfig(parallelism=5, timeout=120)
    >>> client = GarakClientWrapper(config)
    >>>
    >>> # Map SCI probe names to garak identifiers
    >>> mapper = ProbeMapper(config)
    >>> garak_probes = mapper.map_probe_list(["prompt_injection_basic", "jailbreak_basic"])
    >>>
    >>> # Run a scan with mapped probes
    >>> results = client.run_scan(
    ...     generator_type="openai",
    ...     model_name="gpt-4",
    ...     probes=garak_probes,
    ...     env_vars={"OPENAI_API_KEY": "sk-..."},
    ... )
"""

from sci.garak.adapters import (
    adapt_anthropic_config,
    adapt_aws_config,
    adapt_azure_config,
    adapt_google_config,
    adapt_huggingface_config,
    adapt_openai_config,
    get_adapter_for_provider,
    validate_provider_config,
)
from sci.garak.client import GarakClientWrapper
from sci.garak.mappings import (
    ComplianceMapper,
    DetectorMapper,
    ProbeMapper,
    get_detector_description,
    get_probe_description,
    list_available_detectors,
    list_available_probes,
    validate_mappings,
)

__all__ = [
    # Client
    "GarakClientWrapper",
    # Mappers
    "ProbeMapper",
    "DetectorMapper",
    "ComplianceMapper",
    # Utility functions
    "list_available_probes",
    "list_available_detectors",
    "validate_mappings",
    "get_probe_description",
    "get_detector_description",
    # Provider adapters
    "adapt_anthropic_config",
    "adapt_aws_config",
    "adapt_azure_config",
    "adapt_google_config",
    "adapt_huggingface_config",
    "adapt_openai_config",
    "get_adapter_for_provider",
    "validate_provider_config",
]

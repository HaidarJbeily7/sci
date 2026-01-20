"""
Garak framework integration for SCI.

This module provides integration with the garak security testing framework,
enabling SCI to leverage garak's probes and detectors for LLM security testing.

The integration uses garak programmatically by invoking `garak.cli.main()` with
appropriate arguments. Provider adapters map SCI's `ProviderConfig` models to
garak's expected environment variables and command-line parameters.

Example:
    >>> from sci.garak import GarakClientWrapper
    >>> from sci.config.models import GarakConfig
    >>>
    >>> config = GarakConfig(parallelism=5, timeout=120)
    >>> client = GarakClientWrapper(config)
    >>>
    >>> # Run a scan
    >>> results = client.run_scan(
    ...     generator_type="openai",
    ...     model_name="gpt-4",
    ...     probes=["encoding.InjectBase64"],
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

__all__ = [
    "GarakClientWrapper",
    "adapt_anthropic_config",
    "adapt_aws_config",
    "adapt_azure_config",
    "adapt_google_config",
    "adapt_huggingface_config",
    "adapt_openai_config",
    "get_adapter_for_provider",
    "validate_provider_config",
]

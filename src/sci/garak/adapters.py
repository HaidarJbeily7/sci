"""
Provider adapters for garak integration.

This module provides adapter functions that map SCI's provider configurations
to garak-compatible formats, including environment variables and CLI parameters.
"""

from typing import Any, Callable

from sci.config.models import (
    AWSProviderConfig,
    AzureProviderConfig,
    GoogleProviderConfig,
    ProviderConfig,
)
from sci.logging.setup import get_logger

logger = get_logger(__name__)


def adapt_openai_config(
    config: ProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt OpenAI provider configuration for garak.

    Args:
        config: SCI ProviderConfig for OpenAI.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = ProviderConfig(api_key="sk-...", model="gpt-4")
        >>> gen_type, env_vars, params = adapt_openai_config(config)
        >>> gen_type
        'openai'
        >>> env_vars
        {'OPENAI_API_KEY': 'sk-...'}
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.api_key:
        env_vars["OPENAI_API_KEY"] = config.api_key

    if config.base_url:
        # OpenAI allows custom base URLs for API-compatible services
        env_vars["OPENAI_API_BASE"] = config.base_url
        additional_params["api_base"] = config.base_url

    if config.model:
        additional_params["model_name"] = config.model

    logger.debug(
        "adapted_openai_config",
        has_api_key=bool(config.api_key),
        has_base_url=bool(config.base_url),
        model=config.model,
    )

    return "openai", env_vars, additional_params


def adapt_anthropic_config(
    config: ProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt Anthropic provider configuration for garak.

    Args:
        config: SCI ProviderConfig for Anthropic.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = ProviderConfig(api_key="sk-ant-...", model="claude-3-opus")
        >>> gen_type, env_vars, params = adapt_anthropic_config(config)
        >>> gen_type
        'anthropic'
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.api_key:
        env_vars["ANTHROPIC_API_KEY"] = config.api_key

    if config.model:
        additional_params["model_name"] = config.model

    logger.debug(
        "adapted_anthropic_config",
        has_api_key=bool(config.api_key),
        model=config.model,
    )

    return "anthropic", env_vars, additional_params


def adapt_google_config(
    config: GoogleProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt Google AI provider configuration for garak.

    Args:
        config: SCI GoogleProviderConfig.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = GoogleProviderConfig(
        ...     api_key="...",
        ...     project_id="my-project",
        ...     location="us-central1"
        ... )
        >>> gen_type, env_vars, params = adapt_google_config(config)
        >>> params['project_id']
        'my-project'
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.api_key:
        env_vars["GOOGLE_API_KEY"] = config.api_key

    if config.project_id:
        additional_params["project_id"] = config.project_id
        env_vars["GOOGLE_CLOUD_PROJECT"] = config.project_id

    if config.location:
        additional_params["location"] = config.location
        env_vars["GOOGLE_CLOUD_LOCATION"] = config.location

    if config.model:
        additional_params["model_name"] = config.model

    logger.debug(
        "adapted_google_config",
        has_api_key=bool(config.api_key),
        project_id=config.project_id,
        location=config.location,
        model=config.model,
    )

    return "google", env_vars, additional_params


def adapt_azure_config(
    config: AzureProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt Azure OpenAI provider configuration for garak.

    Args:
        config: SCI AzureProviderConfig.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = AzureProviderConfig(
        ...     api_key="...",
        ...     endpoint="https://my-resource.openai.azure.com",
        ...     deployment_name="gpt-4-deployment"
        ... )
        >>> gen_type, env_vars, params = adapt_azure_config(config)
        >>> gen_type
        'azure'
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.api_key:
        env_vars["AZURE_OPENAI_KEY"] = config.api_key
        env_vars["AZURE_OPENAI_API_KEY"] = config.api_key

    if config.endpoint:
        env_vars["AZURE_OPENAI_ENDPOINT"] = config.endpoint
        additional_params["endpoint"] = config.endpoint

    if config.api_version:
        env_vars["AZURE_OPENAI_API_VERSION"] = config.api_version
        additional_params["api_version"] = config.api_version

    if config.deployment_name:
        additional_params["deployment_name"] = config.deployment_name
        additional_params["model_name"] = config.deployment_name

    logger.debug(
        "adapted_azure_config",
        has_api_key=bool(config.api_key),
        has_endpoint=bool(config.endpoint),
        api_version=config.api_version,
        deployment_name=config.deployment_name,
    )

    return "azure", env_vars, additional_params


def adapt_aws_config(
    config: AWSProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt AWS Bedrock provider configuration for garak.

    Args:
        config: SCI AWSProviderConfig.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = AWSProviderConfig(
        ...     access_key_id="AKIA...",
        ...     secret_access_key="...",
        ...     region="us-east-1",
        ...     model="anthropic.claude-v2"
        ... )
        >>> gen_type, env_vars, params = adapt_aws_config(config)
        >>> gen_type
        'bedrock'
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.access_key_id:
        env_vars["AWS_ACCESS_KEY_ID"] = config.access_key_id

    if config.secret_access_key:
        env_vars["AWS_SECRET_ACCESS_KEY"] = config.secret_access_key

    if config.region:
        env_vars["AWS_DEFAULT_REGION"] = config.region
        env_vars["AWS_REGION"] = config.region
        env_vars["BEDROCK_REGION"] = config.region
        additional_params["region"] = config.region

    if config.model:
        additional_params["model_name"] = config.model

    logger.debug(
        "adapted_aws_config",
        has_access_key=bool(config.access_key_id),
        has_secret_key=bool(config.secret_access_key),
        region=config.region,
        model=config.model,
    )

    return "bedrock", env_vars, additional_params


def adapt_huggingface_config(
    config: ProviderConfig,
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """
    Adapt Hugging Face provider configuration for garak.

    Args:
        config: SCI ProviderConfig for Hugging Face.

    Returns:
        Tuple of (generator_type, env_vars, additional_params).

    Example:
        >>> config = ProviderConfig(
        ...     api_key="hf_...",
        ...     model="meta-llama/Llama-2-7b-chat-hf"
        ... )
        >>> gen_type, env_vars, params = adapt_huggingface_config(config)
        >>> gen_type
        'huggingface'
    """
    env_vars: dict[str, str] = {}
    additional_params: dict[str, Any] = {}

    if config.api_key:
        env_vars["HUGGINGFACE_API_KEY"] = config.api_key
        env_vars["HF_TOKEN"] = config.api_key
        env_vars["HUGGING_FACE_HUB_TOKEN"] = config.api_key

    if config.base_url:
        additional_params["api_base"] = config.base_url
        env_vars["HF_INFERENCE_ENDPOINT"] = config.base_url

    if config.model:
        additional_params["model_name"] = config.model

    logger.debug(
        "adapted_huggingface_config",
        has_api_key=bool(config.api_key),
        has_base_url=bool(config.base_url),
        model=config.model,
    )

    return "huggingface", env_vars, additional_params


# Type alias for adapter functions
AdapterFunc = Callable[[ProviderConfig], tuple[str, dict[str, str], dict[str, Any]]]

# Registry of provider adapters
_ADAPTER_REGISTRY: dict[str, AdapterFunc] = {
    "openai": adapt_openai_config,
    "anthropic": adapt_anthropic_config,
    "google": adapt_google_config,  # type: ignore[dict-item]
    "azure": adapt_azure_config,  # type: ignore[dict-item]
    "aws": adapt_aws_config,  # type: ignore[dict-item]
    "bedrock": adapt_aws_config,  # type: ignore[dict-item]
    "huggingface": adapt_huggingface_config,
    "hugging_face": adapt_huggingface_config,
    "hf": adapt_huggingface_config,
}


def get_adapter_for_provider(provider_name: str) -> AdapterFunc:
    """
    Get the appropriate adapter function for a provider.

    Args:
        provider_name: Name of the provider (e.g., "openai", "anthropic").

    Returns:
        Adapter function for the provider.

    Raises:
        ValueError: If the provider is not supported.

    Example:
        >>> adapter = get_adapter_for_provider("openai")
        >>> config = ProviderConfig(api_key="sk-...")
        >>> gen_type, env_vars, params = adapter(config)
    """
    provider_key = provider_name.lower().replace("-", "_")

    if provider_key not in _ADAPTER_REGISTRY:
        supported = ", ".join(sorted(set(_ADAPTER_REGISTRY.keys())))
        raise ValueError(
            f"Unsupported provider: {provider_name}. "
            f"Supported providers: {supported}"
        )

    logger.debug(
        "adapter_resolved",
        provider=provider_name,
        adapter=_ADAPTER_REGISTRY[provider_key].__name__,
    )

    return _ADAPTER_REGISTRY[provider_key]


def validate_provider_config(
    provider_name: str,
    config: ProviderConfig,
) -> list[str]:
    """
    Validate that required fields are present for a provider.

    Args:
        provider_name: Name of the provider.
        config: Provider configuration to validate.

    Returns:
        List of validation error messages (empty if valid).

    Example:
        >>> config = ProviderConfig()  # Missing API key
        >>> errors = validate_provider_config("openai", config)
        >>> errors
        ['API key is required for openai provider']
    """
    errors: list[str] = []
    provider_key = provider_name.lower().replace("-", "_")

    # Common validation: API key required for most providers
    api_key_required_providers = {
        "openai",
        "anthropic",
        "google",
        "huggingface",
        "hugging_face",
        "hf",
    }

    if provider_key in api_key_required_providers:
        if not config.api_key:
            errors.append(f"API key is required for {provider_name} provider")

    # Provider-specific validation
    if provider_key == "azure":
        if isinstance(config, AzureProviderConfig):
            if not config.api_key:
                errors.append("API key is required for Azure provider")
            if not config.endpoint:
                errors.append("Endpoint URL is required for Azure provider")
            if not config.deployment_name:
                errors.append("Deployment name is required for Azure provider")
        else:
            errors.append("Azure provider requires AzureProviderConfig")

    elif provider_key in ("aws", "bedrock"):
        if isinstance(config, AWSProviderConfig):
            if not config.access_key_id:
                errors.append("AWS access key ID is required for AWS/Bedrock provider")
            if not config.secret_access_key:
                errors.append(
                    "AWS secret access key is required for AWS/Bedrock provider"
                )
            if not config.region:
                errors.append("AWS region is required for AWS/Bedrock provider")
        else:
            errors.append("AWS/Bedrock provider requires AWSProviderConfig")

    elif provider_key == "google":
        if isinstance(config, GoogleProviderConfig):
            if not config.api_key:
                errors.append("API key is required for Google provider")
            # project_id and location have defaults, so not strictly required
        else:
            errors.append("Google provider requires GoogleProviderConfig")

    # Validate API key is not empty string
    if config.api_key is not None and config.api_key.strip() == "":
        errors.append("API key cannot be an empty string")

    logger.debug(
        "provider_config_validated",
        provider=provider_name,
        errors_count=len(errors),
        is_valid=len(errors) == 0,
    )

    return errors

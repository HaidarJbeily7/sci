"""
Unit tests for garak provider adapters.

Tests the adapter functions that convert SCI provider configurations
to garak-compatible formats including environment variables and CLI parameters.
"""

import pytest

from sci.config.models import (
    AWSProviderConfig,
    AzureProviderConfig,
    GoogleProviderConfig,
    ProviderConfig,
)
from sci.engine.exceptions import GarakConfigurationError
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


class TestAdaptOpenAIConfig:
    """Tests for adapt_openai_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic OpenAI configuration."""
        config = ProviderConfig(
            api_key="sk-test-key-1234567890abcdef1234567890abcdef",
            model="gpt-4",
        )

        gen_type, env_vars, params = adapt_openai_config(config)

        assert gen_type == "openai"
        assert env_vars["OPENAI_API_KEY"] == config.api_key
        assert params.get("model_name") == "gpt-4"

    def test_with_base_url(self) -> None:
        """Test adapting config with custom base URL."""
        config = ProviderConfig(
            api_key="sk-test-key",
            base_url="https://custom-api.example.com/v1",
            model="gpt-4",
        )

        gen_type, env_vars, params = adapt_openai_config(config)

        assert env_vars["OPENAI_API_BASE"] == config.base_url
        assert params["api_base"] == config.base_url

    def test_without_api_key(self) -> None:
        """Test adapting config without API key (uses env var)."""
        config = ProviderConfig(model="gpt-4")

        gen_type, env_vars, params = adapt_openai_config(config)

        assert gen_type == "openai"
        assert "OPENAI_API_KEY" not in env_vars

    def test_without_model(self) -> None:
        """Test adapting config without model."""
        config = ProviderConfig(api_key="sk-test-key")

        gen_type, env_vars, params = adapt_openai_config(config)

        assert "model_name" not in params or params.get("model_name") is None


class TestAdaptAnthropicConfig:
    """Tests for adapt_anthropic_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic Anthropic configuration."""
        config = ProviderConfig(
            api_key="sk-ant-test-key-1234567890abcdef1234567890abcdef",
            model="claude-3-opus-20240229",
        )

        gen_type, env_vars, params = adapt_anthropic_config(config)

        assert gen_type == "anthropic"
        assert env_vars["ANTHROPIC_API_KEY"] == config.api_key
        assert params.get("model_name") == "claude-3-opus-20240229"

    def test_without_api_key(self) -> None:
        """Test adapting config without API key."""
        config = ProviderConfig(model="claude-3-sonnet")

        gen_type, env_vars, params = adapt_anthropic_config(config)

        assert gen_type == "anthropic"
        assert "ANTHROPIC_API_KEY" not in env_vars


class TestAdaptGoogleConfig:
    """Tests for adapt_google_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic Google configuration."""
        config = GoogleProviderConfig(
            api_key="google-test-key",
            project_id="my-project",
            location="us-central1",
            model="gemini-pro",
        )

        gen_type, env_vars, params = adapt_google_config(config)

        assert gen_type == "google"
        assert env_vars["GOOGLE_API_KEY"] == config.api_key
        assert env_vars["GOOGLE_CLOUD_PROJECT"] == "my-project"
        assert env_vars["GOOGLE_CLOUD_LOCATION"] == "us-central1"
        assert params["project_id"] == "my-project"
        assert params["location"] == "us-central1"

    def test_with_defaults(self) -> None:
        """Test adapting config with default values."""
        config = GoogleProviderConfig(api_key="google-test-key")

        gen_type, env_vars, params = adapt_google_config(config)

        assert gen_type == "google"
        # Default location should be set
        assert params.get("location") == "us-central1"


class TestAdaptAzureConfig:
    """Tests for adapt_azure_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic Azure configuration."""
        config = AzureProviderConfig(
            api_key="azure-test-key",
            endpoint="https://my-resource.openai.azure.com",
            deployment_name="gpt-4-deployment",
            api_version="2024-02-15-preview",
        )

        gen_type, env_vars, params = adapt_azure_config(config)

        assert gen_type == "azure"
        assert env_vars["AZURE_OPENAI_KEY"] == config.api_key
        assert env_vars["AZURE_OPENAI_API_KEY"] == config.api_key
        assert env_vars["AZURE_OPENAI_ENDPOINT"] == config.endpoint
        assert env_vars["AZURE_OPENAI_API_VERSION"] == "2024-02-15-preview"
        assert params["endpoint"] == config.endpoint
        assert params["deployment_name"] == "gpt-4-deployment"

    def test_deployment_as_model_name(self) -> None:
        """Test that deployment name is also set as model_name."""
        config = AzureProviderConfig(
            api_key="azure-test-key",
            endpoint="https://my-resource.openai.azure.com",
            deployment_name="my-deployment",
        )

        gen_type, env_vars, params = adapt_azure_config(config)

        assert params["model_name"] == "my-deployment"


class TestAdaptAWSConfig:
    """Tests for adapt_aws_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic AWS Bedrock configuration."""
        config = AWSProviderConfig(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1",
            model="anthropic.claude-v2",
        )

        gen_type, env_vars, params = adapt_aws_config(config)

        assert gen_type == "bedrock"
        assert env_vars["AWS_ACCESS_KEY_ID"] == config.access_key_id
        assert env_vars["AWS_SECRET_ACCESS_KEY"] == config.secret_access_key
        assert env_vars["AWS_DEFAULT_REGION"] == "us-east-1"
        assert env_vars["AWS_REGION"] == "us-east-1"
        assert env_vars["BEDROCK_REGION"] == "us-east-1"
        assert params["region"] == "us-east-1"

    def test_without_credentials(self) -> None:
        """Test adapting config without explicit credentials (uses env/IAM)."""
        config = AWSProviderConfig(
            region="us-west-2",
            model="anthropic.claude-v2",
        )

        gen_type, env_vars, params = adapt_aws_config(config)

        assert gen_type == "bedrock"
        assert "AWS_ACCESS_KEY_ID" not in env_vars
        assert params["region"] == "us-west-2"


class TestAdaptHuggingFaceConfig:
    """Tests for adapt_huggingface_config function."""

    def test_basic_config(self) -> None:
        """Test adapting basic Hugging Face configuration."""
        config = ProviderConfig(
            api_key="hf_test_token_1234567890abcdef1234567890",
            model="meta-llama/Llama-2-7b-chat-hf",
        )

        gen_type, env_vars, params = adapt_huggingface_config(config)

        assert gen_type == "huggingface"
        assert env_vars["HUGGINGFACE_API_KEY"] == config.api_key
        assert env_vars["HF_TOKEN"] == config.api_key
        assert env_vars["HUGGING_FACE_HUB_TOKEN"] == config.api_key
        assert params.get("model_name") == config.model

    def test_with_base_url(self) -> None:
        """Test adapting config with custom inference endpoint."""
        config = ProviderConfig(
            api_key="hf_test_token",
            base_url="https://my-inference-endpoint.huggingface.cloud",
            model="my-model",
        )

        gen_type, env_vars, params = adapt_huggingface_config(config)

        assert env_vars["HF_INFERENCE_ENDPOINT"] == config.base_url
        assert params["api_base"] == config.base_url


class TestGetAdapterForProvider:
    """Tests for get_adapter_for_provider function."""

    def test_get_openai_adapter(self) -> None:
        """Test getting OpenAI adapter."""
        adapter = get_adapter_for_provider("openai")
        assert adapter == adapt_openai_config

    def test_get_anthropic_adapter(self) -> None:
        """Test getting Anthropic adapter."""
        adapter = get_adapter_for_provider("anthropic")
        assert adapter == adapt_anthropic_config

    def test_get_google_adapter(self) -> None:
        """Test getting Google adapter."""
        adapter = get_adapter_for_provider("google")
        assert adapter == adapt_google_config

    def test_get_azure_adapter(self) -> None:
        """Test getting Azure adapter."""
        adapter = get_adapter_for_provider("azure")
        assert adapter == adapt_azure_config

    def test_get_aws_adapter(self) -> None:
        """Test getting AWS adapter."""
        adapter = get_adapter_for_provider("aws")
        assert adapter == adapt_aws_config

    def test_get_bedrock_adapter(self) -> None:
        """Test getting Bedrock adapter (alias for AWS)."""
        adapter = get_adapter_for_provider("bedrock")
        assert adapter == adapt_aws_config

    def test_get_huggingface_adapter(self) -> None:
        """Test getting Hugging Face adapter."""
        adapter = get_adapter_for_provider("huggingface")
        assert adapter == adapt_huggingface_config

    def test_get_huggingface_aliases(self) -> None:
        """Test Hugging Face adapter aliases."""
        adapter1 = get_adapter_for_provider("hugging_face")
        adapter2 = get_adapter_for_provider("hf")

        assert adapter1 == adapt_huggingface_config
        assert adapter2 == adapt_huggingface_config

    def test_case_insensitive(self) -> None:
        """Test that provider names are case-insensitive."""
        adapter1 = get_adapter_for_provider("OpenAI")
        adapter2 = get_adapter_for_provider("OPENAI")
        adapter3 = get_adapter_for_provider("openai")

        assert adapter1 == adapter2 == adapter3

    def test_unsupported_provider_raises_error(self) -> None:
        """Test that unsupported provider raises error."""
        with pytest.raises(GarakConfigurationError) as exc_info:
            get_adapter_for_provider("unsupported_provider")

        assert "CONFIG" in exc_info.value.error_code
        assert "unsupported" in str(exc_info.value).lower()


class TestValidateProviderConfig:
    """Tests for validate_provider_config function."""

    def test_valid_openai_config(self) -> None:
        """Test validation of valid OpenAI config."""
        config = ProviderConfig(
            api_key="sk-test-key-1234567890abcdef1234567890abcdef",
            model="gpt-4",
        )

        errors = validate_provider_config("openai", config)

        assert len(errors) == 0

    def test_openai_missing_api_key(self) -> None:
        """Test validation of OpenAI config missing API key."""
        config = ProviderConfig(model="gpt-4")

        errors = validate_provider_config("openai", config)

        assert len(errors) > 0
        assert any("api key" in e.lower() for e in errors)

    def test_openai_invalid_api_key_format(self) -> None:
        """Test validation of OpenAI config with invalid key format."""
        config = ProviderConfig(
            api_key="invalid-key-format",  # Doesn't start with sk-
            model="gpt-4",
        )

        errors = validate_provider_config("openai", config)

        assert len(errors) > 0
        assert any("format" in e.lower() for e in errors)

    def test_valid_azure_config(self) -> None:
        """Test validation of valid Azure config."""
        config = AzureProviderConfig(
            api_key="azure-key",
            endpoint="https://my-resource.openai.azure.com",
            deployment_name="gpt-4-deployment",
        )

        errors = validate_provider_config("azure", config)

        assert len(errors) == 0

    def test_azure_missing_endpoint(self) -> None:
        """Test validation of Azure config missing endpoint."""
        config = AzureProviderConfig(
            api_key="azure-key",
            deployment_name="gpt-4-deployment",
        )

        errors = validate_provider_config("azure", config)

        assert len(errors) > 0
        assert any("endpoint" in e.lower() for e in errors)

    def test_azure_missing_deployment(self) -> None:
        """Test validation of Azure config missing deployment name."""
        config = AzureProviderConfig(
            api_key="azure-key",
            endpoint="https://my-resource.openai.azure.com",
        )

        errors = validate_provider_config("azure", config)

        assert len(errors) > 0
        assert any("deployment" in e.lower() for e in errors)

    def test_azure_invalid_endpoint_format(self) -> None:
        """Test validation of Azure config with invalid endpoint."""
        config = AzureProviderConfig(
            api_key="azure-key",
            endpoint="not-a-valid-url",
            deployment_name="gpt-4-deployment",
        )

        errors = validate_provider_config("azure", config)

        assert len(errors) > 0

    def test_valid_aws_config(self) -> None:
        """Test validation of valid AWS config."""
        config = AWSProviderConfig(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1",
        )

        errors = validate_provider_config("aws", config)

        assert len(errors) == 0

    def test_aws_missing_credentials(self) -> None:
        """Test validation of AWS config missing credentials."""
        config = AWSProviderConfig(region="us-east-1")

        errors = validate_provider_config("aws", config)

        assert len(errors) > 0
        assert any("access key" in e.lower() for e in errors)
        assert any("secret" in e.lower() for e in errors)

    def test_aws_missing_region(self) -> None:
        """Test validation of AWS config missing region."""
        config = AWSProviderConfig(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="secret",
        )

        errors = validate_provider_config("aws", config)

        assert len(errors) > 0
        assert any("region" in e.lower() for e in errors)

    def test_valid_google_config(self) -> None:
        """Test validation of valid Google config."""
        config = GoogleProviderConfig(api_key="google-api-key")

        errors = validate_provider_config("google", config)

        assert len(errors) == 0

    def test_google_missing_api_key(self) -> None:
        """Test validation of Google config missing API key."""
        config = GoogleProviderConfig()

        errors = validate_provider_config("google", config)

        assert len(errors) > 0
        assert any("api key" in e.lower() for e in errors)

    def test_valid_huggingface_config(self) -> None:
        """Test validation of valid Hugging Face config."""
        config = ProviderConfig(
            api_key="hf_test_token_1234567890abcdef1234567890"
        )

        errors = validate_provider_config("huggingface", config)

        assert len(errors) == 0

    def test_huggingface_invalid_token_format(self) -> None:
        """Test validation of HF config with invalid token format."""
        config = ProviderConfig(api_key="invalid-token-format")

        errors = validate_provider_config("huggingface", config)

        assert len(errors) > 0
        assert any("format" in e.lower() for e in errors)

    def test_empty_api_key_string(self) -> None:
        """Test validation rejects empty string API key."""
        config = ProviderConfig(api_key="   ")

        errors = validate_provider_config("openai", config)

        assert len(errors) > 0
        assert any("empty" in e.lower() for e in errors)

    def test_invalid_base_url(self) -> None:
        """Test validation of invalid base URL."""
        config = ProviderConfig(
            api_key="sk-test-key-1234567890abcdef1234567890abcdef",
            base_url="not-a-valid-url",
        )

        errors = validate_provider_config("openai", config)

        assert len(errors) > 0
        assert any("url" in e.lower() for e in errors)


class TestAdapterIntegration:
    """Integration tests for adapter workflow."""

    def test_full_adapter_workflow_openai(self) -> None:
        """Test complete adapter workflow for OpenAI."""
        config = ProviderConfig(
            api_key="sk-test-key-1234567890abcdef1234567890abcdef",
            model="gpt-4",
        )

        # Get adapter
        adapter = get_adapter_for_provider("openai")

        # Validate config
        errors = validate_provider_config("openai", config)
        assert len(errors) == 0

        # Adapt config
        gen_type, env_vars, params = adapter(config)

        # Verify results
        assert gen_type == "openai"
        assert "OPENAI_API_KEY" in env_vars
        assert params.get("model_name") == "gpt-4"

    def test_full_adapter_workflow_azure(self) -> None:
        """Test complete adapter workflow for Azure."""
        config = AzureProviderConfig(
            api_key="azure-key",
            endpoint="https://my-resource.openai.azure.com",
            deployment_name="gpt-4-deployment",
            api_version="2024-02-15-preview",
        )

        # Get adapter
        adapter = get_adapter_for_provider("azure")

        # Validate config
        errors = validate_provider_config("azure", config)
        assert len(errors) == 0

        # Adapt config
        gen_type, env_vars, params = adapter(config)

        # Verify results
        assert gen_type == "azure"
        assert "AZURE_OPENAI_KEY" in env_vars
        assert "AZURE_OPENAI_ENDPOINT" in env_vars
        assert params["deployment_name"] == "gpt-4-deployment"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

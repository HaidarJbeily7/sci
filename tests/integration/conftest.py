"""
Pytest fixtures for garak integration tests.

This module provides shared fixtures for integration testing of garak
components including mocked clients, configurations, and sample data.
"""

import json
import tempfile
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

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

# Import test fixtures
from tests.fixtures.garak_reports import (
    get_mock_available_probes,
    get_mock_client_run_scan_response,
    get_sample_garak_config,
    get_sample_scan_result_success,
    get_sample_test_profile_standard,
    get_sample_openai_config,
    get_sample_anthropic_config,
    get_sample_azure_config,
    get_sample_aws_config,
    get_sample_google_config,
    get_sample_huggingface_config,
)


# =============================================================================
# Mock Garak Client Fixture
# =============================================================================


@pytest.fixture
def mock_garak_client() -> Generator[MagicMock, None, None]:
    """
    Fixture providing a mocked GarakClientWrapper.

    The mock is pre-configured with common return values:
    - validate_installation() returns True
    - run_scan() returns sample scan results
    - list_available_probes() returns a list of probe names
    - list_available_generators() returns a list of generator names
    - validate_connection() returns True

    Yields:
        MagicMock instance configured as GarakClientWrapper.
    """
    with patch("sci.garak.client.GarakClientWrapper") as mock_class:
        mock_instance = MagicMock()

        # Configure default behaviors
        mock_instance.validate_installation.return_value = True
        mock_instance.run_scan.return_value = get_mock_client_run_scan_response()
        mock_instance.list_available_probes.return_value = get_mock_available_probes()
        mock_instance.list_available_generators.return_value = [
            "openai",
            "anthropic",
            "google",
            "azure",
            "bedrock",
            "huggingface",
        ]
        mock_instance.validate_connection.return_value = True
        mock_instance.config = GarakConfig(**get_sample_garak_config())

        mock_class.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_garak_import() -> Generator[None, None, None]:
    """
    Fixture that mocks garak module import.

    Useful for testing code that depends on garak being installed
    without actually requiring the package.

    Yields:
        None
    """
    mock_garak = MagicMock()
    mock_garak.__version__ = "2.0.0"
    mock_garak.cli = MagicMock()
    mock_garak.cli.main = MagicMock(return_value=0)

    with patch.dict("sys.modules", {"garak": mock_garak, "garak.cli": mock_garak.cli}):
        yield


# =============================================================================
# Configuration Fixtures
# =============================================================================


@pytest.fixture
def sample_garak_config() -> GarakConfig:
    """
    Fixture providing a sample GarakConfig instance.

    Returns:
        GarakConfig with default test values.
    """
    return GarakConfig(**get_sample_garak_config())


@pytest.fixture
def sample_sci_config(sample_garak_config: GarakConfig) -> SCIConfig:
    """
    Fixture providing a sample SCIConfig instance.

    Args:
        sample_garak_config: Injected GarakConfig fixture.

    Returns:
        SCIConfig with test values.
    """
    return SCIConfig(
        garak=sample_garak_config,
        output=OutputConfig(
            directory="./test_results",
            format="json",
            compression=False,
            include_timestamps=True,
        ),
    )


@pytest.fixture
def sample_config_manager(
    temp_output_dir: Path,
) -> Generator[ConfigManager, None, None]:
    """
    Fixture providing a pre-configured ConfigManager.

    The ConfigManager is initialized with test configuration data
    and a temporary output directory.

    Args:
        temp_output_dir: Injected temporary directory fixture.

    Yields:
        ConfigManager instance with test configuration.
    """
    # Create a temporary config file
    config_data = {
        "logging": {"level": "DEBUG", "format": "console"},
        "output": {
            "directory": str(temp_output_dir),
            "format": "json",
        },
        "garak": get_sample_garak_config(),
        "profiles": {
            "standard": get_sample_test_profile_standard(),
            "minimal": {
                "name": "minimal",
                "description": "Minimal test profile",
                "probes": ["prompt_injection_basic"],
                "detectors": ["toxicity_basic"],
            },
        },
        "providers": {
            "openai": get_sample_openai_config(),
            "anthropic": get_sample_anthropic_config(),
        },
    }

    config_file = temp_output_dir / "test_settings.yaml"
    import yaml

    with open(config_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(config_data, f)

    # Create ConfigManager
    manager = ConfigManager()

    # Mock the config loading
    with patch.object(manager, "_config", config_data):
        with patch.object(manager, "_loaded", True):
            yield manager


# =============================================================================
# Directory Fixtures
# =============================================================================


@pytest.fixture
def temp_output_dir() -> Generator[Path, None, None]:
    """
    Fixture providing a temporary output directory.

    The directory is automatically cleaned up after the test.

    Yields:
        Path to the temporary directory.
    """
    with tempfile.TemporaryDirectory(prefix="sci_test_") as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def temp_report_dir(temp_output_dir: Path) -> Path:
    """
    Fixture providing a directory with sample report files.

    Creates a subdirectory with sample garak reports for testing
    report parsing and storage functionality.

    Args:
        temp_output_dir: Injected temporary directory fixture.

    Returns:
        Path to the reports directory.
    """
    reports_dir = temp_output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Create sample report files
    from tests.fixtures.garak_reports import (
        get_sample_garak_report_json,
        get_sample_garak_report_jsonl,
    )

    # JSON report
    with open(reports_dir / "report.json", "w", encoding="utf-8") as f:
        json.dump(get_sample_garak_report_json(), f, indent=2)

    # JSONL report
    with open(reports_dir / "report.jsonl", "w", encoding="utf-8") as f:
        f.write(get_sample_garak_report_jsonl())

    return reports_dir


# =============================================================================
# Scan Result Fixtures
# =============================================================================


@pytest.fixture
def sample_scan_results() -> dict[str, Any]:
    """
    Fixture providing realistic scan results.

    Returns:
        Dictionary with scan results including findings and summary.
    """
    return get_sample_scan_result_success()


@pytest.fixture
def sample_scan_results_with_errors() -> dict[str, Any]:
    """
    Fixture providing scan results with some probe failures.

    Returns:
        Dictionary with partial success scan results.
    """
    from tests.fixtures.garak_reports import get_sample_scan_result_partial

    return get_sample_scan_result_partial()


# =============================================================================
# Provider Configuration Fixtures
# =============================================================================


@pytest.fixture
def mock_openai_config() -> ProviderConfig:
    """Fixture providing mock OpenAI provider configuration."""
    return ProviderConfig(**get_sample_openai_config())


@pytest.fixture
def mock_anthropic_config() -> ProviderConfig:
    """Fixture providing mock Anthropic provider configuration."""
    return ProviderConfig(**get_sample_anthropic_config())


@pytest.fixture
def mock_azure_config() -> AzureProviderConfig:
    """Fixture providing mock Azure provider configuration."""
    return AzureProviderConfig(**get_sample_azure_config())


@pytest.fixture
def mock_aws_config() -> AWSProviderConfig:
    """Fixture providing mock AWS provider configuration."""
    return AWSProviderConfig(**get_sample_aws_config())


@pytest.fixture
def mock_google_config() -> GoogleProviderConfig:
    """Fixture providing mock Google provider configuration."""
    return GoogleProviderConfig(**get_sample_google_config())


@pytest.fixture
def mock_huggingface_config() -> ProviderConfig:
    """Fixture providing mock Hugging Face provider configuration."""
    return ProviderConfig(**get_sample_huggingface_config())


# =============================================================================
# Test Profile Fixtures
# =============================================================================


@pytest.fixture
def sample_test_profile() -> TestProfile:
    """Fixture providing a sample test profile."""
    return TestProfile(**get_sample_test_profile_standard())


@pytest.fixture
def sample_minimal_profile() -> TestProfile:
    """Fixture providing a minimal test profile."""
    return TestProfile(
        name="minimal",
        description="Minimal test profile",
        probes=["prompt_injection_basic"],
        detectors=["toxicity_basic"],
        compliance_tags=["article-15"],
        max_parallel=3,
        timeout=60,
    )


# =============================================================================
# Environment Fixtures
# =============================================================================


@pytest.fixture
def clean_environment() -> Generator[None, None, None]:
    """
    Fixture that provides a clean environment without API keys.

    Temporarily removes common API key environment variables
    to test behavior when credentials are missing.

    Yields:
        None
    """
    import os

    env_vars_to_remove = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "AZURE_OPENAI_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "HF_TOKEN",
    ]

    original_values = {}
    for var in env_vars_to_remove:
        if var in os.environ:
            original_values[var] = os.environ.pop(var)

    try:
        yield
    finally:
        os.environ.update(original_values)


@pytest.fixture
def mock_env_with_api_keys() -> Generator[None, None, None]:
    """
    Fixture that sets mock API keys in the environment.

    Yields:
        None
    """
    import os

    mock_keys = {
        "OPENAI_API_KEY": "sk-test-1234567890abcdef1234567890abcdef",
        "ANTHROPIC_API_KEY": "sk-ant-test-1234567890abcdef1234567890abcdef",
    }

    original_values = {}
    for key, value in mock_keys.items():
        if key in os.environ:
            original_values[key] = os.environ[key]
        os.environ[key] = value

    try:
        yield
    finally:
        for key in mock_keys:
            if key in original_values:
                os.environ[key] = original_values[key]
            elif key in os.environ:
                del os.environ[key]

"""
Unit tests for SCI configuration management.

Tests configuration loading, validation, and manipulation.
"""

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from sci.config.defaults import DEFAULT_CONFIG, get_default_config_yaml
from sci.config.manager import ConfigManager, ValidationResult
from sci.config.models import (
    LogFormat,
    LogLevel,
    LoggingConfig,
    OutputConfig,
    OutputFormat,
    ProviderConfig,
    SCIConfig,
    TestProfile,
)


class TestConfigManager:
    """Tests for ConfigManager class."""

    def test_init(self) -> None:
        """Test ConfigManager initialization."""
        manager = ConfigManager()
        assert manager.is_loaded is False
        assert manager.config_file is None

    def test_load_defaults(self) -> None:
        """Test loading with default configuration."""
        manager = ConfigManager()
        manager.load()
        assert manager.is_loaded is True

    def test_get_with_default(self) -> None:
        """Test getting value with default fallback."""
        manager = ConfigManager()
        manager.load()
        value = manager.get("nonexistent.key", "default_value")
        assert value == "default_value"

    def test_get_nested_value(self) -> None:
        """Test getting nested configuration value."""
        manager = ConfigManager()
        manager.load()
        log_level = manager.get("logging.level", "INFO")
        assert log_level is not None

    def test_set_value(self) -> None:
        """Test setting configuration value."""
        manager = ConfigManager()
        manager.load()
        manager.set("custom.key", "custom_value")
        assert manager.get("custom.key") == "custom_value"

    def test_to_dict(self) -> None:
        """Test exporting configuration as dictionary."""
        manager = ConfigManager()
        manager.load()
        config_dict = manager.to_dict()
        assert isinstance(config_dict, dict)

    def test_mask_secrets(self) -> None:
        """Test that secrets are masked."""
        manager = ConfigManager()
        manager.load()
        manager.set("providers.openai.api_key", "sk-secret-key-12345")
        masked = manager.mask_secrets()
        assert masked.get("providers", {}).get("openai", {}).get("api_key") == "***MASKED***"

    def test_load_yaml_file(self) -> None:
        """Test loading configuration from YAML file."""
        config_content = {
            "logging": {"level": "DEBUG"},
            "output": {"format": "yaml"},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(config_content, f)
            config_path = Path(f.name)

        try:
            manager = ConfigManager()
            manager.load(config_path)
            assert manager.is_loaded is True
            assert manager.config_file == config_path
        finally:
            config_path.unlink()

    def test_load_json_file(self) -> None:
        """Test loading configuration from JSON file."""
        config_content = {
            "logging": {"level": "WARNING"},
            "output": {"format": "json"},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(config_content, f)
            config_path = Path(f.name)

        try:
            manager = ConfigManager()
            manager.load(config_path)
            assert manager.is_loaded is True
        finally:
            config_path.unlink()

    def test_load_nonexistent_file(self) -> None:
        """Test loading from nonexistent file raises error."""
        manager = ConfigManager()
        with pytest.raises(FileNotFoundError):
            manager.load(Path("/nonexistent/config.yaml"))

    def test_validate_valid_config(self) -> None:
        """Test validation passes for valid configuration."""
        manager = ConfigManager()
        manager.load()
        result = manager.validate()
        assert isinstance(result, ValidationResult)
        assert result.is_valid is True

    def test_validate_invalid_log_level(self) -> None:
        """Test validation catches invalid log level."""
        manager = ConfigManager()
        manager.load()
        manager.set("logging.level", "INVALID_LEVEL")
        result = manager.validate()
        assert result.is_valid is False
        assert any("log level" in e.lower() for e in result.errors)


class TestConfigModels:
    """Tests for Pydantic configuration models."""

    def test_provider_config_defaults(self) -> None:
        """Test ProviderConfig default values."""
        config = ProviderConfig()
        assert config.timeout == 30
        assert config.max_retries == 3

    def test_provider_config_validation(self) -> None:
        """Test ProviderConfig validation."""
        config = ProviderConfig(
            api_key="sk-test-key",
            timeout=60,
            max_retries=5,
        )
        assert config.api_key == "sk-test-key"
        assert config.timeout == 60
        assert config.max_retries == 5

    def test_provider_config_empty_api_key(self) -> None:
        """Test empty API key is converted to None."""
        config = ProviderConfig(api_key="   ")
        assert config.api_key is None

    def test_logging_config_defaults(self) -> None:
        """Test LoggingConfig default values."""
        config = LoggingConfig()
        assert config.level == LogLevel.INFO
        assert config.format == LogFormat.CONSOLE
        assert config.output == "stdout"
        assert config.structured is True

    def test_output_config_defaults(self) -> None:
        """Test OutputConfig default values."""
        config = OutputConfig()
        assert config.directory == "./results"
        assert config.format == OutputFormat.JSON
        assert config.compression is False

    def test_test_profile_validation(self) -> None:
        """Test TestProfile validation."""
        profile = TestProfile(
            name="test_profile",
            description="A test profile",
            probes=["probe1", "probe2"],
            detectors=["detector1"],
        )
        assert profile.name == "test_profile"
        assert len(profile.probes) == 2
        assert len(profile.detectors) == 1
        assert profile.max_parallel == 5
        assert profile.timeout == 300

    def test_sci_config_full(self) -> None:
        """Test full SCIConfig model."""
        config = SCIConfig(
            logging=LoggingConfig(level=LogLevel.DEBUG),
            output=OutputConfig(format=OutputFormat.YAML),
        )
        assert config.logging.level == LogLevel.DEBUG
        assert config.output.format == OutputFormat.YAML


class TestDefaultConfig:
    """Tests for default configuration."""

    def test_default_config_structure(self) -> None:
        """Test DEFAULT_CONFIG has expected structure."""
        assert "logging" in DEFAULT_CONFIG
        assert "output" in DEFAULT_CONFIG
        assert "compliance" in DEFAULT_CONFIG
        assert "profiles" in DEFAULT_CONFIG
        assert "providers" in DEFAULT_CONFIG

    def test_default_profiles(self) -> None:
        """Test default profiles are defined."""
        profiles = DEFAULT_CONFIG.get("profiles", {})
        assert "minimal" in profiles
        assert "standard" in profiles
        assert "comprehensive" in profiles

    def test_get_default_config_yaml(self) -> None:
        """Test YAML default config generation."""
        yaml_content = get_default_config_yaml()
        assert isinstance(yaml_content, str)
        assert "logging:" in yaml_content
        assert "profiles:" in yaml_content

    def test_default_yaml_is_valid(self) -> None:
        """Test generated YAML is valid."""
        yaml_content = get_default_config_yaml()
        parsed = yaml.safe_load(yaml_content)
        assert isinstance(parsed, dict)
        assert "logging" in parsed


class TestConfigMerging:
    """Tests for configuration merging behavior."""

    def test_file_overrides_defaults(self) -> None:
        """Test that file values override defaults."""
        config_content = {
            "logging": {"level": "ERROR"},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(config_content, f)
            config_path = Path(f.name)

        try:
            manager = ConfigManager()
            manager.load(config_path)
            # File value should override default
            level = manager.get("logging.level")
            assert level == "ERROR"
        finally:
            config_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

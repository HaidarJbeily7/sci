"""
Configuration Manager for SCI.

This module provides the ConfigManager class for loading, validating,
and accessing configuration from multiple sources (YAML, JSON, environment variables).
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dynaconf import Dynaconf

from sci.config.defaults import DEFAULT_CONFIG
from sci.config.models import SCIConfig
from sci.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of configuration validation."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ConfigManager:
    """
    Configuration manager for SCI.

    Handles loading configuration from multiple sources with proper precedence:
    CLI args > Environment variables > Config file > Defaults

    Usage:
        manager = ConfigManager()
        manager.load(Path("settings.yaml"))
        value = manager.get("providers.openai.model")
    """

    def __init__(self) -> None:
        """Initialize the configuration manager."""
        self._settings: Optional[Dynaconf] = None
        self._config_file: Optional[Path] = None
        self._loaded = False

    def load(self, config_path: Optional[Path] = None) -> None:
        """
        Load configuration from file and environment.

        Args:
            config_path: Optional path to configuration file (YAML or JSON).
                        If not provided, searches for default config files.
        """
        settings_files: list[str] = []

        if config_path is not None:
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found: {config_path}")
            settings_files.append(str(config_path))
            self._config_file = config_path
            # Always include secrets files alongside the specified config
            settings_files.extend([".secrets.yaml", ".secrets.json"])
        else:
            # Default search paths
            settings_files = [
                "settings.yaml",
                "settings.json",
                "settings.toml",
                ".secrets.yaml",
                ".secrets.json",
            ]

        self._settings = Dynaconf(
            envvar_prefix="SCI",
            settings_files=settings_files,
            environments=False,
            load_dotenv=True,
            merge_enabled=True,
            default_settings_paths=[],
        )

        # Apply defaults for missing values
        self._apply_defaults()
        self._loaded = True

        logger.info(
            "configuration_loaded",
            config_file=str(self._config_file) if self._config_file else None,
            environment=self._settings.current_env,
        )

    def _apply_defaults(self) -> None:
        """Apply default values for missing configuration keys."""
        if self._settings is None:
            return

        def apply_nested(defaults: dict, prefix: str = "") -> None:
            for key, value in defaults.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    apply_nested(value, full_key)
                else:
                    if not self._settings.exists(full_key):
                        self._settings.set(full_key, value)

        apply_nested(DEFAULT_CONFIG)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.

        Args:
            key: Configuration key (supports dot notation, e.g., "providers.openai.model")
            default: Default value if key doesn't exist

        Returns:
            Configuration value or default
        """
        if not self._loaded:
            self.load()

        if self._settings is None:
            return default

        try:
            return self._settings.get(key, default)
        except Exception:
            return default

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.

        Args:
            key: Configuration key (supports dot notation)
            value: Value to set
        """
        if not self._loaded:
            self.load()

        if self._settings is not None:
            self._settings.set(key, value)

    def validate(self, strict: bool = False) -> ValidationResult:
        """
        Validate the current configuration against the schema.

        Args:
            strict: If True, treat warnings as errors

        Returns:
            ValidationResult with validation status and any errors/warnings
        """
        if not self._loaded:
            self.load()

        errors: list[str] = []
        warnings: list[str] = []

        try:
            # Convert to dict and validate with Pydantic
            config_dict = self.to_dict()
            SCIConfig.model_validate(config_dict)
        except Exception as e:
            errors.append(str(e))

        # Additional validation checks
        if self._settings is not None:
            # Check for common misconfigurations
            log_level = self.get("logging.level", "INFO")
            valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
            if log_level.upper() not in valid_levels:
                errors.append(
                    f"Invalid log level: {log_level}. Must be one of {valid_levels}"
                )

            # Check output format
            output_format = self.get("output.format", "json")
            valid_formats = ["json", "yaml", "html"]
            if output_format.lower() not in valid_formats:
                warnings.append(
                    f"Unusual output format: {output_format}. Standard formats are {valid_formats}"
                )

        is_valid = len(errors) == 0
        if strict:
            is_valid = is_valid and len(warnings) == 0

        return ValidationResult(is_valid=is_valid, errors=errors, warnings=warnings)

    def to_dict(self) -> dict:
        """
        Export the current configuration as a dictionary.

        Returns:
            Dictionary representation of the configuration
        """
        if not self._loaded:
            self.load()

        if self._settings is None:
            return DEFAULT_CONFIG.copy()

        return dict(self._settings.as_dict())

    def mask_secrets(self) -> dict:
        """
        Return configuration with sensitive values masked.

        Returns:
            Dictionary with secrets replaced by "***MASKED***"
        """
        config = self.to_dict()
        return self._mask_dict(config)

    def _mask_dict(self, d: dict, parent_key: str = "") -> dict:
        """Recursively mask sensitive values in a dictionary."""
        masked = {}
        sensitive_keys = {
            "api_key",
            "secret",
            "password",
            "token",
            "access_key",
            "secret_key",
            "access_key_id",
            "secret_access_key",
            "credentials",
        }

        for key, value in d.items():
            key_lower = key.lower()
            if isinstance(value, dict):
                masked[key] = self._mask_dict(value, key)
            elif any(sensitive in key_lower for sensitive in sensitive_keys):
                masked[key] = "***MASKED***"
            else:
                masked[key] = value

        return masked

    @property
    def config_file(self) -> Optional[Path]:
        """Return the path to the loaded configuration file."""
        return self._config_file

    @property
    def is_loaded(self) -> bool:
        """Return whether configuration has been loaded."""
        return self._loaded


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """
    Get the global configuration manager instance.

    Returns:
        ConfigManager instance (creates one if not exists)
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager

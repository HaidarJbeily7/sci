"""
Pydantic models for SCI configuration validation.

This module defines type-safe configuration models that ensure
configuration correctness at load time.
"""

from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LogLevel(str, Enum):
    """Valid log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(str, Enum):
    """Valid log output formats."""

    JSON = "json"
    CONSOLE = "console"


class OutputFormat(str, Enum):
    """Valid output formats for results."""

    JSON = "json"
    YAML = "yaml"
    HTML = "html"


class RiskLevel(str, Enum):
    """EU AI Act risk classification levels."""

    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class ProviderConfig(BaseModel):
    """Configuration for an LLM provider."""

    model_config = ConfigDict(extra="allow")

    api_key: Optional[str] = Field(
        default=None,
        description="API key for the provider",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Base URL for API requests",
    )
    timeout: Annotated[int, Field(ge=1, le=600)] = Field(
        default=30,
        description="Request timeout in seconds",
    )
    max_retries: Annotated[int, Field(ge=0, le=10)] = Field(
        default=3,
        description="Maximum number of retry attempts",
    )
    model: Optional[str] = Field(
        default=None,
        description="Default model to use",
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        """Validate API key format if provided."""
        if v is not None and v.strip() == "":
            return None
        return v


class AzureProviderConfig(ProviderConfig):
    """Configuration for Azure OpenAI provider."""

    endpoint: Optional[str] = Field(
        default=None,
        description="Azure OpenAI endpoint URL",
    )
    api_version: str = Field(
        default="2024-02-15-preview",
        description="Azure API version",
    )
    deployment_name: Optional[str] = Field(
        default=None,
        description="Azure deployment name",
    )


class AWSProviderConfig(ProviderConfig):
    """Configuration for AWS Bedrock provider."""

    access_key_id: Optional[str] = Field(
        default=None,
        description="AWS access key ID",
    )
    secret_access_key: Optional[str] = Field(
        default=None,
        description="AWS secret access key",
    )
    region: str = Field(
        default="us-east-1",
        description="AWS region",
    )


class GoogleProviderConfig(ProviderConfig):
    """Configuration for Google AI provider."""

    project_id: Optional[str] = Field(
        default=None,
        description="GCP project ID",
    )
    location: str = Field(
        default="us-central1",
        description="GCP location",
    )


class ProvidersConfig(BaseModel):
    """Configuration for all LLM providers."""

    model_config = ConfigDict(extra="allow")

    openai: Optional[ProviderConfig] = None
    anthropic: Optional[ProviderConfig] = None
    google: Optional[GoogleProviderConfig] = None
    azure: Optional[AzureProviderConfig] = None
    aws: Optional[AWSProviderConfig] = None
    huggingface: Optional[ProviderConfig] = None


class TestProfile(BaseModel):
    """Configuration for a test execution profile."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        description="Profile name",
    )
    description: str = Field(
        default="",
        description="Profile description",
    )
    probes: list[str] = Field(
        default_factory=list,
        description="List of probe names to execute",
    )
    detectors: list[str] = Field(
        default_factory=list,
        description="List of detector names to apply",
    )
    compliance_tags: list[str] = Field(
        default_factory=list,
        description="EU AI Act compliance tags",
    )
    max_parallel: Annotated[int, Field(ge=1, le=100)] = Field(
        default=5,
        description="Maximum parallel probe executions",
    )
    timeout: Annotated[int, Field(ge=1, le=3600)] = Field(
        default=300,
        description="Profile execution timeout in seconds",
    )


class LoggingConfig(BaseModel):
    """Configuration for logging."""

    model_config = ConfigDict(extra="forbid")

    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level",
    )
    format: LogFormat = Field(
        default=LogFormat.CONSOLE,
        description="Log output format",
    )
    output: str = Field(
        default="stdout",
        description="Log output destination (stdout, stderr, or file path)",
    )
    structured: bool = Field(
        default=True,
        description="Enable structured logging",
    )


class OutputConfig(BaseModel):
    """Configuration for output settings."""

    model_config = ConfigDict(extra="forbid")

    directory: str = Field(
        default="./results",
        description="Output directory for results",
    )
    format: OutputFormat = Field(
        default=OutputFormat.JSON,
        description="Default output format",
    )
    compression: bool = Field(
        default=False,
        description="Enable output compression",
    )
    include_timestamps: bool = Field(
        default=True,
        description="Include timestamps in output filenames",
    )


class ComplianceConfig(BaseModel):
    """Configuration for EU AI Act compliance settings."""

    model_config = ConfigDict(extra="forbid")

    articles: list[str] = Field(
        default_factory=list,
        description="EU AI Act articles to evaluate",
    )
    annexes: list[str] = Field(
        default_factory=list,
        description="EU AI Act annexes to include",
    )
    risk_threshold: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=0.7,
        description="Risk threshold for compliance (0.0-1.0)",
    )
    strict_mode: bool = Field(
        default=False,
        description="Enable strict compliance mode",
    )
    generate_evidence: bool = Field(
        default=True,
        description="Generate evidence documentation",
    )


class GarakConfig(BaseModel):
    """Configuration for garak framework integration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(
        default=True,
        description="Enable garak framework integration",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Base URL for garak API endpoint (if using hosted garak)",
    )
    timeout: Annotated[int, Field(ge=1, le=600)] = Field(
        default=60,
        description="Request timeout for garak operations in seconds",
    )
    max_retries: Annotated[int, Field(ge=0, le=10)] = Field(
        default=3,
        description="Maximum retry attempts for garak API calls",
    )
    parallelism: Annotated[int, Field(ge=1, le=100)] = Field(
        default=10,
        description="Number of parallel probe executions",
    )
    limit_samples: Optional[int] = Field(
        default=None,
        description="Limit number of samples per probe (None for unlimited)",
    )
    extended_detectors: bool = Field(
        default=True,
        description="Use extended detectors for more thorough testing",
    )
    probe_categories: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of SCI probe names to garak probe identifiers",
    )
    # Timeout configuration
    scan_timeout: Annotated[int, Field(ge=1, le=7200)] = Field(
        default=600,
        description="Overall scan timeout in seconds",
    )
    probe_timeout: Annotated[int, Field(ge=1, le=600)] = Field(
        default=120,
        description="Per-probe timeout in seconds",
    )
    connection_timeout: Annotated[int, Field(ge=1, le=300)] = Field(
        default=30,
        description="Connection validation timeout in seconds",
    )
    # Retry configuration
    retry_delay: Annotated[float, Field(ge=0.1, le=60.0)] = Field(
        default=1.0,
        description="Initial retry delay in seconds",
    )
    # Error handling configuration
    continue_on_error: bool = Field(
        default=False,
        description="Continue scan if individual probe fails",
    )


class SCIConfig(BaseModel):
    """Root configuration model for SCI."""

    model_config = ConfigDict(extra="allow")

    providers: Optional[ProvidersConfig] = Field(
        default=None,
        description="LLM provider configurations",
    )
    profiles: dict[str, TestProfile] = Field(
        default_factory=dict,
        description="Test execution profiles",
    )
    logging: LoggingConfig = Field(
        default_factory=LoggingConfig,
        description="Logging configuration",
    )
    output: OutputConfig = Field(
        default_factory=OutputConfig,
        description="Output configuration",
    )
    compliance: ComplianceConfig = Field(
        default_factory=ComplianceConfig,
        description="Compliance configuration",
    )
    garak: GarakConfig = Field(
        default_factory=GarakConfig,
        description="Garak framework configuration",
    )

"""
SCI Engine module for orchestrating security scans.

This module provides the GarakEngine class that coordinates the complete
scan lifecycle including profile loading, probe/detector mapping,
scan execution, result processing, and report generation.

Key components:
- GarakEngine: Main orchestration engine for security scans
- GarakResultProcessor: Transforms raw scan results into standardized format
- ResultStorageManager: Manages result persistence with multi-format support
- ScanReport: Comprehensive scan report model with security scoring

Exception hierarchy:
- GarakIntegrationError: Base exception for all garak-related errors
- GarakConfigurationError: Configuration validation failures
- GarakConnectionError: Network/connectivity issues
- GarakExecutionError: Scan execution failures
- GarakTimeoutError: Timeout-related errors
- GarakValidationError: Pre-execution validation failures
- GarakInstallationError: Garak installation/version issues
"""

from sci.engine.exceptions import (
    # Base exceptions
    GarakIntegrationError,
    GarakConfigurationError,
    GarakConnectionError,
    GarakExecutionError,
    GarakTimeoutError,
    GarakValidationError,
    GarakInstallationError,
    # Retry logic
    is_transient_error,
    retry_on_transient_error,
    # Timeout handling
    TimeoutHandler,
    with_timeout,
    # Validation utilities
    validate_api_key_format,
    validate_model_name,
    validate_endpoint_url,
    get_similar_names,
    get_probe_suggestions,
    get_detector_suggestions,
    # Checkpoint
    ScanCheckpoint,
)
from sci.engine.garak_engine import GarakEngine
from sci.engine.results import (
    # Exceptions
    ResultProcessingError,
    SerializationError,
    StorageError,
    # Enums
    Severity,
    ComplianceStatus,
    VulnerabilityCategory,
    # Models
    Evidence,
    VulnerabilityFinding,
    ProbeResult,
    SecurityScore,
    ArticleAssessment,
    ComplianceAssessment,
    VulnerabilitySummary,
    ReportMetadata,
    ScanReport,
    # Processor and Storage
    GarakResultProcessor,
    ResultStorageManager,
    # Serializers
    ResultSerializer,
    JSONResultSerializer,
    YAMLResultSerializer,
    HTMLResultSerializer,
    get_serializer,
)

__all__ = [
    # Engine
    "GarakEngine",
    # Garak Integration Exceptions
    "GarakIntegrationError",
    "GarakConfigurationError",
    "GarakConnectionError",
    "GarakExecutionError",
    "GarakTimeoutError",
    "GarakValidationError",
    "GarakInstallationError",
    # Retry and timeout utilities
    "is_transient_error",
    "retry_on_transient_error",
    "TimeoutHandler",
    "with_timeout",
    # Validation utilities
    "validate_api_key_format",
    "validate_model_name",
    "validate_endpoint_url",
    "get_similar_names",
    "get_probe_suggestions",
    "get_detector_suggestions",
    # Checkpoint
    "ScanCheckpoint",
    # Result Processing Exceptions
    "ResultProcessingError",
    "SerializationError",
    "StorageError",
    # Enums
    "Severity",
    "ComplianceStatus",
    "VulnerabilityCategory",
    # Models
    "Evidence",
    "VulnerabilityFinding",
    "ProbeResult",
    "SecurityScore",
    "ArticleAssessment",
    "ComplianceAssessment",
    "VulnerabilitySummary",
    "ReportMetadata",
    "ScanReport",
    # Processor and Storage
    "GarakResultProcessor",
    "ResultStorageManager",
    # Serializers
    "ResultSerializer",
    "JSONResultSerializer",
    "YAMLResultSerializer",
    "HTMLResultSerializer",
    "get_serializer",
]

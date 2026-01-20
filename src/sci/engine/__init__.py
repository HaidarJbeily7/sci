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
"""

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
    # Exceptions
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

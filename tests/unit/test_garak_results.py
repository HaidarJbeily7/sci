"""
Unit tests for garak result processing.

Tests the result processing pipeline including finding parsing,
security score calculation, compliance assessment, and report serialization.
"""

import gzip
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from sci.config.models import (
    GarakConfig,
    OutputConfig,
    OutputFormat,
    RiskLevel,
    SCIConfig,
)
from sci.engine.results import (
    ArticleAssessment,
    ComplianceAssessment,
    ComplianceStatus,
    Evidence,
    GarakResultProcessor,
    HTMLResultSerializer,
    JSONResultSerializer,
    ProbeResult,
    ResultProcessingError,
    ResultStorageManager,
    ScanReport,
    SecurityScore,
    SerializationError,
    Severity,
    StorageError,
    VulnerabilityCategory,
    VulnerabilityFinding,
    VulnerabilitySummary,
    YAMLResultSerializer,
    get_serializer,
)


class TestVulnerabilityFindingModel:
    """Tests for VulnerabilityFinding Pydantic model."""

    def test_create_basic_finding(self) -> None:
        """Test creating a basic vulnerability finding."""
        finding = VulnerabilityFinding(
            id="test-001",
            probe_name="promptinject.HumanJailbreaks",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.INJECTION,
            description="Test finding",
        )

        assert finding.id == "test-001"
        assert finding.severity == Severity.HIGH
        assert finding.category == VulnerabilityCategory.INJECTION
        assert finding.confidence == 0.5  # Default

    def test_finding_with_evidence(self) -> None:
        """Test creating finding with evidence."""
        evidence = Evidence(
            prompt="Test prompt",
            response="Test response",
            detector_outcomes={"toxicity": True, "leakage": False},
        )
        finding = VulnerabilityFinding(
            id="test-002",
            probe_name="dan.DAN",
            evidence=evidence,
        )

        assert finding.evidence.prompt == "Test prompt"
        assert finding.evidence.detector_outcomes["toxicity"] is True

    def test_finding_confidence_bounds(self) -> None:
        """Test that confidence is bounded 0-1."""
        finding = VulnerabilityFinding(
            id="test-003",
            probe_name="test",
            confidence=0.95,
        )
        assert 0.0 <= finding.confidence <= 1.0


class TestSecurityScoreModel:
    """Tests for SecurityScore Pydantic model."""

    def test_create_security_score(self) -> None:
        """Test creating a security score."""
        score = SecurityScore(
            overall_score=75.5,
            category_scores={"injection": 70.0, "jailbreak": 80.0},
            risk_level=RiskLevel.LIMITED,
            vulnerabilities_by_severity={
                "critical": 0,
                "high": 2,
                "medium": 5,
                "low": 10,
            },
            compliance_score=72.0,
        )

        assert score.overall_score == 75.5
        assert score.risk_level == RiskLevel.LIMITED
        assert score.vulnerabilities_by_severity["high"] == 2

    def test_score_bounds(self) -> None:
        """Test that scores are bounded 0-100."""
        score = SecurityScore(
            overall_score=85.0,
            compliance_score=90.0,
        )
        assert 0.0 <= score.overall_score <= 100.0
        assert 0.0 <= score.compliance_score <= 100.0


class TestGarakResultProcessor:
    """Tests for GarakResultProcessor class."""

    @pytest.fixture
    def processor(self) -> GarakResultProcessor:
        """Create a result processor with test configuration."""
        config = SCIConfig(garak=GarakConfig())
        return GarakResultProcessor(config)

    @pytest.fixture
    def sample_raw_result(self) -> dict[str, Any]:
        """Create sample raw scan result."""
        return {
            "scan_id": "test-scan-001",
            "status": "success",
            "start_time": "2024-01-15T10:00:00+00:00",
            "end_time": "2024-01-15T10:05:00+00:00",
            "duration_ms": 300000.0,
            "provider": "openai",
            "model": "gpt-4",
            "profile": "standard",
            "probes_executed": [
                "promptinject.HumanJailbreaks",
                "dan.DAN",
            ],
            "findings": [
                {
                    "probe": "promptinject.HumanJailbreaks",
                    "status": "fail",
                    "passed": False,
                    "prompt": "Test prompt",
                    "output": "Test output",
                    "confidence": 0.85,
                    "detectors": {"toxicity": False},
                },
                {
                    "probe": "dan.DAN",
                    "status": "pass",
                    "passed": True,
                    "confidence": 0.3,
                },
            ],
            "summary": {"total": 10, "passed": 7, "failed": 3},
            "compliance_tags": ["article-9", "article-15"],
        }

    def test_process_scan_result_basic(
        self, processor: GarakResultProcessor, sample_raw_result: dict
    ) -> None:
        """Test basic scan result processing."""
        report = processor.process_scan_result(sample_raw_result)

        assert isinstance(report, ScanReport)
        assert report.scan_id == "test-scan-001"
        assert report.status == "success"
        assert report.provider == "openai"
        assert report.model == "gpt-4"

    def test_process_scan_result_findings(
        self, processor: GarakResultProcessor, sample_raw_result: dict
    ) -> None:
        """Test that findings are parsed correctly."""
        report = processor.process_scan_result(sample_raw_result)

        assert len(report.findings) == 2
        assert report.findings[0].probe_name == "promptinject.HumanJailbreaks"
        assert report.findings[0].severity in Severity

    def test_process_scan_result_security_score(
        self, processor: GarakResultProcessor, sample_raw_result: dict
    ) -> None:
        """Test security score calculation."""
        report = processor.process_scan_result(sample_raw_result)

        assert report.security_score is not None
        assert 0.0 <= report.security_score.overall_score <= 100.0
        assert report.security_score.risk_level in RiskLevel

    def test_process_scan_result_compliance(
        self, processor: GarakResultProcessor, sample_raw_result: dict
    ) -> None:
        """Test compliance assessment generation."""
        report = processor.process_scan_result(sample_raw_result)

        assert report.compliance_assessment is not None
        assert report.compliance_assessment.overall_status in ComplianceStatus

    def test_process_scan_result_recommendations(
        self, processor: GarakResultProcessor, sample_raw_result: dict
    ) -> None:
        """Test recommendation generation."""
        report = processor.process_scan_result(sample_raw_result)

        assert report.recommendations is not None
        assert len(report.recommendations) > 0

    def test_process_scan_result_empty_findings(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test processing result with no findings."""
        raw_result = {
            "scan_id": "test-empty",
            "status": "success",
            "findings": [],
            "summary": {"total": 0, "passed": 0, "failed": 0},
        }

        report = processor.process_scan_result(raw_result)

        assert report.security_score.overall_score == 100.0  # No vulnerabilities
        assert report.security_score.risk_level == RiskLevel.MINIMAL


class TestFindingParsing:
    """Tests for finding parsing in GarakResultProcessor."""

    @pytest.fixture
    def processor(self) -> GarakResultProcessor:
        config = SCIConfig(garak=GarakConfig())
        return GarakResultProcessor(config)

    def test_categorize_finding_injection(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test categorizing injection findings."""
        category = processor._categorize_finding("promptinject.HumanJailbreaks")
        assert category == VulnerabilityCategory.INJECTION

    def test_categorize_finding_jailbreak(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test categorizing jailbreak findings."""
        category = processor._categorize_finding("dan.DAN")
        assert category == VulnerabilityCategory.JAILBREAK

    def test_categorize_finding_extraction(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test categorizing extraction findings."""
        category = processor._categorize_finding("leakreplay.LiteratureCloze")
        assert category == VulnerabilityCategory.EXTRACTION

    def test_categorize_finding_toxicity(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test categorizing toxicity findings."""
        category = processor._categorize_finding(
            "realtoxicityprompts.RTPSevere_Toxicity"
        )
        assert category == VulnerabilityCategory.TOXICITY

    def test_determine_severity_high_score(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test severity determination for high confidence."""
        raw = {"status": "fail", "passed": False, "confidence": 0.95}
        severity = processor._determine_severity(raw)
        assert severity in (Severity.CRITICAL, Severity.HIGH)

    def test_determine_severity_low_score(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test severity determination for low confidence."""
        raw = {"status": "pass", "passed": True, "confidence": 0.2}
        severity = processor._determine_severity(raw)
        assert severity in (Severity.LOW, Severity.MEDIUM)


class TestSecurityScoreCalculation:
    """Tests for security score calculation."""

    @pytest.fixture
    def processor(self) -> GarakResultProcessor:
        config = SCIConfig(garak=GarakConfig())
        return GarakResultProcessor(config)

    def test_calculate_risk_level_unacceptable(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test risk level for very low scores."""
        risk = processor._calculate_risk_level(35.0)
        assert risk == RiskLevel.UNACCEPTABLE

    def test_calculate_risk_level_high(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test risk level for moderate scores."""
        risk = processor._calculate_risk_level(50.0)
        assert risk == RiskLevel.HIGH

    def test_calculate_risk_level_limited(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test risk level for good scores."""
        risk = processor._calculate_risk_level(70.0)
        assert risk == RiskLevel.LIMITED

    def test_calculate_risk_level_minimal(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test risk level for excellent scores."""
        risk = processor._calculate_risk_level(85.0)
        assert risk == RiskLevel.MINIMAL


class TestJSONResultSerializer:
    """Tests for JSON serialization."""

    @pytest.fixture
    def serializer(self) -> JSONResultSerializer:
        return JSONResultSerializer()

    @pytest.fixture
    def sample_report(self) -> ScanReport:
        return ScanReport(
            scan_id="test-json-001",
            status="success",
            provider="openai",
            model="gpt-4",
        )

    def test_serialize_creates_file(
        self, serializer: JSONResultSerializer, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        """Test that serialization creates output file."""
        output_path = tmp_path / "report.json"
        result_path = serializer.serialize(sample_report, output_path)

        assert result_path.exists()
        assert result_path.suffix == ".json"

    def test_serialize_valid_json(
        self, serializer: JSONResultSerializer, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        """Test that output is valid JSON."""
        output_path = tmp_path / "report.json"
        serializer.serialize(sample_report, output_path)

        with open(output_path) as f:
            data = json.load(f)

        assert data["scan_id"] == "test-json-001"
        assert "_serialization" in data

    def test_serializer_format_name(
        self, serializer: JSONResultSerializer
    ) -> None:
        """Test serializer format name property."""
        assert serializer.format_name == "json"
        assert serializer.file_extension == ".json"


class TestYAMLResultSerializer:
    """Tests for YAML serialization."""

    @pytest.fixture
    def serializer(self) -> YAMLResultSerializer:
        return YAMLResultSerializer()

    @pytest.fixture
    def sample_report(self) -> ScanReport:
        return ScanReport(
            scan_id="test-yaml-001",
            status="success",
        )

    def test_serialize_creates_file(
        self, serializer: YAMLResultSerializer, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        """Test that YAML serialization creates output file."""
        output_path = tmp_path / "report.yaml"
        result_path = serializer.serialize(sample_report, output_path)

        assert result_path.exists()
        assert result_path.suffix == ".yaml"

    def test_serializer_format_name(
        self, serializer: YAMLResultSerializer
    ) -> None:
        """Test serializer format name property."""
        assert serializer.format_name == "yaml"
        assert serializer.file_extension == ".yaml"


class TestHTMLResultSerializer:
    """Tests for HTML serialization."""

    @pytest.fixture
    def serializer(self) -> HTMLResultSerializer:
        return HTMLResultSerializer()

    @pytest.fixture
    def sample_report(self) -> ScanReport:
        return ScanReport(
            scan_id="test-html-001",
            status="success",
            provider="openai",
            model="gpt-4",
            profile="standard",
            security_score=SecurityScore(
                overall_score=75.0,
                risk_level=RiskLevel.LIMITED,
            ),
        )

    def test_serialize_creates_file(
        self, serializer: HTMLResultSerializer, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        """Test that HTML serialization creates output file."""
        output_path = tmp_path / "report.html"
        result_path = serializer.serialize(sample_report, output_path)

        assert result_path.exists()
        assert result_path.suffix == ".html"

    def test_serialize_valid_html(
        self, serializer: HTMLResultSerializer, sample_report: ScanReport, tmp_path: Path
    ) -> None:
        """Test that output contains HTML structure."""
        output_path = tmp_path / "report.html"
        serializer.serialize(sample_report, output_path)

        content = output_path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "test-html-001" in content
        assert "openai" in content

    def test_serializer_format_name(
        self, serializer: HTMLResultSerializer
    ) -> None:
        """Test serializer format name property."""
        assert serializer.format_name == "html"
        assert serializer.file_extension == ".html"

    def test_html_escapes_special_chars(
        self, serializer: HTMLResultSerializer
    ) -> None:
        """Test that HTML special characters are escaped."""
        escaped = serializer._escape_html("<script>alert('xss')</script>")
        assert "<" not in escaped
        assert ">" not in escaped
        assert "&lt;" in escaped


class TestGetSerializer:
    """Tests for get_serializer factory function."""

    def test_get_json_serializer(self) -> None:
        """Test getting JSON serializer."""
        serializer = get_serializer(OutputFormat.JSON)
        assert isinstance(serializer, JSONResultSerializer)

    def test_get_yaml_serializer(self) -> None:
        """Test getting YAML serializer."""
        serializer = get_serializer(OutputFormat.YAML)
        assert isinstance(serializer, YAMLResultSerializer)

    def test_get_html_serializer(self) -> None:
        """Test getting HTML serializer."""
        serializer = get_serializer(OutputFormat.HTML)
        assert isinstance(serializer, HTMLResultSerializer)


class TestResultStorageManager:
    """Tests for ResultStorageManager class."""

    @pytest.fixture
    def storage_manager(self, tmp_path: Path) -> ResultStorageManager:
        """Create a storage manager with temp directory."""
        config = OutputConfig(
            directory=str(tmp_path / "results"),
            format="json",
            compression=False,
            include_timestamps=True,
        )
        return ResultStorageManager(config)

    @pytest.fixture
    def sample_report(self) -> ScanReport:
        return ScanReport(
            scan_id="storage-test-001",
            status="success",
        )

    def test_save_report_creates_directory(
        self, storage_manager: ResultStorageManager, sample_report: ScanReport
    ) -> None:
        """Test that save_report creates output directory."""
        path = storage_manager.save_report(sample_report, "test-001")

        assert path.parent.exists()

    def test_save_report_json_format(
        self, storage_manager: ResultStorageManager, sample_report: ScanReport
    ) -> None:
        """Test saving report in JSON format."""
        path = storage_manager.save_report(
            sample_report, "test-001", format_override=OutputFormat.JSON
        )

        assert path.suffix == ".json"
        assert path.exists()

    def test_save_report_with_compression(self, tmp_path: Path) -> None:
        """Test saving report with compression enabled."""
        config = OutputConfig(
            directory=str(tmp_path / "compressed"),
            format="json",
            compression=True,
        )
        manager = ResultStorageManager(config)
        report = ScanReport(scan_id="compress-test")

        path = manager.save_report(report, "test-compress")

        assert path.suffix == ".gz"
        # Verify it's valid gzip
        with gzip.open(path, "rt") as f:
            data = json.load(f)
        assert data["scan_id"] == "compress-test"

    def test_save_raw_garak_report(
        self, storage_manager: ResultStorageManager, tmp_path: Path
    ) -> None:
        """Test copying raw garak report."""
        # Create a mock garak report
        raw_report = tmp_path / "garak_report.jsonl"
        raw_report.write_text('{"result": "test"}\n')

        path = storage_manager.save_raw_garak_report(raw_report, "test-001")

        assert path is not None
        assert path.exists()
        assert "garak_raw" in path.name

    def test_save_raw_garak_report_missing_file(
        self, storage_manager: ResultStorageManager
    ) -> None:
        """Test handling missing raw report file."""
        path = storage_manager.save_raw_garak_report(
            Path("/nonexistent/report.jsonl"), "test-001"
        )

        assert path is None

    def test_list_reports(
        self, storage_manager: ResultStorageManager, sample_report: ScanReport
    ) -> None:
        """Test listing stored reports."""
        # Save some reports
        storage_manager.save_report(sample_report, "report-1")
        storage_manager.save_report(sample_report, "report-2")

        reports = storage_manager.list_reports()

        assert len(reports) == 2

    def test_filename_includes_timestamp(
        self, storage_manager: ResultStorageManager, sample_report: ScanReport
    ) -> None:
        """Test that filename includes timestamp when configured."""
        path = storage_manager.save_report(sample_report, "test-001")

        # Should have format: scan_test-001_YYYYMMDD_HHMMSS.json
        assert "_" in path.stem
        parts = path.stem.split("_")
        assert len(parts) >= 3


class TestResultProcessingExceptions:
    """Tests for result processing exceptions."""

    def test_result_processing_error(self) -> None:
        """Test ResultProcessingError exception."""
        error = ResultProcessingError(
            "Processing failed",
            context={"scan_id": "test-001"},
        )

        assert "Processing failed" in str(error)
        assert error.context["scan_id"] == "test-001"

    def test_serialization_error(self) -> None:
        """Test SerializationError exception."""
        cause = ValueError("Invalid data")
        error = SerializationError(
            "Serialization failed",
            format_type="json",
            cause=cause,
        )

        assert "Serialization failed" in str(error)
        assert error.format_type == "json"
        assert error.cause == cause

    def test_storage_error(self) -> None:
        """Test StorageError exception."""
        error = StorageError(
            "Failed to write",
            path=Path("/test/path"),
            operation="write",
        )

        assert "Failed to write" in str(error)
        assert error.path == Path("/test/path")
        assert error.operation == "write"


class TestComplianceAssessment:
    """Tests for compliance assessment generation."""

    @pytest.fixture
    def processor(self) -> GarakResultProcessor:
        config = SCIConfig(garak=GarakConfig())
        return GarakResultProcessor(config)

    def test_generate_compliance_assessment_compliant(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test assessment with compliant results."""
        findings: list[VulnerabilityFinding] = []  # No findings = compliant

        assessment = processor._generate_compliance_assessment(
            findings, ["article-9", "article-15"]
        )

        assert assessment.overall_status == ComplianceStatus.COMPLIANT

    def test_generate_compliance_assessment_non_compliant(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test assessment with critical findings."""
        findings = [
            VulnerabilityFinding(
                id="critical-001",
                probe_name="test",
                severity=Severity.CRITICAL,
                compliance_articles=["article-15"],
            )
        ]

        assessment = processor._generate_compliance_assessment(
            findings, ["article-15"]
        )

        assert assessment.overall_status == ComplianceStatus.NON_COMPLIANT
        assert "article-15" in assessment.high_risk_areas

    def test_article_assessment_status(
        self, processor: GarakResultProcessor
    ) -> None:
        """Test individual article assessment status."""
        findings = [
            VulnerabilityFinding(
                id="high-001",
                probe_name="test",
                severity=Severity.HIGH,
                compliance_articles=["article-9"],
            )
        ]

        assessment = processor._assess_article_compliance("article-9", findings)

        assert assessment.status == ComplianceStatus.PARTIAL
        assert assessment.findings_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

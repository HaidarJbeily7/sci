"""
Unit tests for garak probe and detector mappings.

Tests the mapping system that translates SCI probe/detector names
to garak identifiers and provides EU AI Act compliance mapping.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sci.config.models import GarakConfig, RiskLevel
from sci.garak.mappings import (
    ComplianceMapper,
    DetectorMapper,
    ProbeMapper,
    DETECTOR_TYPE_MAPPING,
    EU_AI_ACT_MAPPING,
    PROBE_MODULE_MAPPING,
    get_all_compliance_articles,
    get_detector_description,
    get_probe_description,
    get_probes_for_article,
    get_sci_detector_name,
    get_sci_probe_name,
    list_available_probes,
)


class TestProbeMapper:
    """Tests for ProbeMapper class."""

    @pytest.fixture
    def mapper(self) -> ProbeMapper:
        """Create a probe mapper with test configuration."""
        config = GarakConfig(
            probe_categories={
                "prompt_injection_basic": "promptinject",
                "prompt_injection_advanced": "promptinject",
                "jailbreak_basic": "dan",
                "jailbreak_encoding": "encoding",
                "extraction_system_prompt": "leakreplay",
                "manipulation_output": "malwaregen",
            }
        )
        return ProbeMapper(config)

    def test_map_probe_name_basic(self, mapper: ProbeMapper) -> None:
        """Test mapping a basic probe name."""
        probes = mapper.map_probe_name("prompt_injection_basic")

        assert len(probes) > 0
        assert all("promptinject" in p for p in probes)

    def test_map_probe_name_jailbreak(self, mapper: ProbeMapper) -> None:
        """Test mapping jailbreak probe name."""
        probes = mapper.map_probe_name("jailbreak_basic")

        assert len(probes) > 0
        assert all("dan" in p.lower() for p in probes)

    def test_map_probe_name_encoding(self, mapper: ProbeMapper) -> None:
        """Test mapping encoding jailbreak probe."""
        probes = mapper.map_probe_name("jailbreak_encoding")

        assert len(probes) > 0
        assert all("encoding" in p.lower() for p in probes)

    def test_map_probe_name_unknown_raises(self, mapper: ProbeMapper) -> None:
        """Test that unknown probe name raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            mapper.map_probe_name("unknown_probe_name")

        assert "unknown_probe_name" in str(exc_info.value).lower()

    def test_map_probe_name_suggestions(self, mapper: ProbeMapper) -> None:
        """Test that error includes suggestions for similar probes."""
        with pytest.raises(ValueError) as exc_info:
            mapper.map_probe_name("prompt_injection_basik")  # Typo

        error_msg = str(exc_info.value)
        assert "did you mean" in error_msg.lower() or "available" in error_msg.lower()

    def test_map_probe_name_caching(self, mapper: ProbeMapper) -> None:
        """Test that probe mappings are cached."""
        probes1 = mapper.map_probe_name("prompt_injection_basic")
        probes2 = mapper.map_probe_name("prompt_injection_basic")

        assert probes1 == probes2
        assert "prompt_injection_basic" in mapper._probe_cache

    def test_map_probe_list(self, mapper: ProbeMapper) -> None:
        """Test mapping multiple probe names."""
        probes = mapper.map_probe_list([
            "prompt_injection_basic",
            "jailbreak_basic",
        ])

        assert len(probes) > 0
        # Should include probes from both categories
        has_promptinject = any("promptinject" in p for p in probes)
        has_dan = any("dan" in p.lower() for p in probes)
        assert has_promptinject and has_dan

    def test_map_probe_list_skips_invalid(self, mapper: ProbeMapper) -> None:
        """Test that invalid probes are skipped in list mapping."""
        probes = mapper.map_probe_list([
            "prompt_injection_basic",
            "invalid_probe",
            "jailbreak_basic",
        ])

        # Should still return results for valid probes
        assert len(probes) > 0

    def test_map_probe_list_empty(self, mapper: ProbeMapper) -> None:
        """Test mapping empty probe list."""
        probes = mapper.map_probe_list([])
        assert probes == []

    def test_map_probe_list_deduplication(self, mapper: ProbeMapper) -> None:
        """Test that duplicate probes are removed."""
        probes = mapper.map_probe_list([
            "prompt_injection_basic",
            "prompt_injection_advanced",  # Same module
        ])

        # Should be unique
        assert len(probes) == len(set(probes))

    def test_find_module_by_prefix(self, mapper: ProbeMapper) -> None:
        """Test prefix-based module lookup."""
        # Test with a probe not in config but matching prefix
        module = mapper._find_module_by_prefix("prompt_injection_custom")
        assert module == "promptinject"

    def test_get_similar_probe_names(self, mapper: ProbeMapper) -> None:
        """Test getting similar probe names for suggestions."""
        suggestions = mapper._get_similar_probe_names("prompt_injection_basik")
        assert len(suggestions) > 0
        assert "prompt_injection_basic" in suggestions


class TestDetectorMapper:
    """Tests for DetectorMapper class."""

    @pytest.fixture
    def mapper(self) -> DetectorMapper:
        """Create a detector mapper with default configuration."""
        return DetectorMapper(GarakConfig())

    def test_map_detector_name_toxicity_basic(
        self, mapper: DetectorMapper
    ) -> None:
        """Test mapping toxicity_basic detector."""
        detectors = mapper.map_detector_name("toxicity_basic")

        assert len(detectors) > 0
        assert any("toxicity" in d.lower() for d in detectors)

    def test_map_detector_name_toxicity_advanced(
        self, mapper: DetectorMapper
    ) -> None:
        """Test mapping toxicity_advanced detector."""
        detectors = mapper.map_detector_name("toxicity_advanced")

        assert len(detectors) > 1  # Advanced includes multiple detectors

    def test_map_detector_name_leakage(self, mapper: DetectorMapper) -> None:
        """Test mapping leakage detector."""
        detectors = mapper.map_detector_name("leakage_basic")

        assert len(detectors) > 0
        assert any("leakage" in d.lower() for d in detectors)

    def test_map_detector_name_bias(self, mapper: DetectorMapper) -> None:
        """Test mapping bias detector."""
        detectors = mapper.map_detector_name("bias_detection")

        assert len(detectors) > 0
        assert any("bias" in d.lower() for d in detectors)

    def test_map_detector_name_unknown_raises(
        self, mapper: DetectorMapper
    ) -> None:
        """Test that unknown detector name raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            mapper.map_detector_name("unknown_detector")

        assert "unknown_detector" in str(exc_info.value).lower()

    def test_map_detector_list(self, mapper: DetectorMapper) -> None:
        """Test mapping multiple detector names."""
        detectors = mapper.map_detector_list([
            "toxicity_basic",
            "leakage_basic",
        ])

        assert len(detectors) > 0
        # Should be unique
        assert len(detectors) == len(set(detectors))

    def test_map_detector_list_skips_invalid(
        self, mapper: DetectorMapper
    ) -> None:
        """Test that invalid detectors are skipped."""
        detectors = mapper.map_detector_list([
            "toxicity_basic",
            "invalid_detector",
        ])

        assert len(detectors) > 0

    def test_get_detector_config(self, mapper: DetectorMapper) -> None:
        """Test getting full detector configuration."""
        config = mapper.get_detector_config("toxicity_basic")

        assert "detectors" in config
        assert "level" in config
        assert "threshold" in config
        assert config["level"] == "basic"

    def test_get_detector_config_advanced(self, mapper: DetectorMapper) -> None:
        """Test getting advanced detector configuration."""
        config = mapper.get_detector_config("toxicity_advanced")

        assert config["level"] == "advanced"
        assert config["threshold"] < 0.5  # Lower threshold = more sensitive

    def test_get_detector_config_unknown(self, mapper: DetectorMapper) -> None:
        """Test getting config for unknown detector."""
        config = mapper.get_detector_config("unknown_detector")

        assert config["detectors"] == []
        assert config["level"] == "unknown"


class TestComplianceMapper:
    """Tests for ComplianceMapper class."""

    @pytest.fixture
    def mapper(self) -> ComplianceMapper:
        """Create a compliance mapper."""
        return ComplianceMapper()

    def test_get_articles_for_probe_injection(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting articles for prompt injection probe."""
        articles = mapper.get_articles_for_probe("prompt_injection_basic")

        assert len(articles) > 0
        assert "article-15" in articles  # Robustness
        assert "article-9" in articles  # Risk management

    def test_get_articles_for_probe_jailbreak(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting articles for jailbreak probe."""
        articles = mapper.get_articles_for_probe("jailbreak_basic")

        assert len(articles) > 0
        assert "article-15" in articles

    def test_get_articles_for_probe_extraction(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting articles for extraction probe."""
        articles = mapper.get_articles_for_probe("extraction_system_prompt")

        assert len(articles) > 0
        assert "article-10" in articles  # Data governance

    def test_get_articles_for_probe_transparency(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting articles for transparency probe."""
        articles = mapper.get_articles_for_probe("compliance_transparency")

        assert len(articles) > 0
        assert "article-13" in articles  # Transparency

    def test_get_articles_for_detector(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting articles for detector."""
        articles = mapper.get_articles_for_detector("toxicity_basic")

        assert len(articles) > 0
        assert "article-9" in articles

    def test_get_compliance_tags(self, mapper: ComplianceMapper) -> None:
        """Test aggregating compliance tags from probes and detectors."""
        tags = mapper.get_compliance_tags(
            probes=["prompt_injection_basic", "extraction_system_prompt"],
            detectors=["toxicity_basic"],
        )

        assert len(tags) > 0
        # Should include articles from all categories
        assert "article-9" in tags
        assert "article-15" in tags
        # Tags should be sorted
        assert tags == sorted(tags, key=lambda x: (0 if x.startswith("article") else 1, x))

    def test_get_compliance_tags_deduplication(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test that compliance tags are deduplicated."""
        tags = mapper.get_compliance_tags(
            probes=["prompt_injection_basic", "jailbreak_basic"],  # Same articles
            detectors=[],
        )

        # Should be unique
        assert len(tags) == len(set(tags))

    def test_get_risk_category(self, mapper: ComplianceMapper) -> None:
        """Test getting risk category for probe."""
        risk = mapper.get_risk_category("prompt_injection_basic")
        assert risk == RiskLevel.HIGH

        risk = mapper.get_risk_category("compliance_transparency")
        assert risk == RiskLevel.LIMITED

    def test_get_compliance_description(
        self, mapper: ComplianceMapper
    ) -> None:
        """Test getting compliance description."""
        desc = mapper.get_compliance_description("prompt_injection")
        assert "robustness" in desc.lower() or "adversarial" in desc.lower()

    def test_extract_category(self, mapper: ComplianceMapper) -> None:
        """Test category extraction from probe/detector names."""
        assert mapper._extract_category("prompt_injection_basic") == "prompt_injection"
        assert mapper._extract_category("toxicity_advanced") == "toxicity"
        assert mapper._extract_category("compliance_transparency") == "compliance_transparency"


class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_probe_description_promptinject(self) -> None:
        """Test getting probe description for promptinject module."""
        desc = get_probe_description("promptinject.HumanJailbreaks")

        assert len(desc) > 0
        assert "injection" in desc.lower() or "jailbreak" in desc.lower()
        assert "HumanJailbreaks" in desc

    def test_get_probe_description_dan(self) -> None:
        """Test getting probe description for dan module."""
        desc = get_probe_description("dan.DAN")

        assert len(desc) > 0
        assert "jailbreak" in desc.lower() or "dan" in desc.lower()

    def test_get_probe_description_unknown(self) -> None:
        """Test getting description for unknown probe."""
        desc = get_probe_description("unknown.Probe")

        assert len(desc) > 0
        assert "unknown" in desc.lower()

    def test_get_detector_description_toxicity(self) -> None:
        """Test getting detector description for toxicity."""
        desc = get_detector_description(
            "detectors.toxicity.ToxicCommentModel"
        )

        assert len(desc) > 0
        assert "toxic" in desc.lower()

    def test_get_detector_description_leakage(self) -> None:
        """Test getting detector description for leakage."""
        desc = get_detector_description(
            "detectors.leakage.TriggerListDetector"
        )

        assert len(desc) > 0
        assert "leak" in desc.lower()

    def test_list_available_probes(self) -> None:
        """Test listing available probes."""
        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = [
            "promptinject.HumanJailbreaks",
            "promptinject.AutoDAN",
            "dan.DAN",
            "encoding.InjectBase64",
        ]

        grouped = list_available_probes(mock_client)

        assert "promptinject" in grouped
        assert "dan" in grouped
        assert "encoding" in grouped
        assert len(grouped["promptinject"]) == 2

    def test_get_sci_probe_name(self) -> None:
        """Test reverse mapping from garak probe to SCI name."""
        config = GarakConfig(
            probe_categories={
                "prompt_injection_basic": "promptinject",
                "jailbreak_basic": "dan",
            }
        )

        sci_name = get_sci_probe_name(
            "promptinject.HumanJailbreaks", config
        )
        assert sci_name == "prompt_injection_basic"

        sci_name = get_sci_probe_name("dan.DAN", config)
        assert sci_name == "jailbreak_basic"

    def test_get_sci_probe_name_unknown(self) -> None:
        """Test reverse mapping for unknown probe."""
        config = GarakConfig()
        sci_name = get_sci_probe_name("unknown.Probe", config)
        assert sci_name is None

    def test_get_sci_detector_name(self) -> None:
        """Test reverse mapping from garak detector to SCI name."""
        sci_name = get_sci_detector_name(
            "detectors.toxicity.ToxicCommentModel"
        )
        assert sci_name == "toxicity_basic"

    def test_get_sci_detector_name_unknown(self) -> None:
        """Test reverse mapping for unknown detector."""
        sci_name = get_sci_detector_name("detectors.unknown.Detector")
        assert sci_name is None

    def test_get_all_compliance_articles(self) -> None:
        """Test getting all compliance articles."""
        articles = get_all_compliance_articles()

        assert len(articles) > 0
        # Should include key articles
        assert "article-9" in articles
        assert "article-10" in articles
        assert "article-15" in articles
        # Should be sorted
        assert articles[0].startswith("article-")

    def test_get_probes_for_article(self) -> None:
        """Test getting probes for an article."""
        probes = get_probes_for_article("article-15")

        assert len(probes) > 0
        assert "prompt_injection" in probes or "jailbreak" in probes


class TestMappingDataStructures:
    """Tests for mapping data structures."""

    def test_probe_module_mapping_completeness(self) -> None:
        """Test that PROBE_MODULE_MAPPING covers key categories."""
        required_keys = [
            "prompt_injection",
            "jailbreak",
            "extraction",
            "manipulation",
        ]

        for key in required_keys:
            assert key in PROBE_MODULE_MAPPING

    def test_detector_type_mapping_structure(self) -> None:
        """Test that DETECTOR_TYPE_MAPPING has correct structure."""
        for name, config in DETECTOR_TYPE_MAPPING.items():
            assert "detectors" in config
            assert "level" in config
            assert isinstance(config["detectors"], list)

    def test_eu_ai_act_mapping_structure(self) -> None:
        """Test that EU_AI_ACT_MAPPING has correct structure."""
        for category, mapping in EU_AI_ACT_MAPPING.items():
            assert "articles" in mapping
            assert "description" in mapping
            assert "risk_level" in mapping
            assert isinstance(mapping["articles"], list)
            assert isinstance(mapping["risk_level"], RiskLevel)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

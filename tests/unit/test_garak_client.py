"""
Unit tests for GarakClient.

Tests the garak client functionality including initialization,
scan execution, report parsing, and error handling.
"""

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sci.config.models import GarakConfig
from sci.engine.exceptions import (
    GarakConnectionError,
    GarakInstallationError,
)


class TestGarakClientInitialization:
    """Tests for GarakClient initialization."""

    def test_initialization_validates_installation(self) -> None:
        """Test that initialization validates garak installation."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"
        mock_config = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": mock_config,
                "garak._plugins": MagicMock(),
                "garak.command": MagicMock(),
                "garak.evaluators": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            config = GarakConfig()
            client = GarakClient(config)
            assert client is not None
            assert client.config == config

    def test_initialization_raises_on_missing_garak(self) -> None:
        """Test that initialization raises error when garak is not installed."""
        with patch.dict("sys.modules", {"garak": None}):
            with pytest.raises(GarakInstallationError) as exc_info:
                from sci.garak.client import GarakClient

                config = GarakConfig()
                with patch.object(
                    GarakClient,
                    "validate_installation",
                    side_effect=GarakInstallationError(
                        message="Garak is not installed",
                        required_version=">=0.13.3",
                    ),
                ):
                    GarakClient(config)

            assert "INSTALL" in str(exc_info.value.error_code)


class TestGarakClientRunScan:
    """Tests for GarakClient.run_scan() method."""

    @pytest.fixture
    def mock_client(self) -> Any:
        """Create a mock garak client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"
        mock_config = MagicMock()
        mock_config.loaded = False
        mock_config.transient = MagicMock()
        mock_config.system = MagicMock()
        mock_config.plugins = MagicMock()
        mock_config.reporting = MagicMock()
        mock_config.run = MagicMock()

        mock_plugins = MagicMock()
        mock_command = MagicMock()
        mock_evaluators = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": mock_config,
                "garak._plugins": mock_plugins,
                "garak.command": mock_command,
                "garak.evaluators": mock_evaluators,
                "garak.exception": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            config = GarakConfig(parallelism=5, timeout=60)
            client = GarakClient(config)
            return client

    def test_run_scan_success(
        self, mock_client: Any, tmp_path: Path
    ) -> None:
        """Test successful scan execution using Python API."""
        # Create mock report file with proper garak format (entry_type: attempt)
        report_file = tmp_path / "sci_scan_test123.jsonl"
        findings = [
            {"entry_type": "attempt", "probe_classname": "test.Probe", "passed": True, "status": "pass"}
        ]
        with open(report_file, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")

        # Mock the in-process execution
        mock_client._run_garak_in_process = MagicMock(
            return_value=str(report_file)
        )

        result = mock_client.run_scan(
            generator_type="openai.OpenAIGenerator",
            model_name="gpt-4",
            probes=["test.Probe"],
            env_vars={"OPENAI_API_KEY": "test-key"},
        )

        assert result["status"] == "success"
        assert result["generator_type"] == "openai.OpenAIGenerator"
        assert result["model_name"] == "gpt-4"
        assert "scan_id" in result
        assert "duration_ms" in result
        assert len(result["findings"]) == 1

    def test_run_scan_handles_errors(
        self, mock_client: Any
    ) -> None:
        """Test error handling during scan execution."""
        # Mock the in-process execution to raise an error
        mock_client._run_garak_in_process = MagicMock(
            side_effect=Exception("Test error")
        )

        result = mock_client.run_scan(
            generator_type="openai.OpenAIGenerator",
            model_name="gpt-4",
            probes=["test.Probe"],
            env_vars={"OPENAI_API_KEY": "test-key"},
        )

        assert result["status"] == "error"
        assert "error" in result
        assert result["error"]["type"] == "Exception"


class TestGarakClientReportParsing:
    """Tests for report parsing."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": MagicMock(),
                "garak._plugins": MagicMock(),
                "garak.command": MagicMock(),
                "garak.evaluators": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            return GarakClient(GarakConfig())

    def test_parse_report_jsonl(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test parsing JSONL report."""
        # Include entry_type: "attempt" as garak does in real reports
        findings = [
            {"entry_type": "attempt", "probe_classname": "test.Probe1", "passed": True},
            {"entry_type": "attempt", "probe_classname": "test.Probe2", "passed": False},
            {"entry_type": "attempt", "probe_classname": "test.Probe3", "passed": True},
        ]
        report_file = tmp_path / "report.jsonl"
        with open(report_file, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")

        result = client._parse_report(str(report_file))

        assert len(result) == 3
        assert result[0]["probe_classname"] == "test.Probe1"

    def test_parse_report_missing_file(
        self, client: Any
    ) -> None:
        """Test handling of missing report file."""
        result = client._parse_report(None)
        assert result == []

        result = client._parse_report("/nonexistent/file.jsonl")
        assert result == []

    def test_parse_report_handles_invalid_json(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test handling of invalid JSON in report."""
        report_file = tmp_path / "report.jsonl"
        report_file.write_text("not valid json {{{")

        result = client._parse_report(str(report_file))

        assert result == []


class TestGarakClientSummaryGeneration:
    """Tests for summary generation from findings."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": MagicMock(),
                "garak._plugins": MagicMock(),
                "garak.command": MagicMock(),
                "garak.evaluators": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            return GarakClient(GarakConfig())

    def test_generate_summary_empty_findings(self, client: Any) -> None:
        """Test summary generation with empty findings."""
        summary = client._generate_summary([])

        assert summary["total"] == 0
        assert summary["passed"] == 0
        assert summary["failed"] == 0
        assert summary["pass_rate"] == 0.0

    def test_generate_summary_all_passed(self, client: Any) -> None:
        """Test summary with all passed findings."""
        findings = [
            {"probe_classname": "test.Probe", "passed": True},
            {"probe_classname": "test.Probe", "passed": True},
            {"probe_classname": "test.Probe2", "passed": True},
        ]

        summary = client._generate_summary(findings)

        assert summary["total"] == 3
        assert summary["passed"] == 3
        assert summary["failed"] == 0
        assert summary["pass_rate"] == 100.0

    def test_generate_summary_mixed_results(self, client: Any) -> None:
        """Test summary with mixed pass/fail results."""
        findings = [
            {"probe_classname": "test.Probe1", "passed": True},
            {"probe_classname": "test.Probe1", "passed": False},
            {"probe_classname": "test.Probe2", "passed": True},
            {"probe_classname": "test.Probe2", "passed": False},
        ]

        summary = client._generate_summary(findings)

        assert summary["total"] == 4
        assert summary["passed"] == 2
        assert summary["failed"] == 2
        assert summary["pass_rate"] == 50.0

    def test_generate_summary_groups_by_probe(self, client: Any) -> None:
        """Test that summary groups results by probe."""
        findings = [
            {"probe_classname": "probe.A", "passed": True},
            {"probe_classname": "probe.A", "passed": False},
            {"probe_classname": "probe.B", "passed": True},
        ]

        summary = client._generate_summary(findings)

        assert "probes" in summary
        assert "probe.A" in summary["probes"]
        assert "probe.B" in summary["probes"]
        assert summary["probes"]["probe.A"]["passed"] == 1
        assert summary["probes"]["probe.A"]["failed"] == 1


class TestGarakClientProbeGeneratorListing:
    """Tests for probe and generator listing via Python API."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"
        mock_config = MagicMock()
        mock_config.loaded = False
        mock_plugins = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": mock_config,
                "garak._plugins": mock_plugins,
                "garak.command": MagicMock(),
                "garak.evaluators": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            client = GarakClient(GarakConfig())
            # Clear LRU cache
            client.list_available_probes.cache_clear()
            client.list_available_generators.cache_clear()
            return client

    def test_list_available_probes(
        self, client: Any
    ) -> None:
        """Test listing probes using Python API."""
        mock_plugins_list = [
            {"module_name": "promptinject.HumanJailbreaks"},
            {"module_name": "encoding.InjectBase64"},
            {"module_name": "dan.DAN"},
        ]

        with patch("garak._plugins.enumerate_plugins", return_value=mock_plugins_list):
            with patch("garak._config.loaded", False):
                with patch("garak._config.load_base_config"):
                    probes = client.list_available_probes()

        assert len(probes) == 3
        assert "promptinject.HumanJailbreaks" in probes

    def test_list_available_generators(
        self, client: Any
    ) -> None:
        """Test listing generators using Python API."""
        mock_generators_list = [
            {"module_name": "openai.OpenAIGenerator"},
            {"module_name": "anthropic.AnthropicGenerator"},
            {"module_name": "huggingface.InferenceAPI"},
        ]

        with patch("garak._plugins.enumerate_plugins", return_value=mock_generators_list):
            with patch("garak._config.loaded", False):
                with patch("garak._config.load_base_config"):
                    generators = client.list_available_generators()

        assert len(generators) == 3
        assert "openai.OpenAIGenerator" in generators


class TestGarakClientConnectionValidation:
    """Tests for connection validation via Python API."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "0.13.3"
        mock_config = MagicMock()
        mock_config.loaded = False
        mock_plugins = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "garak": mock_garak,
                "garak._config": mock_config,
                "garak._plugins": mock_plugins,
                "garak.command": MagicMock(),
                "garak.evaluators": MagicMock(),
            },
        ):
            from sci.garak.client import GarakClient

            return GarakClient(GarakConfig())

    def test_validate_connection_success(
        self, client: Any
    ) -> None:
        """Test successful connection validation via Python API."""
        mock_generator = MagicMock()

        with patch("garak._config.loaded", False):
            with patch("garak._config.load_base_config"):
                with patch("garak._plugins.load_plugin", return_value=mock_generator):
                    result = client.validate_connection(
                        "openai", {"OPENAI_API_KEY": "test-key"}
                    )

        assert result is True

    def test_validate_connection_failure(
        self, client: Any
    ) -> None:
        """Test connection validation failure via Python API."""
        with patch("garak._config.loaded", False):
            with patch("garak._config.load_base_config"):
                with patch("garak._plugins.load_plugin", return_value=None):
                    with pytest.raises(GarakConnectionError) as exc_info:
                        client.validate_connection(
                            "openai", {"OPENAI_API_KEY": "bad-key"}
                        )

        assert "CONN" in exc_info.value.error_code


class TestGarakClientScopedEnvVars:
    """Tests for scoped environment variable context manager."""

    def test_scoped_env_vars_sets_and_restores(self) -> None:
        """Test that scoped env vars are set and restored properly."""
        from sci.garak.client import _scoped_env_vars

        # Store original state
        original_value = os.environ.get("TEST_VAR")
        new_var_existed = "NEW_TEST_VAR" in os.environ

        try:
            # Set a test variable
            os.environ["TEST_VAR"] = "original"

            with _scoped_env_vars({"TEST_VAR": "modified", "NEW_TEST_VAR": "new"}):
                # Inside context, values should be modified
                assert os.environ["TEST_VAR"] == "modified"
                assert os.environ["NEW_TEST_VAR"] == "new"

            # After context, values should be restored
            assert os.environ["TEST_VAR"] == "original"
            assert "NEW_TEST_VAR" not in os.environ

        finally:
            # Clean up
            if original_value is None:
                os.environ.pop("TEST_VAR", None)
            else:
                os.environ["TEST_VAR"] = original_value

            if not new_var_existed:
                os.environ.pop("NEW_TEST_VAR", None)

    def test_scoped_env_vars_handles_exceptions(self) -> None:
        """Test that env vars are restored even on exception."""
        from sci.garak.client import _scoped_env_vars

        os.environ["TEST_VAR"] = "original"

        try:
            with _scoped_env_vars({"TEST_VAR": "modified"}):
                assert os.environ["TEST_VAR"] == "modified"
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Should still be restored
        assert os.environ["TEST_VAR"] == "original"

        # Clean up
        os.environ.pop("TEST_VAR", None)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

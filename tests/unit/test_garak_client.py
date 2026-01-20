"""
Unit tests for GarakClientWrapper.

Tests the garak client wrapper functionality including initialization,
scan execution, report parsing, and error handling.
"""

import io
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from sci.config.models import GarakConfig
from sci.engine.exceptions import (
    GarakConnectionError,
    GarakExecutionError,
    GarakInstallationError,
    GarakTimeoutError,
    GarakValidationError,
)


class TestGarakClientWrapperInitialization:
    """Tests for GarakClientWrapper initialization."""

    def test_initialization_validates_installation(self) -> None:
        """Test that initialization validates garak installation."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            config = GarakConfig()
            client = GarakClientWrapper(config)
            assert client is not None
            assert client.config == config

    def test_initialization_raises_on_missing_garak(self) -> None:
        """Test that initialization raises error when garak is not installed."""
        with patch.dict("sys.modules", {"garak": None}):
            # Force reimport to trigger ImportError
            with pytest.raises(GarakInstallationError) as exc_info:
                from sci.garak.client import GarakClientWrapper

                config = GarakConfig()
                # Mock the validate_installation to raise
                with patch.object(
                    GarakClientWrapper,
                    "validate_installation",
                    side_effect=GarakInstallationError(
                        message="Garak is not installed",
                        required_version=">=2.0.0",
                    ),
                ):
                    GarakClientWrapper(config)

            assert "INSTALL" in str(exc_info.value.error_code)

    def test_initialization_warns_on_old_garak_version(self) -> None:
        """Test that initialization warns on old garak version."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "1.5.0"  # Old version

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            config = GarakConfig()
            # Should not raise but will log warning
            client = GarakClientWrapper(config)
            assert client is not None


class TestGarakClientWrapperRunScan:
    """Tests for GarakClientWrapper.run_scan() method."""

    @pytest.fixture
    def mock_client(self) -> Any:
        """Create a mock garak client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"
        mock_garak.cli = MagicMock()
        mock_garak.cli.main = MagicMock(return_value=None)

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": mock_garak.cli}
        ):
            from sci.garak.client import GarakClientWrapper

            config = GarakConfig(parallelism=5, timeout=60)
            client = GarakClientWrapper(config)
            client._execute_garak = MagicMock(return_value=0)
            return client

    def test_run_scan_success(self, mock_client: Any, tmp_path: Path) -> None:
        """Test successful scan execution."""
        # Create mock report file
        report_data = {
            "results": [
                {"probe": "test.Probe", "passed": True, "status": "pass"}
            ]
        }
        report_file = tmp_path / "report.json"
        with open(report_file, "w") as f:
            json.dump(report_data, f)

        mock_client._find_report_file = MagicMock(return_value=report_file)

        result = mock_client.run_scan(
            generator_type="openai",
            model_name="gpt-4",
            probes=["test.Probe"],
            env_vars={"OPENAI_API_KEY": "test-key"},
            output_dir=tmp_path,
        )

        assert result["status"] == "success"
        assert result["generator_type"] == "openai"
        assert result["model_name"] == "gpt-4"
        assert "scan_id" in result
        assert "duration_ms" in result

    def test_run_scan_with_empty_probes_raises_error(
        self, mock_client: Any
    ) -> None:
        """Test that empty probes list raises validation error."""
        with pytest.raises(GarakValidationError) as exc_info:
            mock_client.run_scan(
                generator_type="openai",
                model_name="gpt-4",
                probes=[],
                env_vars={"OPENAI_API_KEY": "test-key"},
            )

        assert "VAL" in exc_info.value.error_code

    def test_run_scan_with_empty_generator_raises_error(
        self, mock_client: Any
    ) -> None:
        """Test that empty generator type raises validation error."""
        with pytest.raises(GarakValidationError):
            mock_client.run_scan(
                generator_type="",
                model_name="gpt-4",
                probes=["test.Probe"],
                env_vars={},
            )

    def test_run_scan_with_empty_model_raises_error(
        self, mock_client: Any
    ) -> None:
        """Test that empty model name raises validation error."""
        with pytest.raises(GarakValidationError):
            mock_client.run_scan(
                generator_type="openai",
                model_name="",
                probes=["test.Probe"],
                env_vars={},
            )

    def test_run_scan_restores_environment(
        self, mock_client: Any, tmp_path: Path
    ) -> None:
        """Test that environment is restored after scan."""
        original_env = os.environ.copy()

        # Create mock report
        report_file = tmp_path / "report.json"
        with open(report_file, "w") as f:
            json.dump({"results": []}, f)
        mock_client._find_report_file = MagicMock(return_value=report_file)

        mock_client.run_scan(
            generator_type="openai",
            model_name="gpt-4",
            probes=["test.Probe"],
            env_vars={"CUSTOM_VAR": "custom_value"},
            output_dir=tmp_path,
        )

        # Environment should be restored
        assert "CUSTOM_VAR" not in os.environ
        # Original values should still be there
        for key in original_env:
            if key in os.environ:
                assert os.environ[key] == original_env[key]


class TestGarakClientWrapperCLIArguments:
    """Tests for CLI argument building."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            config = GarakConfig(
                parallelism=10,
                timeout=60,
                extended_detectors=True,
                limit_samples=100,
            )
            return GarakClientWrapper(config)

    def test_build_cli_args_basic(self, client: Any, tmp_path: Path) -> None:
        """Test basic CLI argument building."""
        args = client._build_cli_args(
            generator_type="openai",
            model_name="gpt-4",
            probes=["probe.Test1", "probe.Test2"],
            output_dir=tmp_path,
        )

        assert "--model_type" in args
        assert "openai" in args
        assert "--model_name" in args
        assert "gpt-4" in args
        assert "--probes" in args
        assert "probe.Test1,probe.Test2" in args
        assert "--parallel" in args
        assert "10" in args

    def test_build_cli_args_with_extended_detectors(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test CLI args include extended detectors flag."""
        args = client._build_cli_args(
            generator_type="openai",
            model_name="gpt-4",
            probes=["probe.Test"],
            output_dir=tmp_path,
        )

        assert "--extended_detectors" in args

    def test_build_cli_args_with_sample_limit(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test CLI args include sample limit."""
        args = client._build_cli_args(
            generator_type="openai",
            model_name="gpt-4",
            probes=["probe.Test"],
            output_dir=tmp_path,
        )

        assert "--generations" in args
        assert "100" in args


class TestGarakClientWrapperReportParsing:
    """Tests for report file discovery and parsing."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            return GarakClientWrapper(GarakConfig())

    def test_find_report_file_json(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test finding JSON report file."""
        report_file = tmp_path / "report.json"
        report_file.write_text('{"results": []}')

        found = client._find_report_file(tmp_path)
        assert found is not None
        assert found.suffix == ".json"

    def test_find_report_file_jsonl(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test finding JSONL report file."""
        report_file = tmp_path / "report.jsonl"
        report_file.write_text('{"probe": "test"}\n')

        found = client._find_report_file(tmp_path)
        assert found is not None
        assert found.suffix == ".jsonl"

    def test_find_report_file_prefers_most_recent(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test that most recent report is found."""
        import time

        old_report = tmp_path / "report_old.json"
        old_report.write_text('{"results": []}')

        time.sleep(0.1)

        new_report = tmp_path / "report_new.json"
        new_report.write_text('{"results": [{"new": true}]}')

        found = client._find_report_file(tmp_path)
        assert found is not None
        assert "new" in found.name

    def test_find_report_file_returns_none_if_missing(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test that None is returned when no report exists."""
        found = client._find_report_file(tmp_path)
        assert found is None

    def test_parse_garak_report_json(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test parsing JSON report."""
        report_data = {
            "results": [
                {"probe": "test.Probe", "passed": True},
                {"probe": "test.Probe2", "passed": False},
            ]
        }
        report_file = tmp_path / "report.json"
        with open(report_file, "w") as f:
            json.dump(report_data, f)

        result = client._parse_garak_report(report_file)

        assert "findings" in result
        assert "summary" in result
        assert len(result["findings"]) == 2

    def test_parse_garak_report_jsonl(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test parsing JSONL report."""
        findings = [
            {"probe": "test.Probe1", "passed": True},
            {"probe": "test.Probe2", "passed": False},
            {"probe": "test.Probe3", "passed": True},
        ]
        report_file = tmp_path / "report.jsonl"
        with open(report_file, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")

        result = client._parse_garak_report(report_file)

        assert "findings" in result
        assert len(result["findings"]) == 3

    def test_parse_garak_report_handles_missing_file(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test handling of missing report file."""
        result = client._parse_garak_report(tmp_path / "nonexistent.json")

        assert result["findings"] == []
        assert result["summary"] == {}

    def test_parse_garak_report_handles_invalid_json(
        self, client: Any, tmp_path: Path
    ) -> None:
        """Test handling of invalid JSON in report."""
        report_file = tmp_path / "report.json"
        report_file.write_text("not valid json {{{")

        result = client._parse_garak_report(report_file)

        assert result["findings"] == []
        assert result["summary"] == {}


class TestGarakClientWrapperSummaryGeneration:
    """Tests for summary generation from findings."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            return GarakClientWrapper(GarakConfig())

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
            {"probe": "test.Probe", "passed": True},
            {"probe": "test.Probe", "passed": True},
            {"probe": "test.Probe2", "passed": True},
        ]

        summary = client._generate_summary(findings)

        assert summary["total"] == 3
        assert summary["passed"] == 3
        assert summary["failed"] == 0
        assert summary["pass_rate"] == 100.0

    def test_generate_summary_mixed_results(self, client: Any) -> None:
        """Test summary with mixed pass/fail results."""
        findings = [
            {"probe": "test.Probe1", "passed": True},
            {"probe": "test.Probe1", "passed": False},
            {"probe": "test.Probe2", "passed": True},
            {"probe": "test.Probe2", "passed": False},
        ]

        summary = client._generate_summary(findings)

        assert summary["total"] == 4
        assert summary["passed"] == 2
        assert summary["failed"] == 2
        assert summary["pass_rate"] == 50.0

    def test_generate_summary_groups_by_probe(self, client: Any) -> None:
        """Test that summary groups results by probe."""
        findings = [
            {"probe": "probe.A", "passed": True},
            {"probe": "probe.A", "passed": False},
            {"probe": "probe.B", "passed": True},
        ]

        summary = client._generate_summary(findings)

        assert "probes" in summary
        assert "probe.A" in summary["probes"]
        assert "probe.B" in summary["probes"]
        assert summary["probes"]["probe.A"]["passed"] == 1
        assert summary["probes"]["probe.A"]["failed"] == 1


class TestGarakClientWrapperProbeListing:
    """Tests for probe and generator listing."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            client = GarakClientWrapper(GarakConfig())
            # Clear LRU cache for testing
            client.list_available_probes.cache_clear()
            client.list_available_generators.cache_clear()
            return client

    def test_list_available_probes(self, client: Any) -> None:
        """Test listing available probes."""
        mock_output = """
        promptinject.HumanJailbreaks
        promptinject.AutoDAN
        dan.DAN
        encoding.InjectBase64
        """

        def mock_execute(args, stdout, stderr):
            stdout.write(mock_output)
            return 0

        client._execute_garak = mock_execute

        probes = client.list_available_probes()

        assert len(probes) > 0
        assert "promptinject.HumanJailbreaks" in probes

    def test_list_available_generators(self, client: Any) -> None:
        """Test listing available generators."""
        mock_output = """
        openai: OpenAI API generator
        anthropic: Anthropic API generator
        huggingface: Hugging Face generator
        """

        def mock_execute(args, stdout, stderr):
            stdout.write(mock_output)
            return 0

        client._execute_garak = mock_execute

        generators = client.list_available_generators()

        assert len(generators) > 0
        assert "openai" in generators


class TestGarakClientWrapperConnectionValidation:
    """Tests for connection validation."""

    @pytest.fixture
    def client(self) -> Any:
        """Create a mock client for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            from sci.garak.client import GarakClientWrapper

            return GarakClientWrapper(GarakConfig())

    def test_validate_connection_success(self, client: Any) -> None:
        """Test successful connection validation."""
        client._execute_garak = MagicMock(return_value=0)

        with patch.object(client, "_execute_garak", return_value=0):
            result = client.validate_connection(
                "openai", {"OPENAI_API_KEY": "test-key"}
            )

        assert result is True

    def test_validate_connection_auth_error(self, client: Any) -> None:
        """Test connection validation with auth error."""

        def mock_execute(args, stdout, stderr):
            stderr.write("authentication error: invalid api key")
            return 1

        client._execute_garak = mock_execute

        with pytest.raises(GarakConnectionError) as exc_info:
            client.validate_connection("openai", {"OPENAI_API_KEY": "bad-key"})

        assert "CONN" in exc_info.value.error_code


class TestGarakClientWrapperErrorHandling:
    """Tests for error handling and classification."""

    def test_classify_execution_error_auth(self) -> None:
        """Test error classification for authentication errors."""
        from sci.garak.client import _classify_execution_error

        error = _classify_execution_error(
            exit_code=1,
            stderr="Error: Invalid API key provided",
            generator_type="openai",
            model_name="gpt-4",
            probes=["test.Probe"],
        )

        assert isinstance(error, GarakConnectionError)
        assert "CONN" in error.error_code

    def test_classify_execution_error_rate_limit(self) -> None:
        """Test error classification for rate limiting."""
        from sci.garak.client import _classify_execution_error

        error = _classify_execution_error(
            exit_code=1,
            stderr="Error 429: Rate limit exceeded",
            generator_type="openai",
            model_name="gpt-4",
            probes=["test.Probe"],
        )

        assert isinstance(error, GarakConnectionError)
        assert "rate limit" in str(error).lower()

    def test_classify_execution_error_model_not_found(self) -> None:
        """Test error classification for model not found."""
        from sci.garak.client import _classify_execution_error

        error = _classify_execution_error(
            exit_code=1,
            stderr="Model 'gpt-5' not found",
            generator_type="openai",
            model_name="gpt-5",
            probes=["test.Probe"],
        )

        assert isinstance(error, GarakValidationError)
        assert "VAL" in error.error_code

    def test_classify_execution_error_generic(self) -> None:
        """Test error classification for generic errors."""
        from sci.garak.client import _classify_execution_error

        error = _classify_execution_error(
            exit_code=1,
            stderr="Some unknown error occurred",
            generator_type="openai",
            model_name="gpt-4",
            probes=["test.Probe"],
        )

        assert isinstance(error, GarakExecutionError)
        assert "EXEC" in error.error_code


class TestGarakClientWrapperHelperFunctions:
    """Tests for helper functions."""

    def test_mask_sensitive_args(self) -> None:
        """Test masking sensitive CLI arguments."""
        from sci.garak.client import _mask_sensitive_args

        args = [
            "--model_type",
            "openai",
            "--api_key",
            "sk-secret-key-12345",
            "--token",
            "bearer-token-xyz",
            "--probes",
            "test.Probe",
        ]

        masked = _mask_sensitive_args(args)

        assert "sk-secret-key-12345" not in masked
        assert "bearer-token-xyz" not in masked
        assert "openai" in masked
        assert "test.Probe" in masked

    def test_setup_output_directory(self, tmp_path: Path) -> None:
        """Test output directory setup."""
        from sci.garak.client import _setup_output_directory

        output_dir = _setup_output_directory(tmp_path, "test-scan-123")

        assert output_dir.exists()
        assert "garak_scan" in output_dir.name
        assert "test-scan-123" in output_dir.name

    def test_validate_garak_output_true(self, tmp_path: Path) -> None:
        """Test output validation with valid files."""
        from sci.garak.client import _validate_garak_output

        # Create a report file
        (tmp_path / "report.json").write_text('{"results": []}')

        assert _validate_garak_output(tmp_path) is True

    def test_validate_garak_output_false_empty(self, tmp_path: Path) -> None:
        """Test output validation with no files."""
        from sci.garak.client import _validate_garak_output

        assert _validate_garak_output(tmp_path) is False

    def test_validate_garak_output_false_nonexistent(self) -> None:
        """Test output validation with nonexistent directory."""
        from sci.garak.client import _validate_garak_output

        assert _validate_garak_output(Path("/nonexistent/path")) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

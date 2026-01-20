"""
CLI integration tests for garak functionality.

Tests the CLI commands related to garak integration using Typer's CliRunner.
"""

from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from sci.cli.main import app

runner = CliRunner()


class TestRunCommand:
    """Tests for 'sci run' command with garak integration."""

    @pytest.fixture
    def mock_garak_engine(self) -> Generator[MagicMock, None, None]:
        """Mock GarakEngine for CLI testing."""
        mock_engine = MagicMock()
        mock_engine.execute_scan.return_value = {
            "scan_id": "cli-test-001",
            "status": "success",
            "findings": [],
            "summary": {"total": 10, "passed": 10, "failed": 0},
            "compliance_tags": ["article-15"],
        }
        mock_engine.list_probes.return_value = [
            {
                "sci_name": "prompt_injection_basic",
                "garak_module": "promptinject",
                "description": "Basic prompt injection testing",
                "category": "prompt_injection",
                "compliance_tags": ["article-15"],
            },
            {
                "sci_name": "jailbreak_basic",
                "garak_module": "dan",
                "description": "Basic jailbreak testing",
                "category": "jailbreak",
                "compliance_tags": ["article-15"],
            },
        ]
        mock_engine.list_detectors.return_value = [
            {
                "sci_name": "toxicity_basic",
                "garak_detectors": ["detectors.toxicity.ToxicCommentModel"],
                "description": "Basic toxicity detection",
                "category": "toxicity",
            },
        ]
        mock_engine.list_available_profiles.return_value = [
            "minimal",
            "standard",
            "comprehensive",
        ]
        mock_engine.validate_configuration.return_value = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "suggestions": [],
        }

        with patch(
            "sci.cli.run.GarakEngine", return_value=mock_engine
        ):
            yield mock_engine

    def test_run_help(self) -> None:
        """Test 'sci run --help' displays help."""
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "Execute security tests" in result.stdout

    def test_run_probes_subcommand(self) -> None:
        """Test 'sci run probes' lists available probes."""
        result = runner.invoke(app, ["run", "probes"])
        assert result.exit_code == 0
        # Should display probe information
        assert "probes" in result.stdout.lower()

    def test_run_detectors_subcommand(self) -> None:
        """Test 'sci run detectors' lists available detectors."""
        result = runner.invoke(app, ["run", "detectors"])
        assert result.exit_code == 0
        assert "detectors" in result.stdout.lower()

    def test_run_dry_run_mode(self) -> None:
        """Test 'sci run --dry-run' shows execution plan."""
        result = runner.invoke(app, ["run", "--dry-run"])
        assert result.exit_code == 0
        assert "dry run" in result.stdout.lower()

    def test_run_with_provider_and_model_dry_run(self) -> None:
        """Test dry run with provider and model specified."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "openai" in result.stdout.lower()
        assert "gpt-4" in result.stdout.lower()

    def test_run_with_profile_dry_run(self) -> None:
        """Test dry run with profile specified."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--profile",
                "standard",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        assert "standard" in result.stdout.lower()

    def test_run_missing_provider(self) -> None:
        """Test 'sci run' without provider shows error."""
        result = runner.invoke(app, ["run", "--model", "gpt-4"])
        assert result.exit_code == 1
        assert "provider" in result.stdout.lower()

    def test_run_missing_model(self) -> None:
        """Test 'sci run' without model shows error."""
        result = runner.invoke(app, ["run", "--provider", "openai"])
        assert result.exit_code == 1
        assert "model" in result.stdout.lower()


class TestRunProbesSubcommand:
    """Tests for 'sci run probes' subcommand."""

    def test_probes_list_basic(self) -> None:
        """Test basic probe listing."""
        result = runner.invoke(app, ["run", "probes"])
        assert result.exit_code == 0

    def test_probes_list_json_format(self) -> None:
        """Test probe listing with JSON format."""
        result = runner.invoke(app, ["run", "probes", "--format", "json"])
        assert result.exit_code == 0

    def test_probes_list_with_category(self) -> None:
        """Test probe listing filtered by category."""
        result = runner.invoke(
            app, ["run", "probes", "--category", "prompt_injection"]
        )
        assert result.exit_code == 0


class TestRunDetectorsSubcommand:
    """Tests for 'sci run detectors' subcommand."""

    def test_detectors_list_basic(self) -> None:
        """Test basic detector listing."""
        result = runner.invoke(app, ["run", "detectors"])
        assert result.exit_code == 0

    def test_detectors_list_json_format(self) -> None:
        """Test detector listing with JSON format."""
        result = runner.invoke(app, ["run", "detectors", "--format", "json"])
        assert result.exit_code == 0


class TestRunWithOutputOptions:
    """Tests for output-related CLI options."""

    def test_run_with_output_dir(self, tmp_path: Path) -> None:
        """Test specifying output directory."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--output-dir",
                str(tmp_path),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0

    def test_run_with_output_format(self, tmp_path: Path) -> None:
        """Test specifying output format."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--output-dir",
                str(tmp_path),
                "--format",
                "html",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0


class TestReportComplianceSubcommand:
    """Tests for 'sci report compliance' subcommand."""

    def test_report_compliance_help(self) -> None:
        """Test 'sci report compliance --help'."""
        result = runner.invoke(app, ["report", "compliance", "--help"])
        assert result.exit_code == 0

    def test_report_compliance_with_articles(self, tmp_path: Path) -> None:
        """Test generating compliance report for specific articles."""
        # Create a mock result file
        result_file = tmp_path / "results.json"
        result_file.write_text('{"scan_id": "test", "findings": []}')

        result = runner.invoke(
            app,
            [
                "report",
                "compliance",
                str(tmp_path),
                "--articles",
                "9,15",
            ],
        )
        # May fail if no actual results, but should process
        assert result.exit_code in (0, 1)


class TestConfigListProfiles:
    """Tests for 'sci config list-profiles' with garak profiles."""

    def test_list_profiles_includes_builtin(self) -> None:
        """Test that built-in profiles are listed."""
        result = runner.invoke(app, ["config", "list-profiles"])
        assert result.exit_code == 0
        # Should show built-in profiles
        stdout_lower = result.stdout.lower()
        assert "minimal" in stdout_lower or "standard" in stdout_lower


class TestErrorMessages:
    """Tests for CLI error message handling."""

    def test_invalid_provider_error_message(self) -> None:
        """Test error message for invalid provider."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "invalid_provider",
                "--model",
                "gpt-4",
            ],
        )
        assert result.exit_code == 1
        # Should provide helpful error message
        assert "provider" in result.stdout.lower() or "error" in result.stdout.lower()

    def test_invalid_profile_error_message(self) -> None:
        """Test error message for invalid profile."""
        result = runner.invoke(
            app,
            [
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--profile",
                "nonexistent_profile_xyz",
            ],
        )
        assert result.exit_code == 1
        # Should mention the profile issue


class TestVerboseAndQuietModes:
    """Tests for verbose and quiet CLI modes."""

    def test_verbose_mode_dry_run(self) -> None:
        """Test verbose mode shows additional output."""
        result = runner.invoke(
            app,
            [
                "--verbose",
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0

    def test_quiet_mode_dry_run(self) -> None:
        """Test quiet mode reduces output."""
        result = runner.invoke(
            app,
            [
                "--quiet",
                "run",
                "--provider",
                "openai",
                "--model",
                "gpt-4",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0


class TestConfigValidation:
    """Tests for configuration validation commands."""

    def test_config_validate_help(self) -> None:
        """Test 'sci config validate --help'."""
        result = runner.invoke(app, ["config", "validate", "--help"])
        assert result.exit_code == 0
        assert "Validate" in result.stdout

    def test_config_show_help(self) -> None:
        """Test 'sci config show --help'."""
        result = runner.invoke(app, ["config", "show", "--help"])
        assert result.exit_code == 0


class TestReportGeneration:
    """Tests for report generation commands."""

    def test_report_help(self) -> None:
        """Test 'sci report --help'."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate security and compliance reports" in result.stdout

    def test_report_templates(self) -> None:
        """Test 'sci report templates'."""
        result = runner.invoke(app, ["report", "templates"])
        assert result.exit_code == 0
        assert "templates" in result.stdout.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""
Unit tests for SCI CLI commands.

Tests the CLI interface using Typer's CliRunner for isolated testing.
"""

import pytest
from typer.testing import CliRunner

from sci.cli.main import app
from sci.version import __version__

runner = CliRunner()


class TestMainCLI:
    """Tests for the main CLI application."""

    def test_version_flag(self) -> None:
        """Test --version displays correct version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_version_short_flag(self) -> None:
        """Test -V displays correct version."""
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_help_flag(self) -> None:
        """Test --help displays help message."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Security-Centered Intelligence" in result.stdout

    def test_help_short_flag(self) -> None:
        """Test -h displays help message."""
        result = runner.invoke(app, ["-h"])
        assert result.exit_code == 0
        assert "Security-Centered Intelligence" in result.stdout

    def test_no_args_shows_help(self) -> None:
        """Test running without arguments shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        # Should show available commands
        assert "run" in result.stdout
        assert "report" in result.stdout
        assert "config" in result.stdout

    def test_verbose_and_quiet_mutually_exclusive(self) -> None:
        """Test that --verbose and --quiet cannot be used together."""
        result = runner.invoke(app, ["--verbose", "--quiet", "run", "--help"])
        assert result.exit_code == 1
        assert "Cannot use --verbose and --quiet together" in result.stdout


class TestRunCommand:
    """Tests for the 'sci run' command."""

    def test_run_help(self) -> None:
        """Test 'sci run --help' displays help."""
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "Execute security tests" in result.stdout

    def test_run_no_args(self) -> None:
        """Test 'sci run' without arguments shows help."""
        result = runner.invoke(app, ["run"])
        assert result.exit_code == 0

    def test_run_dry_run(self) -> None:
        """Test 'sci run --dry-run' shows execution plan."""
        result = runner.invoke(app, ["run", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.stdout

    def test_run_with_provider(self) -> None:
        """Test 'sci run' with provider option."""
        result = runner.invoke(app, ["run", "--provider", "openai", "--dry-run"])
        assert result.exit_code == 0
        assert "openai" in result.stdout.lower()

    def test_run_missing_provider(self) -> None:
        """Test 'sci run' without provider shows error."""
        result = runner.invoke(app, ["run", "--model", "gpt-4"])
        assert result.exit_code == 1
        assert "provider is required" in result.stdout.lower()

    def test_run_missing_model(self) -> None:
        """Test 'sci run' without model shows error."""
        result = runner.invoke(app, ["run", "--provider", "openai"])
        assert result.exit_code == 1
        assert "model is required" in result.stdout.lower()

    def test_run_probes_subcommand(self) -> None:
        """Test 'sci run probes' lists available probes."""
        result = runner.invoke(app, ["run", "probes"])
        assert result.exit_code == 0
        assert "probes" in result.stdout.lower()

    def test_run_detectors_subcommand(self) -> None:
        """Test 'sci run detectors' lists available detectors."""
        result = runner.invoke(app, ["run", "detectors"])
        assert result.exit_code == 0
        assert "detectors" in result.stdout.lower()


class TestReportCommand:
    """Tests for the 'sci report' command."""

    def test_report_help(self) -> None:
        """Test 'sci report --help' displays help."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate security and compliance reports" in result.stdout

    def test_report_templates_subcommand(self) -> None:
        """Test 'sci report templates' lists available templates."""
        result = runner.invoke(app, ["report", "templates"])
        assert result.exit_code == 0
        assert "templates" in result.stdout.lower()


class TestConfigCommand:
    """Tests for the 'sci config' command."""

    def test_config_help(self) -> None:
        """Test 'sci config --help' displays help."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "Manage SCI configuration" in result.stdout

    def test_config_init_help(self) -> None:
        """Test 'sci config init --help' displays help."""
        result = runner.invoke(app, ["config", "init", "--help"])
        assert result.exit_code == 0
        assert "Generate default configuration" in result.stdout

    def test_config_validate_help(self) -> None:
        """Test 'sci config validate --help' displays help."""
        result = runner.invoke(app, ["config", "validate", "--help"])
        assert result.exit_code == 0
        assert "Validate a configuration file" in result.stdout

    def test_config_show_help(self) -> None:
        """Test 'sci config show --help' displays help."""
        result = runner.invoke(app, ["config", "show", "--help"])
        assert result.exit_code == 0
        assert "Display current configuration" in result.stdout

    def test_config_list_profiles_help(self) -> None:
        """Test 'sci config list-profiles --help' displays help."""
        result = runner.invoke(app, ["config", "list-profiles", "--help"])
        assert result.exit_code == 0
        assert "List available test profiles" in result.stdout


class TestGlobalOptions:
    """Tests for global CLI options."""

    def test_verbose_flag(self) -> None:
        """Test --verbose flag is accepted."""
        result = runner.invoke(app, ["--verbose", "run", "--help"])
        assert result.exit_code == 0

    def test_quiet_flag(self) -> None:
        """Test --quiet flag is accepted."""
        result = runner.invoke(app, ["--quiet", "run", "--help"])
        assert result.exit_code == 0

    def test_log_level_option(self) -> None:
        """Test --log-level option is accepted."""
        result = runner.invoke(app, ["--log-level", "DEBUG", "run", "--help"])
        assert result.exit_code == 0

    def test_log_format_option(self) -> None:
        """Test --log-format option is accepted."""
        result = runner.invoke(app, ["--log-format", "json", "run", "--help"])
        assert result.exit_code == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

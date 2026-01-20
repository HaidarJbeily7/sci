"""
Run command for SCI CLI.

This module provides commands for executing security tests against LLM targets.
"""

import json
import time
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from sci.config.manager import get_config
from sci.config.models import GarakConfig
from sci.engine.exceptions import (
    GarakConfigurationError,
    GarakConnectionError,
    GarakExecutionError,
    GarakInstallationError,
    GarakIntegrationError,
    GarakTimeoutError,
    GarakValidationError,
)
from sci.logging import get_logger
from sci.logging.setup import log_error

# Create the run sub-application
app = typer.Typer(
    name="run",
    help="Execute security tests against LLM targets.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = get_logger(__name__)


def _display_error_panel(
    error: GarakIntegrationError,
    console: Console,
    include_context: bool = True,
) -> None:
    """
    Display a formatted error panel for garak exceptions.

    Args:
        error: The garak exception to display.
        console: Rich console for output.
        include_context: Whether to include context details.
    """
    # Determine panel style based on error type
    if isinstance(error, GarakInstallationError):
        title = "Installation Required"
        border_style = "red"
        icon = "📦"
    elif isinstance(error, GarakConfigurationError):
        title = "Configuration Error"
        border_style = "red"
        icon = "⚙️"
    elif isinstance(error, GarakConnectionError):
        title = "Connection Error"
        border_style = "yellow"
        icon = "🔌"
    elif isinstance(error, GarakTimeoutError):
        title = "Timeout Error"
        border_style = "yellow"
        icon = "⏱️"
    elif isinstance(error, GarakValidationError):
        title = "Validation Error"
        border_style = "red"
        icon = "❌"
    elif isinstance(error, GarakExecutionError):
        title = "Execution Error"
        border_style = "red"
        icon = "💥"
    else:
        title = "Error"
        border_style = "red"
        icon = "❗"

    # Build error message
    lines = [
        f"[bold red]{icon} {error.error_code}[/bold red]: {error.message}",
    ]

    # Add troubleshooting tips
    if error.troubleshooting_tips:
        lines.append("")
        lines.append("[bold cyan]Troubleshooting:[/bold cyan]")
        for i, tip in enumerate(error.troubleshooting_tips[:5], 1):
            lines.append(f"  {i}. {tip}")

    # Add context if requested
    if include_context and error.context:
        # Filter out sensitive or verbose context
        safe_context = {
            k: v for k, v in error.context.items()
            if k not in ("stderr_preview", "original_exception")
            and not str(k).endswith("_key")
        }
        if safe_context:
            lines.append("")
            lines.append("[dim]Context:[/dim]")
            for key, value in list(safe_context.items())[:5]:
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value[:3])
                    if len(error.context[key]) > 3:
                        value += "..."
                lines.append(f"  [dim]{key}:[/dim] {value}")

    # Add checkpoint info if available
    if "checkpoint_path" in error.context:
        lines.append("")
        lines.append(
            f"[yellow]Recovery checkpoint saved to:[/yellow] "
            f"{error.context['checkpoint_path']}"
        )
        lines.append(
            "[dim]Resume the scan with: sci run --resume <checkpoint_path>[/dim]"
        )

    panel_content = "\n".join(lines)
    console.print()
    console.print(Panel(panel_content, title=title, border_style=border_style))


def _display_validation_suggestions(
    suggestions: list[str],
    console: Console,
) -> None:
    """Display validation suggestions in a helpful format."""
    if not suggestions:
        return

    console.print()
    console.print("[bold]Suggestions:[/bold]")
    for suggestion in suggestions[:5]:
        console.print(f"  • {suggestion}")


class Provider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE = "azure"
    AWS = "aws"
    HUGGINGFACE = "huggingface"


class OutputFormat(str, Enum):
    """Supported output formats."""

    JSON = "json"
    YAML = "yaml"
    HTML = "html"


def _create_output_directory(base_dir: Path, include_timestamp: bool) -> Path:
    """
    Create an output directory for scan results.

    Args:
        base_dir: Base directory for output.
        include_timestamp: Whether to create a timestamped subdirectory.

    Returns:
        Path to the created directory.
    """
    if include_timestamp:
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
        output_dir = base_dir / timestamp
    else:
        output_dir = base_dir

    output_dir.mkdir(parents=True, exist_ok=True)

    logger.debug(
        "output_directory_created",
        path=str(output_dir),
        include_timestamp=include_timestamp,
    )

    return output_dir


def _save_results(
    results: dict[str, Any],
    output_dir: Path,
    output_format: OutputFormat,
    include_timestamp: bool,
) -> Path:
    """
    Save scan results to file.

    Args:
        results: Scan results dictionary.
        output_dir: Directory to save results in.
        output_format: Output format (JSON, YAML, HTML).
        include_timestamp: Whether to include timestamp in filename.

    Returns:
        Path to the saved file.
    """
    # Generate filename
    if include_timestamp:
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.{output_format.value}"
    else:
        filename = f"scan_results.{output_format.value}"

    output_path = output_dir / filename

    # Serialize based on format
    if output_format == OutputFormat.JSON:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

    elif output_format == OutputFormat.YAML:
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(results, f, default_flow_style=False, allow_unicode=True)

    elif output_format == OutputFormat.HTML:
        html_content = _generate_html_report(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    file_size = output_path.stat().st_size

    logger.info(
        "results_saved",
        path=str(output_path),
        format=output_format.value,
        size_bytes=file_size,
    )

    return output_path


def _generate_html_report(results: dict[str, Any]) -> str:
    """Generate an HTML report from scan results."""
    summary = results.get("summary", {})
    findings = results.get("findings", [])

    # Determine status color
    status = results.get("status", "unknown")
    status_color = "#28a745" if status == "success" else "#dc3545"

    # Calculate pass rate
    pass_rate = summary.get("pass_rate", 0)
    pass_color = "#28a745" if pass_rate >= 80 else "#ffc107" if pass_rate >= 50 else "#dc3545"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCI Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card .value {{ font-size: 2em; font-weight: bold; }}
        .summary-card .label {{ color: #666; margin-top: 5px; }}
        .status {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }}
        .findings-table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        .findings-table th, .findings-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .findings-table th {{ background: #f8f9fa; }}
        .compliance-tags {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 20px; }}
        .tag {{ background: #e9ecef; padding: 5px 12px; border-radius: 15px; font-size: 0.9em; }}
        .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 20px; }}
        .metadata dt {{ font-weight: bold; color: #555; }}
        .metadata dd {{ margin: 0 0 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SCI Security Scan Report</h1>

        <div class="summary">
            <div class="summary-card">
                <div class="value" style="color: {status_color};">{status.upper()}</div>
                <div class="label">Scan Status</div>
            </div>
            <div class="summary-card">
                <div class="value">{summary.get('total', 0)}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #28a745;">{summary.get('passed', 0)}</div>
                <div class="label">Passed</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #dc3545;">{summary.get('failed', 0)}</div>
                <div class="label">Failed</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: {pass_color};">{pass_rate:.1f}%</div>
                <div class="label">Pass Rate</div>
            </div>
        </div>

        <h2>Scan Details</h2>
        <dl class="metadata">
            <dt>Scan ID</dt>
            <dd>{results.get('scan_id', 'N/A')}</dd>
            <dt>Provider</dt>
            <dd>{results.get('provider', 'N/A')}</dd>
            <dt>Model</dt>
            <dd>{results.get('model', 'N/A')}</dd>
            <dt>Profile</dt>
            <dd>{results.get('profile', 'N/A')} - {results.get('profile_description', '')}</dd>
            <dt>Duration</dt>
            <dd>{results.get('duration_ms', 0):.2f} ms</dd>
            <dt>Start Time</dt>
            <dd>{results.get('start_time', 'N/A')}</dd>
            <dt>End Time</dt>
            <dd>{results.get('end_time', 'N/A')}</dd>
        </dl>

        <h2>EU AI Act Compliance</h2>
        <div class="compliance-tags">
            {''.join(f'<span class="tag">{tag}</span>' for tag in results.get('compliance_tags', []))}
        </div>

        <h2>Probes Executed</h2>
        <div class="compliance-tags">
            {''.join(f'<span class="tag">{probe}</span>' for probe in results.get('probes_executed', [])[:20])}
            {'<span class="tag">...</span>' if len(results.get('probes_executed', [])) > 20 else ''}
        </div>

        <h2>Findings ({len(findings)})</h2>
        {'<p>No findings recorded.</p>' if not findings else f'''
        <table class="findings-table">
            <thead>
                <tr>
                    <th>Probe</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f"""<tr>
                    <td>{f.get('probe', f.get('probe_name', 'Unknown'))}</td>
                    <td>{'Pass' if f.get('passed', f.get('status') == 'pass') else 'Fail'}</td>
                    <td>{str(f.get('details', f.get('message', '')))[:100]}</td>
                </tr>""" for f in findings[:50])}
            </tbody>
        </table>
        '''}

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em;">
            Generated by SCI (Security Compliance Inspector) on {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </footer>
    </div>
</body>
</html>"""

    return html


def _display_results_summary(results: dict[str, Any], console: Console) -> None:
    """
    Display a summary of scan results including security score and compliance.

    Args:
        results: Scan results dictionary (may include processed_report).
        console: Rich console for output.
    """
    status = results.get("status", "unknown")
    processed_report = results.get("processed_report")

    # Create summary table
    table = Table(title="Scan Results Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value")

    # Status with color
    status_style = "green" if status == "success" else "red"
    table.add_row("Status", f"[{status_style}]{status.upper()}[/{status_style}]")

    table.add_row("Scan ID", results.get("scan_id", "N/A"))
    table.add_row("Provider", results.get("provider", "N/A"))
    table.add_row("Model", results.get("model", "N/A"))
    table.add_row("Profile", results.get("profile", "N/A"))

    # Duration
    duration_ms = results.get("duration_ms", 0)
    if duration_ms > 1000:
        duration_str = f"{duration_ms / 1000:.2f} seconds"
    else:
        duration_str = f"{duration_ms:.2f} ms"
    table.add_row("Duration", duration_str)

    console.print()
    console.print(table)

    # Security Score section (from processed report)
    if processed_report:
        security_score = processed_report.security_score
        score_value = security_score.overall_score
        risk_level = security_score.risk_level.value

        # Determine score color
        if score_value >= 80:
            score_style = "green"
        elif score_value >= 60:
            score_style = "yellow"
        else:
            score_style = "red"

        # Risk level color
        risk_colors = {
            "minimal": "green",
            "limited": "cyan",
            "high": "yellow",
            "unacceptable": "red",
        }
        risk_style = risk_colors.get(risk_level, "white")

        # Security Score table
        score_table = Table(title="Security Assessment", show_header=True, header_style="bold cyan")
        score_table.add_column("Metric", style="dim")
        score_table.add_column("Value")

        score_table.add_row(
            "Security Score",
            f"[{score_style}][bold]{score_value:.0f}[/bold] / 100[/{score_style}]"
        )
        score_table.add_row(
            "Risk Level",
            f"[{risk_style}][bold]{risk_level.upper()}[/bold][/{risk_style}]"
        )
        score_table.add_row(
            "Compliance Score",
            f"{security_score.compliance_score:.0f} / 100"
        )

        console.print()
        console.print(score_table)

        # Vulnerabilities by Severity table
        vuln = security_score.vulnerabilities_by_severity
        total_findings = sum(vuln.values())

        if total_findings > 0:
            vuln_table = Table(title="Vulnerabilities by Severity", show_header=True, header_style="bold cyan")
            vuln_table.add_column("Severity", style="dim")
            vuln_table.add_column("Count", justify="right")
            vuln_table.add_column("", justify="left")

            critical = vuln.get("critical", 0)
            high = vuln.get("high", 0)
            medium = vuln.get("medium", 0)
            low = vuln.get("low", 0)

            if critical > 0:
                vuln_table.add_row("Critical", f"[red bold]{critical}[/red bold]", "🔴 Immediate action required")
            else:
                vuln_table.add_row("Critical", "0", "[dim]None[/dim]")

            if high > 0:
                vuln_table.add_row("High", f"[#fd7e14 bold]{high}[/#fd7e14 bold]", "🟠 High priority")
            else:
                vuln_table.add_row("High", "0", "[dim]None[/dim]")

            if medium > 0:
                vuln_table.add_row("Medium", f"[yellow]{medium}[/yellow]", "🟡 Should address")
            else:
                vuln_table.add_row("Medium", "0", "[dim]None[/dim]")

            if low > 0:
                vuln_table.add_row("Low", f"[green]{low}[/green]", "🟢 Monitor")
            else:
                vuln_table.add_row("Low", "0", "[dim]None[/dim]")

            vuln_table.add_row("", "", "")
            vuln_table.add_row("[bold]Total[/bold]", f"[bold]{total_findings}[/bold]", "")

            console.print()
            console.print(vuln_table)

        # Compliance Assessment
        compliance = processed_report.compliance_assessment
        if compliance.articles_assessed > 0:
            comp_table = Table(title="EU AI Act Compliance", show_header=True, header_style="bold cyan")
            comp_table.add_column("Status", style="dim")
            comp_table.add_column("Value")

            # Overall status with color
            comp_status = compliance.overall_status.value
            comp_colors = {
                "compliant": "green",
                "non-compliant": "red",
                "partial": "yellow",
                "not-assessed": "dim",
            }
            comp_style = comp_colors.get(comp_status, "white")

            comp_table.add_row(
                "Overall Status",
                f"[{comp_style}][bold]{comp_status.upper().replace('-', ' ')}[/bold][/{comp_style}]"
            )
            comp_table.add_row(
                "Articles Assessed",
                str(compliance.articles_assessed)
            )
            comp_table.add_row(
                "Articles Passed",
                f"[green]{compliance.articles_passed}[/green]"
            )
            comp_table.add_row(
                "Articles Failed",
                f"[red]{compliance.articles_failed}[/red]" if compliance.articles_failed > 0 else "0"
            )

            console.print()
            console.print(comp_table)

            # High risk areas
            if compliance.high_risk_areas:
                console.print()
                console.print("[bold red]High Risk Areas:[/bold red]")
                for area in compliance.high_risk_areas:
                    console.print(f"  • [red]{area}[/red]")

        # Recommendations
        if processed_report.recommendations:
            console.print()
            console.print("[bold]Recommendations:[/bold]")
            for rec in processed_report.recommendations[:5]:  # Show top 5
                if rec.startswith("CRITICAL"):
                    console.print(f"  [red]• {rec}[/red]")
                elif rec.startswith("HIGH"):
                    console.print(f"  [#fd7e14]• {rec}[/#fd7e14]")
                else:
                    console.print(f"  • {rec}")

    else:
        # Fallback to raw summary if no processed report
        summary = results.get("summary", {})
        if summary:
            results_table = Table(title="Test Results", show_header=True, header_style="bold cyan")
            results_table.add_column("Metric", style="dim")
            results_table.add_column("Count")
            results_table.add_column("Rate")

            total = summary.get("total", 0)
            passed = summary.get("passed", 0)
            failed = summary.get("failed", 0)
            pass_rate = summary.get("pass_rate", 0)

            results_table.add_row("Total Tests", str(total), "")
            results_table.add_row("Passed", f"[green]{passed}[/green]", "")
            results_table.add_row("Failed", f"[red]{failed}[/red]", "")

            # Pass rate with color
            rate_style = "green" if pass_rate >= 80 else "yellow" if pass_rate >= 50 else "red"
            results_table.add_row("Pass Rate", "", f"[{rate_style}]{pass_rate:.1f}%[/{rate_style}]")

            console.print()
            console.print(results_table)

    # Compliance tags
    compliance_tags = results.get("compliance_tags", [])
    if compliance_tags:
        console.print()
        console.print("[bold]EU AI Act Articles Covered:[/bold]")
        console.print(", ".join(f"[cyan]{tag}[/cyan]" for tag in compliance_tags))

    # Output path
    processed_path = results.get("processed_report_path")
    if processed_path:
        console.print()
        console.print(f"[dim]Report saved to: {processed_path}[/dim]")

    # Error information if present
    error = results.get("error")
    if error:
        console.print()
        console.print(
            Panel(
                f"[red]Error Type:[/red] {error.get('type', 'Unknown')}\n"
                f"[red]Message:[/red] {error.get('message', 'No message')}",
                title="Error Details",
                border_style="red",
            )
        )


@app.callback(invoke_without_command=True)
def run_callback(
    ctx: typer.Context,
    profile: Annotated[
        Optional[str],
        typer.Option(
            "--profile",
            "-p",
            help="Test profile name to use (defined in configuration).",
        ),
    ] = None,
    provider: Annotated[
        Optional[Provider],
        typer.Option(
            "--provider",
            help="LLM provider to test against.",
            case_sensitive=False,
        ),
    ] = None,
    model: Annotated[
        Optional[str],
        typer.Option(
            "--model",
            "-m",
            help="Model name/identifier to test.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output directory for test results.",
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format for results.",
            case_sensitive=False,
        ),
    ] = OutputFormat.JSON,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Show what would be executed without running tests.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show detailed findings and progress.",
        ),
    ] = False,
    no_save: Annotated[
        bool,
        typer.Option(
            "--no-save",
            help="Skip saving results to file (dry run for testing).",
        ),
    ] = False,
) -> None:
    """
    Execute security tests against an LLM target.

    [bold]Examples:[/bold]

        [dim]# Run with default profile[/dim]
        $ sci run --provider openai --model gpt-4

        [dim]# Run with specific profile[/dim]
        $ sci run --profile comprehensive --provider anthropic --model claude-3

        [dim]# Dry run to preview execution[/dim]
        $ sci run --profile minimal --dry-run
    """
    if ctx.invoked_subcommand is not None:
        return

    # Get global configuration from parent context
    parent_ctx = ctx.parent
    if parent_ctx is None:
        console.print("[red]Error:[/red] No parent context available.")
        raise typer.Exit(code=1)

    config_file = parent_ctx.obj.get("config_file")
    log_level = parent_ctx.obj.get("log_level", "INFO")

    # Log execution intent
    logger.info(
        "run_command_invoked",
        profile=profile,
        provider=provider.value if provider else None,
        model=model,
        output_dir=str(output) if output else None,
        output_format=output_format.value,
        dry_run=dry_run,
        config_file=str(config_file) if config_file else None,
    )

    # Load configuration
    config_manager = get_config()
    try:
        if config_file:
            config_manager.load(Path(config_file))
        else:
            config_manager.load()
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] Configuration file not found: {e}")
        raise typer.Exit(code=1)

    # Display execution plan
    table = Table(title="Test Execution Plan", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="dim")
    table.add_column("Value")

    profile_name = profile or "standard"
    table.add_row("Profile", profile_name)
    table.add_row("Provider", provider.value if provider else "[dim]not specified[/dim]")
    table.add_row("Model", model or "[dim]not specified[/dim]")
    table.add_row("Output Directory", str(output) if output else "[dim]./results[/dim]")
    table.add_row("Output Format", output_format.value)
    table.add_row("Save Results", "[dim]disabled[/dim]" if no_save else "[green]enabled[/green]")
    table.add_row("Log Level", log_level)
    table.add_row("Config File", str(config_file) if config_file else "[dim]default[/dim]")

    console.print()
    console.print(table)
    console.print()

    if dry_run:
        console.print(
            Panel(
                "[yellow]Dry run mode:[/yellow] No tests will be executed.\n"
                "Remove --dry-run flag to execute the tests.",
                title="Dry Run",
                border_style="yellow",
            )
        )
        logger.info("dry_run_completed", message="Test execution skipped due to dry-run flag")
        return

    # Validate required parameters
    if not provider:
        console.print(
            "[red]Error:[/red] --provider is required. "
            "Specify an LLM provider (openai, anthropic, google, azure, aws, huggingface)."
        )
        raise typer.Exit(code=1)

    if not model:
        console.print(
            "[red]Error:[/red] --model is required. Specify a model name/identifier."
        )
        raise typer.Exit(code=1)

    # Load garak configuration and create engine
    try:
        garak_config_data = config_manager.get("garak", {})
        if isinstance(garak_config_data, dict):
            garak_config = GarakConfig.model_validate(garak_config_data)
        else:
            garak_config = GarakConfig()

        # Import here to avoid circular imports
        from sci.engine.garak_engine import GarakEngine

        engine = GarakEngine(garak_config, config_manager)

    except GarakInstallationError as e:
        _display_error_panel(e, console)
        raise typer.Exit(code=2)
    except ImportError as e:
        # Fallback for ImportError not wrapped in GarakInstallationError
        error = GarakInstallationError(
            message=str(e),
            required_version=">=2.0.0",
        )
        _display_error_panel(error, console)
        raise typer.Exit(code=2)
    except GarakConfigurationError as e:
        _display_error_panel(e, console)
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Error initializing engine:[/red] {e}")
        log_error(e, context={"phase": "engine_initialization"}, command="sci run")
        raise typer.Exit(code=2)

    # Determine output directory
    output_dir = output or Path(config_manager.get("output.directory", "./results"))
    include_timestamps = config_manager.get("output.include_timestamps", True)

    # Validate configuration
    console.print("[dim]Validating configuration...[/dim]")
    validation = engine.validate_configuration(provider.value, profile_name)

    if not validation["is_valid"]:
        console.print()
        console.print(
            Panel(
                "[red]Configuration validation failed:[/red]\n\n"
                + "\n".join(f"• {err}" for err in validation["errors"]),
                title="Validation Errors",
                border_style="red",
            )
        )

        # Display suggestions if available
        suggestions = validation.get("suggestions", [])
        if suggestions:
            _display_validation_suggestions(suggestions, console)
        else:
            # Show suggestions for common issues
            for error in validation["errors"]:
                if "API key" in error.lower():
                    console.print(
                        "\n[yellow]Tip:[/yellow] Set the API key via environment variable "
                        f"(e.g., OPENAI_API_KEY) or add it to .secrets.yaml"
                    )
                    break

        raise typer.Exit(code=1)

    # Show warnings if any
    if validation["warnings"]:
        for warning in validation["warnings"]:
            console.print(f"[yellow]Warning:[/yellow] {warning}")

    # Show suggestions as tips
    suggestions = validation.get("suggestions", [])
    if suggestions and verbose:
        console.print()
        console.print("[dim]Tips:[/dim]")
        for suggestion in suggestions[:3]:
            console.print(f"  [dim]• {suggestion}[/dim]")

    # Create output directory
    try:
        scan_output_dir = _create_output_directory(output_dir, include_timestamps)
    except OSError as e:
        console.print(f"[red]Error creating output directory:[/red] {e}")
        raise typer.Exit(code=1)

    # Execute scan with progress display
    console.print()

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=not verbose,
        ) as progress:
            task = progress.add_task("Initializing security scan...", total=100)

            def progress_callback(name: str, completion: float, status: str) -> None:
                progress.update(task, completed=completion * 100, description=f"{name}")

            results = engine.execute_scan(
                provider_name=provider.value,
                model_name=model,
                profile_name=profile_name,
                output_dir=scan_output_dir,
                progress_callback=progress_callback,
            )

    except GarakValidationError as e:
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=1)
    except GarakConfigurationError as e:
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=1)
    except GarakConnectionError as e:
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        # Suggest retry for connection errors
        console.print()
        console.print(
            "[yellow]Tip:[/yellow] Connection errors may be transient. "
            "Try running the command again."
        )
        raise typer.Exit(code=2)
    except GarakTimeoutError as e:
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        # Suggest timeout increase
        console.print()
        console.print(
            "[yellow]Tip:[/yellow] You can increase the timeout in your configuration:\n"
            "  garak:\n"
            "    scan_timeout: 1200  # seconds\n"
            "    probe_timeout: 240  # seconds"
        )
        raise typer.Exit(code=2)
    except GarakExecutionError as e:
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=2)
    except GarakIntegrationError as e:
        # Catch-all for other garak errors
        _display_error_panel(e, console)
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=2)
    except ValueError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=1)
    except RuntimeError as e:
        console.print(f"[red]Execution error:[/red] {e}")
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=2)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        log_error(e, context={"phase": "scan_execution"}, command="sci run")
        raise typer.Exit(code=2)

    # Display results summary
    _display_results_summary(results, console)

    # Save additional results (processed report is already saved by engine)
    if not no_save:
        try:
            # Save CLI-formatted results (in addition to engine-saved report)
            results_path = _save_results(
                results=results,
                output_dir=scan_output_dir,
                output_format=output_format,
                include_timestamp=include_timestamps,
            )

            # Get the processed report path
            processed_path = results.get("processed_report_path")

            console.print()
            if processed_path:
                console.print(
                    Panel(
                        f"[green]Scan completed successfully![/green]\n\n"
                        f"Processed report: [bold]{processed_path}[/bold]\n"
                        f"Raw results: [bold]{results_path}[/bold]",
                        title="Success",
                        border_style="green",
                    )
                )
            else:
                console.print(
                    Panel(
                        f"[green]Scan completed successfully![/green]\n\n"
                        f"Results saved to: [bold]{results_path}[/bold]",
                        title="Success",
                        border_style="green",
                    )
                )

        except OSError as e:
            console.print(f"[yellow]Warning:[/yellow] Could not save results: {e}")
    else:
        console.print()
        console.print(
            Panel(
                f"[green]Scan completed successfully![/green]\n\n"
                f"[yellow]Results not saved (--no-save flag was used)[/yellow]",
                title="Success",
                border_style="green",
            )
        )

    # Log completion
    logger.info(
        "run_command_completed",
        provider=provider.value,
        model=model,
        profile=profile_name,
        status=results.get("status"),
        duration_ms=results.get("duration_ms"),
        findings_count=len(results.get("findings", [])),
    )


@app.command("probes")
def list_probes(
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            "-c",
            help="Filter probes by category.",
        ),
    ] = None,
    compliance_tag: Annotated[
        Optional[str],
        typer.Option(
            "--compliance",
            help="Filter probes by EU AI Act compliance tag.",
        ),
    ] = None,
) -> None:
    """
    List available security probes.

    [bold]Examples:[/bold]

        [dim]# List all probes[/dim]
        $ sci run probes

        [dim]# Filter by category[/dim]
        $ sci run probes --category injection

        [dim]# Filter by compliance tag[/dim]
        $ sci run probes --compliance article-15
    """
    logger.info(
        "list_probes_invoked",
        category=category,
        compliance_tag=compliance_tag,
    )

    # Load configuration and create engine
    config_manager = get_config()
    try:
        config_manager.load()
    except Exception:
        pass  # Use defaults if no config file

    garak_config_data = config_manager.get("garak", {})
    if isinstance(garak_config_data, dict):
        garak_config = GarakConfig.model_validate(garak_config_data)
    else:
        garak_config = GarakConfig()

    try:
        from sci.engine.garak_engine import GarakEngine

        engine = GarakEngine(garak_config, config_manager)
        probes = engine.list_probes(category=category, compliance_tag=compliance_tag)

    except ImportError:
        # Fallback if garak is not installed - show static list
        from sci.garak.mappings import PROBE_MODULE_MAPPING, EU_AI_ACT_MAPPING

        probes = []
        for prefix, module in PROBE_MODULE_MAPPING.items():
            probe_category = prefix.split("_")[0] if "_" in prefix else prefix

            if category and probe_category != category:
                continue

            tags = EU_AI_ACT_MAPPING.get(probe_category, {}).get("articles", [])
            if compliance_tag and compliance_tag not in tags:
                continue

            probes.append({
                "sci_name": f"{prefix}_basic",
                "garak_module": module,
                "description": f"Security probe from {module} module",
                "compliance_tags": tags,
                "category": probe_category,
            })

    # Create table
    table = Table(
        title="Available Security Probes",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("SCI Probe Name", style="green")
    table.add_column("Garak Module", style="dim")
    table.add_column("Category")
    table.add_column("EU AI Act Articles", style="cyan")
    table.add_column("Risk Level", style="yellow")

    # Import EU_AI_ACT_MAPPING to get risk levels
    from sci.garak.mappings import EU_AI_ACT_MAPPING as mapping

    for probe in probes:
        tags = ", ".join(probe.get("compliance_tags", []))
        category = probe.get("category", "")

        # Get risk level from mapping
        risk_info = mapping.get(category, {})
        risk_level = risk_info.get("risk_level")
        if risk_level:
            risk_str = risk_level.value.upper()
            if risk_str == "HIGH":
                risk_str = f"[red]{risk_str}[/red]"
            elif risk_str == "LIMITED":
                risk_str = f"[yellow]{risk_str}[/yellow]"
            else:
                risk_str = f"[green]{risk_str}[/green]"
        else:
            risk_str = "[dim]-[/dim]"

        table.add_row(
            probe["sci_name"],
            probe["garak_module"],
            category,
            tags or "[dim]none[/dim]",
            risk_str,
        )

    console.print()
    console.print(table)
    console.print()
    console.print(f"[dim]Total probes: {len(probes)}[/dim]")

    if category or compliance_tag:
        filters = []
        if category:
            filters.append(f"category={category}")
        if compliance_tag:
            filters.append(f"compliance={compliance_tag}")
        console.print(f"[dim]Filters applied: {', '.join(filters)}[/dim]")

    console.print()
    console.print(
        "[dim]Use --category and --compliance options to filter probes.[/dim]"
    )


@app.command("detectors")
def list_detectors(
    category: Annotated[
        Optional[str],
        typer.Option(
            "--category",
            "-c",
            help="Filter detectors by category.",
        ),
    ] = None,
) -> None:
    """
    List available response detectors.

    [bold]Examples:[/bold]

        [dim]# List all detectors[/dim]
        $ sci run detectors

        [dim]# Filter by category[/dim]
        $ sci run detectors --category toxicity
    """
    logger.info("list_detectors_invoked", category=category)

    # Load configuration and create engine
    config_manager = get_config()
    try:
        config_manager.load()
    except Exception:
        pass  # Use defaults if no config file

    garak_config_data = config_manager.get("garak", {})
    if isinstance(garak_config_data, dict):
        garak_config = GarakConfig.model_validate(garak_config_data)
    else:
        garak_config = GarakConfig()

    try:
        from sci.engine.garak_engine import GarakEngine

        engine = GarakEngine(garak_config, config_manager)
        detectors = engine.list_detectors(category=category)

    except ImportError:
        # Fallback if garak is not installed - show static list
        from sci.garak.mappings import DETECTOR_TYPE_MAPPING

        detectors = []
        for sci_name, config in DETECTOR_TYPE_MAPPING.items():
            detector_category = sci_name.split("_")[0]

            if category and detector_category != category:
                continue

            detectors.append({
                "sci_name": sci_name,
                "garak_detectors": config.get("detectors", []),
                "category": detector_category,
                "level": config.get("level", "basic"),
            })

    # Create table
    table = Table(
        title="Available Response Detectors",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("SCI Detector Name", style="green")
    table.add_column("Category")
    table.add_column("Level", style="cyan")
    table.add_column("EU AI Act Articles", style="cyan")
    table.add_column("Garak Detectors", style="dim")

    # Import ComplianceMapper to get articles
    from sci.garak.mappings import ComplianceMapper

    compliance_mapper = ComplianceMapper()

    for detector in detectors:
        garak_dets = ", ".join(
            d.split(".")[-1] for d in detector.get("garak_detectors", [])
        )

        # Get compliance articles for this detector
        articles = compliance_mapper.get_articles_for_detector(detector["sci_name"])
        articles_str = ", ".join(articles) if articles else "[dim]none[/dim]"

        table.add_row(
            detector["sci_name"],
            detector.get("category", ""),
            detector.get("level", "basic"),
            articles_str,
            garak_dets or "[dim]none[/dim]",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(f"[dim]Total detectors: {len(detectors)}[/dim]")

    if category:
        console.print(f"[dim]Filter applied: category={category}[/dim]")

    console.print()
    console.print("[dim]Use --category option to filter detectors.[/dim]")

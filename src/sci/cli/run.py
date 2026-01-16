"""
Run command for SCI CLI.

This module provides commands for executing security tests against LLM targets.
"""

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sci.logging import get_logger

# Create the run sub-application
app = typer.Typer(
    name="run",
    help="Execute security tests against LLM targets.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = get_logger(__name__)


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

    # Display execution plan
    table = Table(title="Test Execution Plan", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="dim")
    table.add_column("Value")

    table.add_row("Profile", profile or "[dim]default[/dim]")
    table.add_row("Provider", provider.value if provider else "[dim]not specified[/dim]")
    table.add_row("Model", model or "[dim]not specified[/dim]")
    table.add_row("Output Directory", str(output) if output else "[dim]./results[/dim]")
    table.add_row("Output Format", output_format.value)
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

    # Placeholder for actual test execution
    console.print(
        Panel(
            f"[green]Ready to execute security tests[/green]\n\n"
            f"Provider: [bold]{provider.value}[/bold]\n"
            f"Model: [bold]{model}[/bold]\n"
            f"Profile: [bold]{profile or 'default'}[/bold]\n\n"
            "[dim]Test orchestration will be implemented in Phase 8.[/dim]",
            title="Execution Ready",
            border_style="green",
        )
    )

    logger.info(
        "run_command_completed",
        provider=provider.value,
        model=model,
        profile=profile,
        status="placeholder",
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

    console.print(
        Panel(
            "[dim]Security probes will be implemented in Phases 4-6.[/dim]\n\n"
            "Categories planned:\n"
            "• [cyan]injection[/cyan] - Prompt injection attacks\n"
            "• [cyan]jailbreak[/cyan] - System prompt bypasses\n"
            "• [cyan]extraction[/cyan] - Data extraction attempts\n"
            "• [cyan]manipulation[/cyan] - Output manipulation\n"
            "• [cyan]compliance[/cyan] - EU AI Act compliance checks",
            title="Available Probes",
            border_style="blue",
        )
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

    console.print(
        Panel(
            "[dim]Response detectors will be implemented in Phase 7.[/dim]\n\n"
            "Detectors planned:\n"
            "• [cyan]toxicity[/cyan] - Harmful content detection\n"
            "• [cyan]bias[/cyan] - Bias and fairness analysis\n"
            "• [cyan]hallucination[/cyan] - Factual accuracy checks\n"
            "• [cyan]leakage[/cyan] - Sensitive data leakage detection\n"
            "• [cyan]compliance[/cyan] - Compliance violation detection",
            title="Available Detectors",
            border_style="blue",
        )
    )

"""
Main CLI application for SCI.

This module provides the main Typer application and global options.
"""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from sci.version import __version__

# Create the main Typer application
app = typer.Typer(
    name="sci",
    help="Security-Centered Intelligence - LLM Security Testing & Compliance Framework",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Rich console for formatted output
console = Console()
error_console = Console(stderr=True)

# Global state for configuration
state: dict[str, object] = {}


def version_callback(value: bool) -> None:
    """Display version information and exit."""
    if value:
        console.print(f"[bold blue]SCI[/bold blue] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Enable verbose output with detailed logging.",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet",
            "-q",
            help="Suppress all output except errors.",
        ),
    ] = False,
    log_level: Annotated[
        Optional[str],
        typer.Option(
            "--log-level",
            "-l",
            help="Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
            envvar="SCI_LOG_LEVEL",
        ),
    ] = None,
    log_format: Annotated[
        Optional[str],
        typer.Option(
            "--log-format",
            help="Log output format (json, console).",
            envvar="SCI_LOG_FORMAT",
        ),
    ] = None,
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file (YAML or JSON).",
            envvar="SCI_CONFIG_FILE",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """
    [bold blue]SCI[/bold blue] - Security-Centered Intelligence

    A comprehensive LLM security testing and compliance framework designed for
    systematic security evaluation with EU AI Act compliance mapping.

    [dim]Use --help on any command for more information.[/dim]
    """
    # Store global options in context
    ctx.ensure_object(dict)

    # Determine effective log level
    if verbose and quiet:
        error_console.print(
            "[red]Error:[/red] Cannot use --verbose and --quiet together."
        )
        raise typer.Exit(code=1)

    effective_log_level = log_level
    if verbose and not log_level:
        effective_log_level = "DEBUG"
    elif quiet and not log_level:
        effective_log_level = "ERROR"
    elif not log_level:
        effective_log_level = "INFO"

    # Store in context for subcommands
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["log_level"] = effective_log_level
    ctx.obj["log_format"] = log_format or "console"
    ctx.obj["config_file"] = config_file

    # Initialize logging with global settings
    from sci.logging import setup_logging

    setup_logging(
        level=effective_log_level,
        format_type=ctx.obj["log_format"],
    )


# Import and register subcommands
from sci.cli import config as config_cmd
from sci.cli import report as report_cmd
from sci.cli import run as run_cmd

app.add_typer(run_cmd.app, name="run", help="Execute security tests against LLM targets.")
app.add_typer(report_cmd.app, name="report", help="Generate security and compliance reports.")
app.add_typer(config_cmd.app, name="config", help="Manage SCI configuration.")


if __name__ == "__main__":
    app()

"""
Report command for SCI CLI.

This module provides commands for generating security and compliance reports.
"""

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sci.logging import get_logger

# Create the report sub-application
app = typer.Typer(
    name="report",
    help="Generate security and compliance reports.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = get_logger(__name__)


class ReportFormat(str, Enum):
    """Supported report formats."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


class ReportType(str, Enum):
    """Types of reports available."""

    FULL = "full"
    COMPLIANCE = "compliance"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


@app.callback(invoke_without_command=True)
def report_callback(
    ctx: typer.Context,
    input_dir: Annotated[
        Optional[Path],
        typer.Option(
            "--input",
            "-i",
            help="Input directory containing test results.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file path for the report.",
            resolve_path=True,
        ),
    ] = None,
    report_format: Annotated[
        ReportFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format for the report.",
            case_sensitive=False,
        ),
    ] = ReportFormat.HTML,
    report_type: Annotated[
        ReportType,
        typer.Option(
            "--type",
            "-t",
            help="Type of report to generate.",
            case_sensitive=False,
        ),
    ] = ReportType.FULL,
    compliance_only: Annotated[
        bool,
        typer.Option(
            "--compliance-only",
            help="Generate compliance-focused report only.",
        ),
    ] = False,
    include_evidence: Annotated[
        bool,
        typer.Option(
            "--include-evidence",
            help="Include full evidence in the report.",
        ),
    ] = True,
) -> None:
    """
    Generate security and compliance reports from test results.

    [bold]Examples:[/bold]

        [dim]# Generate HTML report from results[/dim]
        $ sci report --input ./results --output report.html

        [dim]# Generate compliance-only PDF report[/dim]
        $ sci report --input ./results --format pdf --compliance-only

        [dim]# Generate executive summary[/dim]
        $ sci report --input ./results --type executive
    """
    if ctx.invoked_subcommand is not None:
        return

    # Log report generation intent
    logger.info(
        "report_command_invoked",
        input_dir=str(input_dir) if input_dir else None,
        output=str(output) if output else None,
        format=report_format.value,
        type=report_type.value,
        compliance_only=compliance_only,
        include_evidence=include_evidence,
    )

    # Display report configuration
    table = Table(title="Report Configuration", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="dim")
    table.add_column("Value")

    table.add_row("Input Directory", str(input_dir) if input_dir else "[dim]not specified[/dim]")
    table.add_row("Output File", str(output) if output else "[dim]auto-generated[/dim]")
    table.add_row("Format", report_format.value.upper())
    table.add_row("Report Type", report_type.value.title())
    table.add_row("Compliance Only", "Yes" if compliance_only else "No")
    table.add_row("Include Evidence", "Yes" if include_evidence else "No")

    console.print()
    console.print(table)
    console.print()

    # Validate required parameters
    if not input_dir:
        console.print(
            "[red]Error:[/red] --input is required. "
            "Specify the directory containing test results."
        )
        raise typer.Exit(code=1)

    # Placeholder for actual report generation
    console.print(
        Panel(
            f"[green]Ready to generate report[/green]\n\n"
            f"Input: [bold]{input_dir}[/bold]\n"
            f"Format: [bold]{report_format.value.upper()}[/bold]\n"
            f"Type: [bold]{report_type.value.title()}[/bold]\n\n"
            "[dim]Report generation will be implemented in Phase 10.[/dim]",
            title="Report Generation",
            border_style="green",
        )
    )

    logger.info(
        "report_command_completed",
        input_dir=str(input_dir),
        format=report_format.value,
        status="placeholder",
    )


@app.command("templates")
def list_templates() -> None:
    """
    List available report templates.

    [bold]Examples:[/bold]

        [dim]# List all templates[/dim]
        $ sci report templates
    """
    logger.info("list_templates_invoked")

    console.print(
        Panel(
            "[dim]Report templates will be implemented in Phase 10.[/dim]\n\n"
            "Templates planned:\n"
            "• [cyan]full[/cyan] - Complete security assessment report\n"
            "• [cyan]compliance[/cyan] - EU AI Act compliance report\n"
            "• [cyan]executive[/cyan] - Executive summary for stakeholders\n"
            "• [cyan]technical[/cyan] - Detailed technical findings\n"
            "• [cyan]custom[/cyan] - User-defined template support",
            title="Available Templates",
            border_style="blue",
        )
    )


@app.command("compliance")
def compliance_report(
    input_dir: Annotated[
        Path,
        typer.Argument(
            help="Input directory containing test results.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file path for the compliance report.",
            resolve_path=True,
        ),
    ] = None,
    articles: Annotated[
        Optional[str],
        typer.Option(
            "--articles",
            help="Comma-separated list of EU AI Act articles to include.",
        ),
    ] = None,
    risk_level: Annotated[
        Optional[str],
        typer.Option(
            "--risk-level",
            help="Filter by risk level (minimal, limited, high, unacceptable).",
        ),
    ] = None,
) -> None:
    """
    Generate EU AI Act compliance-focused report.

    [bold]Examples:[/bold]

        [dim]# Generate compliance report[/dim]
        $ sci report compliance ./results

        [dim]# Filter by specific articles[/dim]
        $ sci report compliance ./results --articles "9,10,15"

        [dim]# Filter by risk level[/dim]
        $ sci report compliance ./results --risk-level high
    """
    logger.info(
        "compliance_report_invoked",
        input_dir=str(input_dir),
        output=str(output) if output else None,
        articles=articles,
        risk_level=risk_level,
    )

    # Parse articles if provided
    article_list = [a.strip() for a in articles.split(",")] if articles else None

    console.print(
        Panel(
            f"[green]Generating EU AI Act Compliance Report[/green]\n\n"
            f"Input: [bold]{input_dir}[/bold]\n"
            f"Articles: [bold]{article_list or 'All'}[/bold]\n"
            f"Risk Level: [bold]{risk_level or 'All'}[/bold]\n\n"
            "[dim]Compliance reporting will be implemented in Phase 10.[/dim]",
            title="Compliance Report",
            border_style="green",
        )
    )

    logger.info(
        "compliance_report_completed",
        input_dir=str(input_dir),
        status="placeholder",
    )

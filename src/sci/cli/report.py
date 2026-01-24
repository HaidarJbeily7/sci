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

    # Find scan result files
    import json
    from datetime import datetime

    scan_files = list(input_dir.glob("scan_*.json"))
    if not scan_files:
        console.print(
            f"[red]Error:[/red] No scan result files found in {input_dir}"
        )
        raise typer.Exit(code=1)

    # Use the most recent scan file
    latest_scan = max(scan_files, key=lambda p: p.stat().st_mtime)
    console.print(f"[dim]Using scan results from:[/dim] {latest_scan.name}")

    try:
        with open(latest_scan, "r") as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error:[/red] Failed to parse scan results: {e}")
        raise typer.Exit(code=1)

    # Generate output path with correct extension
    if output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext_map = {
            ReportFormat.HTML: "html",
            ReportFormat.JSON: "json",
            ReportFormat.MARKDOWN: "md",
            ReportFormat.PDF: "pdf",
        }
        ext = ext_map.get(report_format, "html")
        output = input_dir / f"report_{timestamp}.{ext}"

    # Generate the report
    if report_format == ReportFormat.HTML:
        html_content = _generate_html_report(scan_data, include_evidence)
        output.write_text(html_content)
        console.print(f"\n[green]✓[/green] HTML report generated: [bold]{output}[/bold]")
    elif report_format == ReportFormat.JSON:
        # Just copy/reformat the JSON
        with open(output, "w") as f:
            json.dump(scan_data, f, indent=2)
        console.print(f"\n[green]✓[/green] JSON report generated: [bold]{output}[/bold]")
    elif report_format == ReportFormat.MARKDOWN:
        md_content = _generate_markdown_report(scan_data, include_evidence)
        output.write_text(md_content)
        console.print(f"\n[green]✓[/green] Markdown report generated: [bold]{output}[/bold]")
    else:
        console.print(f"[yellow]Warning:[/yellow] {report_format.value} format not yet implemented")

    logger.info(
        "report_command_completed",
        input_dir=str(input_dir),
        output=str(output),
        format=report_format.value,
        status="success",
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


def _generate_html_report(scan_data: dict, include_evidence: bool = True) -> str:
    """Generate an HTML report from scan data."""
    from typing import Any

    scan_id = scan_data.get("scan_id", "unknown")
    status = scan_data.get("status", "unknown")
    profile = scan_data.get("profile", "unknown")
    provider = scan_data.get("provider", "unknown")
    model = scan_data.get("model", "unknown")
    start_time = scan_data.get("start_time", "")
    duration_ms = scan_data.get("duration_ms", 0)

    security_score = scan_data.get("security_score", {})
    overall_score = security_score.get("overall_score", 0)
    risk_level = security_score.get("risk_level", "unknown")
    vulns = security_score.get("vulnerabilities_by_severity", {})

    compliance = scan_data.get("compliance_assessment", {})
    findings = scan_data.get("findings", [])
    probes_executed = scan_data.get("probes_executed", [])

    # Determine score color
    if overall_score >= 80:
        score_color = "#22c55e"  # green
    elif overall_score >= 60:
        score_color = "#eab308"  # yellow
    else:
        score_color = "#ef4444"  # red

    # Build findings HTML
    findings_html = ""
    if findings:
        for finding in findings[:50]:  # Limit to 50 findings
            severity = finding.get("severity", "unknown")
            sev_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#65a30d"}.get(severity.lower(), "#6b7280")
            findings_html += f"""
            <div class="finding">
                <span class="severity" style="background-color: {sev_color}">{severity.upper()}</span>
                <strong>{finding.get('probe', 'Unknown probe')}</strong>
                <p>{finding.get('description', 'No description')}</p>
            </div>
            """
    else:
        findings_html = "<p class='no-findings'>No vulnerabilities detected.</p>"

    # Build compliance HTML
    compliance_html = ""
    for article in compliance.get("article_details", []):
        status_icon = "✓" if article.get("status") == "compliant" else "✗"
        status_color = "#22c55e" if article.get("status") == "compliant" else "#ef4444"
        compliance_html += f"""
        <tr>
            <td><span style="color: {status_color}">{status_icon}</span> {article.get('article_id', '')}</td>
            <td>{article.get('title', '')}</td>
            <td style="color: {status_color}">{article.get('status', '').title()}</td>
            <td>{article.get('findings_count', 0)}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCI Security Report - {scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{ background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%); color: white; padding: 2rem; border-radius: 12px; margin-bottom: 2rem; }}
        header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        header p {{ opacity: 0.9; }}
        .score-card {{ background: white; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 2rem; }}
        .score {{ font-size: 4rem; font-weight: bold; color: {score_color}; }}
        .score-details {{ flex: 1; }}
        .score-details h2 {{ margin-bottom: 0.5rem; }}
        .risk-badge {{ display: inline-block; padding: 0.25rem 0.75rem; background: {score_color}; color: white; border-radius: 9999px; font-size: 0.875rem; text-transform: uppercase; }}
        .vulns {{ display: flex; gap: 1rem; margin-top: 1rem; }}
        .vuln-count {{ padding: 0.5rem 1rem; border-radius: 8px; background: #f1f5f9; }}
        .vuln-count.critical {{ border-left: 4px solid #dc2626; }}
        .vuln-count.high {{ border-left: 4px solid #ea580c; }}
        .vuln-count.medium {{ border-left: 4px solid #ca8a04; }}
        .vuln-count.low {{ border-left: 4px solid #65a30d; }}
        .section {{ background: white; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .section h3 {{ margin-bottom: 1rem; color: #334155; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; font-weight: 600; }}
        .finding {{ padding: 1rem; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 0.5rem; }}
        .finding .severity {{ padding: 0.125rem 0.5rem; color: white; border-radius: 4px; font-size: 0.75rem; margin-right: 0.5rem; }}
        .finding p {{ margin-top: 0.5rem; color: #64748b; font-size: 0.875rem; }}
        .no-findings {{ color: #22c55e; font-style: italic; }}
        .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
        .meta-item {{ background: #f8fafc; padding: 1rem; border-radius: 8px; }}
        .meta-item label {{ font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
        .meta-item span {{ display: block; font-weight: 600; margin-top: 0.25rem; }}
        footer {{ text-align: center; color: #64748b; font-size: 0.875rem; margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SCI Security Assessment Report</h1>
            <p>Scan ID: {scan_id} | Generated: {start_time[:19] if start_time else 'N/A'}</p>
        </header>

        <div class="score-card">
            <div class="score">{overall_score:.0f}</div>
            <div class="score-details">
                <h2>Security Score</h2>
                <span class="risk-badge">{risk_level} Risk</span>
                <div class="vulns">
                    <div class="vuln-count critical"><strong>{vulns.get('critical', 0)}</strong> Critical</div>
                    <div class="vuln-count high"><strong>{vulns.get('high', 0)}</strong> High</div>
                    <div class="vuln-count medium"><strong>{vulns.get('medium', 0)}</strong> Medium</div>
                    <div class="vuln-count low"><strong>{vulns.get('low', 0)}</strong> Low</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h3>Scan Details</h3>
            <div class="meta">
                <div class="meta-item"><label>Provider</label><span>{provider}</span></div>
                <div class="meta-item"><label>Model</label><span>{model}</span></div>
                <div class="meta-item"><label>Profile</label><span>{profile}</span></div>
                <div class="meta-item"><label>Duration</label><span>{duration_ms/1000:.1f}s</span></div>
                <div class="meta-item"><label>Probes Executed</label><span>{len(probes_executed)}</span></div>
                <div class="meta-item"><label>Status</label><span>{status}</span></div>
            </div>
        </div>

        <div class="section">
            <h3>EU AI Act Compliance</h3>
            <table>
                <thead>
                    <tr><th>Article</th><th>Title</th><th>Status</th><th>Findings</th></tr>
                </thead>
                <tbody>
                    {compliance_html if compliance_html else '<tr><td colspan="4">No compliance data available</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h3>Security Findings</h3>
            {findings_html}
        </div>

        <footer>
            <p>Generated by SCI - Security-Centered Intelligence | {start_time[:10] if start_time else 'N/A'}</p>
        </footer>
    </div>
</body>
</html>"""

    return html


def _generate_markdown_report(scan_data: dict, include_evidence: bool = True) -> str:
    """Generate a Markdown report from scan data."""
    scan_id = scan_data.get("scan_id", "unknown")
    profile = scan_data.get("profile", "unknown")
    provider = scan_data.get("provider", "unknown")
    model = scan_data.get("model", "unknown")
    start_time = scan_data.get("start_time", "")

    security_score = scan_data.get("security_score", {})
    overall_score = security_score.get("overall_score", 0)
    risk_level = security_score.get("risk_level", "unknown")
    vulns = security_score.get("vulnerabilities_by_severity", {})

    compliance = scan_data.get("compliance_assessment", {})
    findings = scan_data.get("findings", [])
    probes_executed = scan_data.get("probes_executed", [])

    md = f"""# SCI Security Assessment Report

**Scan ID:** {scan_id}  
**Date:** {start_time[:19] if start_time else 'N/A'}  
**Provider:** {provider}  
**Model:** {model}  
**Profile:** {profile}

---

## Security Score: {overall_score:.0f}/100

**Risk Level:** {risk_level.upper()}

| Severity | Count |
|----------|-------|
| Critical | {vulns.get('critical', 0)} |
| High | {vulns.get('high', 0)} |
| Medium | {vulns.get('medium', 0)} |
| Low | {vulns.get('low', 0)} |

---

## EU AI Act Compliance

| Article | Title | Status | Findings |
|---------|-------|--------|----------|
"""

    for article in compliance.get("article_details", []):
        status_icon = "✓" if article.get("status") == "compliant" else "✗"
        md += f"| {article.get('article_id', '')} | {article.get('title', '')} | {status_icon} {article.get('status', '')} | {article.get('findings_count', 0)} |\n"

    md += "\n---\n\n## Security Findings\n\n"

    if findings:
        for finding in findings[:50]:
            md += f"### [{finding.get('severity', 'UNKNOWN').upper()}] {finding.get('probe', 'Unknown')}\n\n"
            md += f"{finding.get('description', 'No description')}\n\n"
    else:
        md += "*No vulnerabilities detected.*\n"

    md += f"\n---\n\n*Generated by SCI - Security-Centered Intelligence*\n"

    return md

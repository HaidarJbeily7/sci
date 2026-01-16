"""
Config command for SCI CLI.

This module provides commands for managing SCI configuration.
"""

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from sci.logging import get_logger

# Create the config sub-application
app = typer.Typer(
    name="config",
    help="Manage SCI configuration.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = get_logger(__name__)


@app.command("init")
def init_config(
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output path for the configuration file.",
            resolve_path=True,
        ),
    ] = Path("settings.yaml"),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing configuration file.",
        ),
    ] = False,
    include_secrets: Annotated[
        bool,
        typer.Option(
            "--include-secrets",
            help="Include secrets template file.",
        ),
    ] = True,
) -> None:
    """
    Generate default configuration file.

    Creates a new configuration file with default settings and documented options.

    [bold]Examples:[/bold]

        [dim]# Create default config[/dim]
        $ sci config init

        [dim]# Create config at custom path[/dim]
        $ sci config init --output my-config.yaml

        [dim]# Overwrite existing config[/dim]
        $ sci config init --force
    """
    logger.info(
        "init_config_invoked",
        output=str(output),
        force=force,
        include_secrets=include_secrets,
    )

    # Check if file exists
    if output.exists() and not force:
        console.print(
            f"[red]Error:[/red] Configuration file already exists at {output}\n"
            "Use --force to overwrite."
        )
        raise typer.Exit(code=1)

    # Import default configuration
    from sci.config.defaults import get_default_config_yaml

    config_content = get_default_config_yaml()

    # Write configuration file
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(config_content)

    console.print(f"[green]✓[/green] Configuration file created at: [bold]{output}[/bold]")

    # Create secrets template if requested
    if include_secrets:
        secrets_path = output.parent / ".secrets.yaml"
        if not secrets_path.exists() or force:
            secrets_content = """# SCI Secrets Configuration
# This file contains sensitive credentials. DO NOT commit to version control.
# Add .secrets.yaml to your .gitignore file.

providers:
  openai:
    api_key: "sk-your-openai-api-key"
  anthropic:
    api_key: "sk-ant-your-anthropic-api-key"
  google:
    api_key: "your-google-api-key"
  azure:
    api_key: "your-azure-api-key"
  aws:
    access_key_id: "your-aws-access-key"
    secret_access_key: "your-aws-secret-key"
  huggingface:
    api_key: "hf_your-huggingface-token"
"""
            secrets_path.write_text(secrets_content)
            console.print(
                f"[green]✓[/green] Secrets template created at: [bold]{secrets_path}[/bold]"
            )
            console.print(
                "[yellow]⚠[/yellow] Remember to add .secrets.yaml to your .gitignore!"
            )

    logger.info(
        "init_config_completed",
        output=str(output),
        secrets_created=include_secrets,
    )


@app.command("validate")
def validate_config(
    config_file: Annotated[
        Path,
        typer.Argument(
            help="Path to configuration file to validate.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            "-s",
            help="Enable strict validation mode.",
        ),
    ] = False,
) -> None:
    """
    Validate a configuration file.

    Checks the configuration file for syntax errors and validates
    against the SCI configuration schema.

    [bold]Examples:[/bold]

        [dim]# Validate config file[/dim]
        $ sci config validate settings.yaml

        [dim]# Strict validation[/dim]
        $ sci config validate settings.yaml --strict
    """
    logger.info(
        "validate_config_invoked",
        config_file=str(config_file),
        strict=strict,
    )

    from sci.config.manager import ConfigManager

    try:
        # Load and validate configuration
        manager = ConfigManager()
        manager.load(config_file)
        validation_result = manager.validate(strict=strict)

        if validation_result.is_valid:
            console.print(
                Panel(
                    f"[green]✓ Configuration is valid[/green]\n\n"
                    f"File: [bold]{config_file}[/bold]\n"
                    f"Mode: {'Strict' if strict else 'Standard'}",
                    title="Validation Passed",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    f"[red]✗ Configuration has errors[/red]\n\n"
                    f"File: [bold]{config_file}[/bold]",
                    title="Validation Failed",
                    border_style="red",
                )
            )
            for error in validation_result.errors:
                console.print(f"  [red]•[/red] {error}")
            raise typer.Exit(code=1)

    except Exception as e:
        console.print(f"[red]Error validating configuration:[/red] {e}")
        logger.error("validate_config_failed", error=str(e))
        raise typer.Exit(code=1) from e

    logger.info("validate_config_completed", config_file=str(config_file), valid=True)


@app.command("show")
def show_config(
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    show_secrets: Annotated[
        bool,
        typer.Option(
            "--show-secrets",
            help="Show secret values (use with caution).",
        ),
    ] = False,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format (yaml, json, table).",
        ),
    ] = "yaml",
) -> None:
    """
    Display current configuration.

    Shows the merged configuration from all sources with secrets masked
    unless explicitly requested.

    [bold]Examples:[/bold]

        [dim]# Show current config[/dim]
        $ sci config show

        [dim]# Show config as JSON[/dim]
        $ sci config show --format json

        [dim]# Show with secrets (use with caution)[/dim]
        $ sci config show --show-secrets
    """
    logger.info(
        "show_config_invoked",
        config_file=str(config_file) if config_file else None,
        show_secrets=show_secrets,
        format=output_format,
    )

    from sci.config.manager import ConfigManager

    try:
        manager = ConfigManager()
        if config_file:
            manager.load(config_file)
        else:
            manager.load()

        # Get configuration, masking secrets if needed
        if show_secrets:
            config_dict = manager.to_dict()
        else:
            config_dict = manager.mask_secrets()

        if output_format == "yaml":
            import yaml

            config_yaml = yaml.dump(config_dict, default_flow_style=False, sort_keys=False)
            syntax = Syntax(config_yaml, "yaml", theme="monokai", line_numbers=True)
            console.print(syntax)
        elif output_format == "json":
            import json

            config_json = json.dumps(config_dict, indent=2)
            syntax = Syntax(config_json, "json", theme="monokai", line_numbers=True)
            console.print(syntax)
        elif output_format == "table":
            _display_config_table(config_dict)
        else:
            console.print(f"[red]Error:[/red] Unknown format: {output_format}")
            raise typer.Exit(code=1)

    except Exception as e:
        console.print(f"[red]Error loading configuration:[/red] {e}")
        logger.error("show_config_failed", error=str(e))
        raise typer.Exit(code=1) from e

    logger.info("show_config_completed")


def _display_config_table(config: dict, prefix: str = "") -> None:
    """Display configuration as a table."""
    table = Table(title="Current Configuration", show_header=True, header_style="bold cyan")
    table.add_column("Key", style="dim")
    table.add_column("Value")

    def flatten_dict(d: dict, parent_key: str = "") -> list[tuple[str, str]]:
        items: list[tuple[str, str]] = []
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key))
            else:
                items.append((new_key, str(v)))
        return items

    for key, value in flatten_dict(config):
        table.add_row(key, value)

    console.print(table)


@app.command("list-profiles")
def list_profiles(
    config_file: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to configuration file.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
) -> None:
    """
    List available test profiles.

    Shows all test profiles defined in the configuration with their
    descriptions and key settings.

    [bold]Examples:[/bold]

        [dim]# List profiles from default config[/dim]
        $ sci config list-profiles

        [dim]# List profiles from specific config[/dim]
        $ sci config list-profiles --config my-config.yaml
    """
    logger.info(
        "list_profiles_invoked",
        config_file=str(config_file) if config_file else None,
    )

    from sci.config.manager import ConfigManager

    try:
        manager = ConfigManager()
        if config_file:
            manager.load(config_file)
        else:
            manager.load()

        profiles = manager.get("profiles", {})

        if not profiles:
            console.print("[yellow]No test profiles defined in configuration.[/yellow]")
            return

        table = Table(title="Available Test Profiles", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="bold")
        table.add_column("Description")
        table.add_column("Probes", justify="right")
        table.add_column("Compliance Tags")

        for name, profile in profiles.items():
            description = profile.get("description", "[dim]No description[/dim]")
            probes_count = len(profile.get("probes", []))
            compliance_tags = ", ".join(profile.get("compliance_tags", [])) or "[dim]None[/dim]"
            table.add_row(name, description, str(probes_count), compliance_tags)

        console.print()
        console.print(table)
        console.print()

    except Exception as e:
        console.print(f"[red]Error loading configuration:[/red] {e}")
        logger.error("list_profiles_failed", error=str(e))
        raise typer.Exit(code=1) from e

    logger.info("list_profiles_completed")

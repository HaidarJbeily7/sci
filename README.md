# SCI - Security-Centered Intelligence

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A comprehensive LLM security testing and compliance framework designed for systematic security evaluation with EU AI Act compliance mapping.**

---

## 🎯 Vision

SCI (Security-Centered Intelligence) is a production-ready framework for systematically testing Large Language Model (LLM) systems against security vulnerabilities and regulatory compliance requirements. Built with EU AI Act compliance in mind, SCI provides structured security assessments with evidence trails suitable for regulatory documentation.

## ✨ Features

- **🔒 Security Testing**: Comprehensive probe library for testing prompt injection, jailbreaking, data extraction, and manipulation vulnerabilities
- **📋 EU AI Act Compliance**: Built-in compliance mapping to EU AI Act articles and annexes with evidence generation
- **📊 Structured Reporting**: Generate detailed security reports in multiple formats (JSON, HTML, PDF, Markdown)
- **🔧 Multi-Provider Support**: Test across OpenAI, Anthropic, Google, Azure, AWS Bedrock, and Hugging Face
- **📝 Structured Logging**: JSON logging for CI/CD integration with full execution traceability
- **⚙️ Flexible Configuration**: YAML/JSON configuration with environment variable overrides
- **🛡️ Garak Integration**: Powered by the [garak](https://github.com/leondz/garak) LLM security testing framework

## 🛡️ Garak Framework Integration

SCI integrates with the **garak** framework to provide comprehensive LLM security testing capabilities. Garak is an open-source LLM vulnerability scanner that provides extensive probe libraries for testing prompt injection, jailbreaking, data extraction, and other security vulnerabilities.

### Key Integration Features

- **Semantic Probe Mapping**: SCI's user-friendly probe names automatically map to garak's technical identifiers
- **Provider Adapters**: Seamless authentication configuration for all major LLM providers
- **Result Enrichment**: Garak findings are enriched with severity levels, compliance mapping, and remediation guidance
- **EU AI Act Mapping**: All findings are automatically associated with relevant EU AI Act articles

### Quick Start with Garak

```bash
# Install garak dependency
pip install 'garak>=0.13.3'

# Run a security scan
sci run --provider openai --model gpt-4 --profile standard

# Preview what will be tested (dry run)
sci run --provider openai --model gpt-4 --profile comprehensive --dry-run

# List available security probes
sci run probes

# List available detectors
sci run detectors
```

### Example Scan Output

```bash
$ sci run --provider openai --model gpt-4 --profile standard

🔍 SCI Security Scan
────────────────────────────────────────
Provider: openai
Model: gpt-4
Profile: standard

▶ Executing probes...
  ✓ prompt_injection_basic (3/3 passed)
  ✗ jailbreak_basic (2/5 passed)
  ✓ extraction_system_prompt (5/5 passed)

📊 Results Summary
────────────────────────────────────────
Security Score: 72/100
Risk Level: LIMITED
Findings: 3 vulnerabilities detected
  - Critical: 0
  - High: 1
  - Medium: 2
  - Low: 0

📋 EU AI Act Compliance
  Article 9: PARTIAL
  Article 15: COMPLIANT

Report saved: ./results/scan_abc123_20240115.html
```

See [Garak Integration Guide](docs/garak-integration.md) for detailed documentation.

## 🚀 Quick Start

### Installation

#### Using UV (Recommended)

[UV](https://docs.astral.sh/uv/) is a fast Python package manager that provides faster dependency resolution, automatic virtual environment management, and reproducible builds via lock files.

```bash
# Install UV (macOS/Linux)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install UV (Windows)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# Clone the repository
git clone https://github.com/sci-project/sci.git
cd sci

# Install the project (creates virtual environment automatically)
uv sync

# Or install with development dependencies
uv sync --all-extras

# Run the CLI
uv run sci --help
```

> **Note**: The `uv.lock` file ensures reproducible builds across all environments. It should be committed to version control.

#### Using pip

If you prefer traditional pip-based installation:

```bash
# Clone the repository
git clone https://github.com/sci-project/sci.git
cd sci

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Display help
sci --help
# Or explicitly with UV: uv run sci --help

# Show version
sci --version

# Initialize configuration
sci config init

# Run security tests (dry-run)
sci run --provider openai --model gpt-4 --dry-run

# Generate a report
sci report --input ./results --format html
```

> **Note**: After running `uv sync`, commands like `sci` work directly. You can also use `uv run sci` for explicit execution without activating the virtual environment.

### Configuration

Create a configuration file to customize SCI behavior:

```bash
# Generate default configuration
sci config init --output settings.yaml

# Validate your configuration
sci config validate settings.yaml

# View current configuration
sci config show
```

## 📁 Project Structure

```
sci/
├── src/sci/
│   ├── cli/              # Command-line interface
│   │   ├── main.py       # Main CLI application
│   │   ├── run.py        # sci run command
│   │   ├── report.py     # sci report command
│   │   └── config.py     # sci config command
│   ├── config/           # Configuration management
│   │   ├── manager.py    # Configuration loading/validation
│   │   ├── models.py     # Pydantic models
│   │   └── defaults.py   # Default values
│   ├── engine/           # Core scanning engine
│   │   ├── garak_engine.py    # Garak integration orchestration
│   │   ├── results.py         # Result processing pipeline
│   │   └── exceptions.py      # Custom exception hierarchy
│   ├── garak/            # Garak framework integration
│   │   ├── client.py     # Garak CLI wrapper
│   │   ├── adapters.py   # Provider configuration adapters
│   │   └── mappings.py   # Probe/detector/compliance mappings
│   ├── logging/          # Structured logging
│   │   └── setup.py      # Logging configuration
│   └── version.py        # Version management
├── tests/                # Test suite
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── fixtures/         # Test fixtures and sample data
├── docs/                 # Documentation
│   └── examples/         # Example configurations
└── pyproject.toml        # Project configuration
```

## 🔧 CLI Commands

### `sci run`

Execute security tests against LLM targets.

```bash
# Run tests with specific provider and model
sci run --provider openai --model gpt-4

# Use a test profile
sci run --profile comprehensive --provider anthropic --model claude-3

# Dry run to preview execution
sci run --dry-run

# List available probes
sci run probes

# List available detectors
sci run detectors
```

### `sci report`

Generate security and compliance reports.

```bash
# Generate HTML report
sci report --input ./results --format html --output report.html

# Generate compliance-focused report
sci report --input ./results --compliance-only

# Generate EU AI Act compliance report
sci report compliance ./results --articles "9,15"
```

### `sci config`

Manage SCI configuration.

```bash
# Initialize configuration
sci config init

# Validate configuration
sci config validate settings.yaml

# Show current configuration
sci config show

# List test profiles
sci config list-profiles
```

## ⚙️ Configuration

SCI supports multiple configuration sources with the following precedence:

1. **CLI arguments** (highest priority)
2. **Environment variables** (`SCI_` prefix)
3. **Configuration file** (settings.yaml)
4. **Defaults** (lowest priority)

### Environment Variables

```bash
# General settings
export SCI_LOG_LEVEL=DEBUG
export SCI_LOG_FORMAT=json

# Provider API keys
export SCI_PROVIDERS__OPENAI__API_KEY=sk-your-key
export SCI_PROVIDERS__ANTHROPIC__API_KEY=sk-ant-your-key
```

### Configuration File

```yaml
# settings.yaml
logging:
  level: INFO
  format: console

output:
  directory: ./results
  format: json

profiles:
  minimal:
    name: minimal
    probes:
      - prompt_injection_basic
      - jailbreak_basic
```

See [Configuration Reference](docs/configuration.md) for complete documentation.

## 🧪 Development

### Setup Development Environment

```bash
# Clone and install
git clone https://github.com/sci-project/sci.git
cd sci
uv sync --all-extras

# Install pre-commit hooks
pre-commit install

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=src/sci --cov-report=html

# Format code
uv run black src/ tests/

# Lint code
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

> **Note**: The `uv run` prefix automatically manages the virtual environment, so you don't need to activate it manually. The `uv.lock` file ensures all developers use identical dependency versions—commit it to version control.
>
> **Troubleshooting**: If `uv run sci` doesn't work, ensure UV is in your PATH or use the full path to the UV executable.

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/unit/test_cli.py

# Run specific test
pytest tests/unit/test_cli.py::TestMainCLI::test_version_flag
```

## 🏗️ Architecture

SCI is designed with a layered architecture for extensibility:

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer (Typer)                     │
├─────────────────────────────────────────────────────────────┤
│                   Configuration Layer (Dynaconf)             │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    GarakEngine                       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │    │
│  │  │  Probe   │  │ Detector │  │    Compliance    │  │    │
│  │  │  Mapper  │  │  Mapper  │  │      Mapper      │  │    │
│  │  └──────────┘  └──────────┘  └──────────────────┘  │    │
│  │  ┌──────────────────────────────────────────────┐  │    │
│  │  │           GarakClientWrapper                  │  │    │
│  │  └──────────────────────────────────────────────┘  │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Result Processing Pipeline              │    │
│  │  SecurityScore │ ComplianceAssessment │ Serializers │    │
│  └─────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    Reporting Layer                           │
└─────────────────────────────────────────────────────────────┘
```

## 📋 EU AI Act Compliance

SCI provides built-in mapping to EU AI Act requirements:

- **Article 9**: Risk Management Systems
- **Article 10**: Data and Data Governance
- **Article 13**: Transparency and Provision of Information
- **Article 14**: Human Oversight
- **Article 15**: Accuracy, Robustness and Cybersecurity
- **Annex IV**: Technical Documentation Requirements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## 📚 Documentation

- [Configuration Reference](docs/configuration.md)
- [CLI Reference](docs/cli-reference.md)
- [Garak Integration Guide](docs/garak-integration.md)
- [Garak Troubleshooting](docs/troubleshooting-garak.md)

### Example Configurations

- [Minimal Configuration](docs/examples/garak-minimal.yaml)
- [Standard Configuration](docs/examples/garak-standard.yaml)
- [Comprehensive Configuration](docs/examples/garak-comprehensive.yaml)
- [Multi-Provider Testing](docs/examples/garak-multi-provider.yaml)
- [Security-Focused Profile](docs/examples/profile-security-focused.yaml)
- [Compliance-Focused Profile](docs/examples/profile-compliance-focused.yaml)

---

**SCI** - Empowering secure and compliant AI deployments.

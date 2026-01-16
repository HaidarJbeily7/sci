# SCI CLI Reference

Complete reference for the Security-Centered Intelligence command-line interface.

## Global Options

These options are available for all commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Enable verbose output with detailed logging |
| `--quiet` | `-q` | Suppress all output except errors |
| `--log-level` | `-l` | Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `--log-format` | | Log output format (json, console) |
| `--config` | `-c` | Path to configuration file (YAML or JSON) |
| `--version` | `-V` | Show version and exit |
| `--help` | `-h` | Show help message and exit |

## Commands

### `sci run`

Execute security tests against LLM targets.

```bash
sci run [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--profile` | `-p` | Test profile name | default |
| `--provider` | | LLM provider (openai, anthropic, google, azure, aws, huggingface) | - |
| `--model` | `-m` | Model name/identifier | - |
| `--output` | `-o` | Output directory for results | ./results |
| `--format` | `-f` | Output format (json, yaml, html) | json |
| `--dry-run` | | Preview execution without running tests | - |

#### Examples

```bash
# Run with OpenAI GPT-4
sci run --provider openai --model gpt-4

# Run with specific profile
sci run --profile comprehensive --provider anthropic --model claude-3

# Dry run to see execution plan
sci run --provider openai --model gpt-4 --dry-run

# Custom output directory
sci run --provider openai --model gpt-4 --output ./my-results
```

#### Subcommands

##### `sci run probes`

List available security probes.

```bash
sci run probes [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--category` | `-c` | Filter by category |
| `--compliance` | | Filter by compliance tag |

##### `sci run detectors`

List available response detectors.

```bash
sci run detectors [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--category` | `-c` | Filter by category |

---

### `sci report`

Generate security and compliance reports.

```bash
sci report [OPTIONS]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input directory containing test results | - |
| `--output` | `-o` | Output file path | auto-generated |
| `--format` | `-f` | Report format (json, html, pdf, markdown) | html |
| `--type` | `-t` | Report type (full, compliance, executive, technical) | full |
| `--compliance-only` | | Generate compliance-focused report only | - |
| `--include-evidence` | | Include full evidence in report | true |

#### Examples

```bash
# Generate HTML report
sci report --input ./results --output report.html

# Generate PDF report
sci report --input ./results --format pdf

# Compliance-only report
sci report --input ./results --compliance-only

# Executive summary
sci report --input ./results --type executive
```

#### Subcommands

##### `sci report templates`

List available report templates.

```bash
sci report templates
```

##### `sci report compliance`

Generate EU AI Act compliance report.

```bash
sci report compliance <INPUT_DIR> [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--output` | `-o` | Output file path |
| `--articles` | | Comma-separated EU AI Act articles |
| `--risk-level` | | Filter by risk level |

---

### `sci config`

Manage SCI configuration.

```bash
sci config [COMMAND]
```

#### Subcommands

##### `sci config init`

Generate default configuration file.

```bash
sci config init [OPTIONS]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output path | settings.yaml |
| `--force` | `-f` | Overwrite existing file | - |
| `--include-secrets` | | Include secrets template | true |

```bash
# Create default configuration
sci config init

# Custom output path
sci config init --output my-config.yaml

# Overwrite existing
sci config init --force
```

##### `sci config validate`

Validate a configuration file.

```bash
sci config validate <CONFIG_FILE> [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--strict` | `-s` | Strict validation mode |

```bash
# Validate configuration
sci config validate settings.yaml

# Strict validation
sci config validate settings.yaml --strict
```

##### `sci config show`

Display current configuration.

```bash
sci config show [OPTIONS]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config` | `-c` | Path to configuration file | - |
| `--show-secrets` | | Show secret values | false |
| `--format` | `-f` | Output format (yaml, json, table) | yaml |

```bash
# Show configuration as YAML
sci config show

# Show as JSON
sci config show --format json

# Show with secrets (use with caution)
sci config show --show-secrets
```

##### `sci config list-profiles`

List available test profiles.

```bash
sci config list-profiles [OPTIONS]
```

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to configuration file |

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Validation error |

## Environment Variables

Environment variables can be used to set options:

| Variable | Description |
|----------|-------------|
| `SCI_LOG_LEVEL` | Default log level |
| `SCI_LOG_FORMAT` | Default log format |
| `SCI_CONFIG_FILE` | Default configuration file |

## CI/CD Integration

### JSON Logging

For CI/CD environments, use JSON logging format:

```bash
sci --log-format json run --provider openai --model gpt-4
```

### Exit Codes

Use exit codes to determine pipeline status:

```bash
sci run --provider openai --model gpt-4 || echo "Tests failed"
```

### Example GitHub Actions

```yaml
- name: Run SCI Tests
  env:
    SCI_PROVIDERS__OPENAI__API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: |
    sci --log-format json run --provider openai --model gpt-4

- name: Generate Report
  run: |
    sci report --input ./results --format html --output report.html
```

### Example GitLab CI

```yaml
security_test:
  script:
    - sci --log-format json run --provider openai --model gpt-4
    - sci report --input ./results --format json
  artifacts:
    paths:
      - results/
```

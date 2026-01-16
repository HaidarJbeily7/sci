# SCI Configuration Reference

This document provides a complete reference for configuring the Security-Centered Intelligence (SCI) framework.

## Configuration Sources

SCI loads configuration from multiple sources with the following precedence (highest to lowest):

1. **CLI Arguments** - Options passed directly to commands
2. **Environment Variables** - Variables with `SCI_` prefix
3. **Configuration Files** - `settings.yaml`, `settings.json`, `.secrets.yaml`
4. **Default Values** - Built-in defaults

## Configuration File

SCI supports YAML and JSON configuration files. Generate a default configuration:

```bash
sci config init --output settings.yaml
```

### File Structure

```yaml
# settings.yaml

# Logging Configuration
logging:
  level: INFO          # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: console      # console, json
  output: stdout       # stdout, stderr, or file path
  structured: true     # Enable structured logging

# Output Configuration
output:
  directory: ./results           # Output directory for results
  format: json                   # json, yaml, html
  compression: false             # Enable gzip compression
  include_timestamps: true       # Include timestamps in filenames

# Compliance Configuration
compliance:
  articles:                      # EU AI Act articles to evaluate
    - article-9
    - article-15
  annexes:                       # EU AI Act annexes
    - annex-iv
  risk_threshold: 0.7            # Risk score threshold (0.0-1.0)
  strict_mode: false             # Strict compliance checking
  generate_evidence: true        # Generate evidence documentation

# Test Profiles
profiles:
  my_profile:
    name: my_profile
    description: Custom test profile
    probes:
      - prompt_injection_basic
      - jailbreak_basic
    detectors:
      - toxicity_basic
    compliance_tags:
      - article-9
    max_parallel: 5
    timeout: 300

# Provider Configuration
providers:
  openai:
    base_url: https://api.openai.com/v1
    timeout: 30
    max_retries: 3
    model: gpt-4
```

## Environment Variables

All configuration options can be set via environment variables using the `SCI_` prefix with double underscores for nested keys.

### General Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `SCI_ENV` | Environment name (development, staging, production) | `development` |
| `SCI_LOG_LEVEL` | Logging level | `INFO` |
| `SCI_LOG_FORMAT` | Log output format (json, console) | `console` |
| `SCI_CONFIG_FILE` | Path to configuration file | - |

### Provider API Keys

```bash
# OpenAI
export SCI_PROVIDERS__OPENAI__API_KEY="sk-your-key"
export SCI_PROVIDERS__OPENAI__BASE_URL="https://api.openai.com/v1"
export SCI_PROVIDERS__OPENAI__TIMEOUT=30
export SCI_PROVIDERS__OPENAI__MAX_RETRIES=3

# Anthropic
export SCI_PROVIDERS__ANTHROPIC__API_KEY="sk-ant-your-key"
export SCI_PROVIDERS__ANTHROPIC__BASE_URL="https://api.anthropic.com"

# Google
export SCI_PROVIDERS__GOOGLE__API_KEY="your-google-key"
export SCI_PROVIDERS__GOOGLE__PROJECT_ID="your-project-id"
export SCI_PROVIDERS__GOOGLE__LOCATION="us-central1"

# Azure OpenAI
export SCI_PROVIDERS__AZURE__API_KEY="your-azure-key"
export SCI_PROVIDERS__AZURE__ENDPOINT="https://your-resource.openai.azure.com"
export SCI_PROVIDERS__AZURE__API_VERSION="2024-02-15-preview"
export SCI_PROVIDERS__AZURE__DEPLOYMENT_NAME="your-deployment"

# AWS Bedrock
export SCI_PROVIDERS__AWS__ACCESS_KEY_ID="your-access-key"
export SCI_PROVIDERS__AWS__SECRET_ACCESS_KEY="your-secret-key"
export SCI_PROVIDERS__AWS__REGION="us-east-1"

# Hugging Face
export SCI_PROVIDERS__HUGGINGFACE__API_KEY="hf_your-token"
```

### Output Settings

```bash
export SCI_OUTPUT__DIRECTORY="./results"
export SCI_OUTPUT__FORMAT="json"
export SCI_OUTPUT__COMPRESSION="false"
```

### Compliance Settings

```bash
export SCI_COMPLIANCE__RISK_THRESHOLD=0.7
export SCI_COMPLIANCE__STRICT_MODE="false"
```

## Secrets Management

Store sensitive credentials in `.secrets.yaml` (excluded from version control):

```yaml
# .secrets.yaml
providers:
  openai:
    api_key: "sk-your-actual-api-key"
  anthropic:
    api_key: "sk-ant-your-actual-key"
```

**Important**: Add `.secrets.yaml` to your `.gitignore` file.

## Test Profiles

### Built-in Profiles

SCI includes three built-in profiles:

#### Minimal Profile
Quick smoke test with essential probes only.
- Probes: `prompt_injection_basic`, `jailbreak_basic`
- Timeout: 120 seconds
- Max parallel: 3

#### Standard Profile
Standard security assessment covering major vulnerability categories.
- Probes: Basic and advanced injection, jailbreak, extraction
- Compliance: article-9, article-15
- Timeout: 300 seconds
- Max parallel: 5

#### Comprehensive Profile
Full security assessment with all probes and EU AI Act compliance mapping.
- Probes: All available probes
- Compliance: Full EU AI Act mapping
- Timeout: 600 seconds
- Max parallel: 10

### Custom Profiles

Define custom profiles in your configuration:

```yaml
profiles:
  quick_check:
    name: quick_check
    description: Fast security check for CI/CD
    probes:
      - prompt_injection_basic
    detectors:
      - toxicity_basic
    max_parallel: 10
    timeout: 60
```

## Provider Configuration

### OpenAI

```yaml
providers:
  openai:
    api_key: ${SCI_PROVIDERS__OPENAI__API_KEY}
    base_url: https://api.openai.com/v1
    timeout: 30
    max_retries: 3
    model: gpt-4
```

### Anthropic

```yaml
providers:
  anthropic:
    api_key: ${SCI_PROVIDERS__ANTHROPIC__API_KEY}
    base_url: https://api.anthropic.com
    timeout: 30
    max_retries: 3
    model: claude-3-opus-20240229
```

### Azure OpenAI

```yaml
providers:
  azure:
    api_key: ${SCI_PROVIDERS__AZURE__API_KEY}
    endpoint: https://your-resource.openai.azure.com
    api_version: 2024-02-15-preview
    deployment_name: your-deployment
    timeout: 30
    max_retries: 3
```

### AWS Bedrock

```yaml
providers:
  aws:
    access_key_id: ${SCI_PROVIDERS__AWS__ACCESS_KEY_ID}
    secret_access_key: ${SCI_PROVIDERS__AWS__SECRET_ACCESS_KEY}
    region: us-east-1
    timeout: 30
    max_retries: 3
```

## Validation

Validate your configuration before running tests:

```bash
# Validate configuration file
sci config validate settings.yaml

# Strict validation (warnings treated as errors)
sci config validate settings.yaml --strict

# Show merged configuration
sci config show
```

## Best Practices

1. **Use environment variables for secrets** - Never commit API keys to version control
2. **Use `.secrets.yaml`** - Keep sensitive configuration separate
3. **Validate before running** - Always validate configuration changes
4. **Use profiles** - Define reusable test configurations
5. **Set appropriate timeouts** - Adjust based on your LLM provider latency

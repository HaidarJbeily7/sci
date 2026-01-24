# Garak Troubleshooting Guide

This guide helps resolve common issues when using SCI's garak integration.

## Installation Issues

### Garak Not Found

**Symptoms:**

- `GarakInstallationError: Garak is not installed`
- `ModuleNotFoundError: No module named 'garak'`
- `sci run probes` fails with import error

**Root Causes:**

1. Garak package not installed
2. Wrong Python environment activated
3. Installation in different virtual environment

**Solutions:**

```bash
# Install garak
pip install 'garak>=0.13.3'

# Or with UV
uv add 'garak>=0.13.3'

# Verify installation
python -c "import garak; print(garak.__version__)"

# If using UV, ensure correct environment
uv run python -c "import garak; print(garak.__version__)"
```

**Prevention:**

- Add garak to your `pyproject.toml` dependencies
- Use lock files (`uv.lock` or `requirements.txt`) to ensure consistent environments

### Version Compatibility Issues

**Symptoms:**

- `Warning: Garak version may not be fully compatible`
- Unexpected probe behavior
- Missing probe modules

**Root Causes:**

1. Garak version < 2.0.0 installed
2. Breaking API changes in newer garak versions

**Solutions:**

```bash
# Check current version
python -c "import garak; print(garak.__version__)"

# Upgrade to latest compatible version
pip install --upgrade 'garak>=2.0.0'

# Or pin to specific version
pip install 'garak==0.13.3'
```

### Python Version Requirements

**Symptoms:**

- `SyntaxError` during import
- Type hint errors
- Async-related errors

**Root Causes:**

- Python version < 3.10

**Solutions:**

```bash
# Check Python version
python --version

# Use pyenv or conda to install Python 3.10+
pyenv install 3.10
pyenv local 3.10

# Or with UV
uv python install 3.10
```

## Configuration Issues

### Invalid Probe/Detector Names

**Symptoms:**

- `GarakValidationError: Unknown SCI probe name`
- `Profile 'x' has no valid probes`
- Suggestions shown but scan doesn't run

**Root Causes:**

1. Typo in probe/detector name
2. Probe not in configuration mapping
3. Custom probe not registered

**Solutions:**

```bash
# List available probes
sci run probes

# List available detectors
sci run detectors

# Check your configuration
sci config show
```

```yaml
# Fix typo in settings.yaml
profiles:
  my_profile:
    probes:
      - prompt_injection_basic  # Correct
      # - prompt_injectionbasic  # Wrong
```

### Missing API Keys

**Symptoms:**

- `API key is required for provider`
- `Authentication failed`
- Empty API key warning

**Root Causes:**

1. Environment variable not set
2. Configuration file missing API key
3. `.secrets.yaml` not loaded

**Solutions:**

```bash
# Set environment variable
export OPENAI_API_KEY="sk-your-key"

# Or use .secrets.yaml
echo "providers:
  openai:
    api_key: sk-your-key" > .secrets.yaml

# Verify configuration
sci config show | grep -i api
```

**Prevention:**

- Use environment variables for CI/CD
- Add `.secrets.yaml` to `.gitignore`

### Provider Configuration Errors

**Symptoms:**

- `Unsupported provider: x`
- `Provider configuration validation failed`
- `Invalid endpoint URL`

**Root Causes:**

1. Provider name misspelled
2. Missing required fields
3. Invalid URL format

**Solutions:**

```yaml
# Azure requires endpoint and deployment_name
providers:
  azure:
    api_key: ${AZURE_OPENAI_KEY}
    endpoint: https://your-resource.openai.azure.com  # Must be full URL
    deployment_name: gpt-4-deployment  # Required
    api_version: 2024-02-15-preview

# AWS requires region and credentials
providers:
  aws:
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    region: us-east-1  # Required
```

## Execution Issues

### Timeout Errors

**Symptoms:**

- `GarakTimeoutError: Operation timed out`
- Scan hangs indefinitely
- Partial results returned

**Root Causes:**

1. Timeout too short for number of probes
2. Slow API responses
3. Network latency

**Solutions:**

```yaml
# Increase timeouts in settings.yaml
garak:
  timeout: 120         # Per-request timeout
  scan_timeout: 1800   # Overall scan timeout (30 min)
```

```bash
# Run with fewer probes
sci run --provider openai --model gpt-4 --profile minimal
```

**Prevention:**

- Start with `minimal` profile for testing
- Increase timeout based on probe count
- Use `--dry-run` to verify configuration first

### Connection Failures

**Symptoms:**

- `GarakConnectionError: Connection failed`
- `Network unreachable`
- `Connection timed out`

**Root Causes:**

1. Internet connectivity issues
2. Firewall blocking API endpoints
3. Provider API outage
4. DNS resolution problems

**Solutions:**

```bash
# Test connectivity
curl -I https://api.openai.com/v1/models

# Check provider status pages:
# OpenAI: https://status.openai.com
# Anthropic: https://status.anthropic.com
# Azure: https://status.azure.com

# Verify DNS
nslookup api.openai.com
```

```yaml
# Configure proxy if needed
# (Set via environment)
export HTTPS_PROXY="http://proxy:8080"
```

### Rate Limiting

**Symptoms:**

- `Error 429: Rate limit exceeded`
- `Too many requests`
- Intermittent failures during scan

**Root Causes:**

1. Parallelism too high
2. API tier limits exceeded
3. Shared API key with other services

**Solutions:**

```yaml
# Reduce parallelism
garak:
  parallelism: 3  # Lower value for rate-limited APIs

# Enable retry with backoff
garak:
  max_retries: 5
```

```bash
# Run with minimal parallelism
sci run --provider openai --model gpt-4 --profile minimal
```

**Prevention:**

- Monitor API usage dashboards
- Use dedicated API keys for testing
- Schedule scans during off-peak hours

### Authentication Errors

**Symptoms:**

- `Error 401: Unauthorized`
- `Invalid API key`
- `Authentication failed for provider`

**Root Causes:**

1. API key expired or revoked
2. Wrong API key format
3. API key doesn't have required permissions
4. Environment variable not loaded

**Solutions:**

```bash
# Verify API key format
# OpenAI: sk-xxx...
# Anthropic: sk-ant-xxx...
# Hugging Face: hf_xxx...

# Test API key directly
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Check key permissions in provider dashboard
```

**Prevention:**

- Rotate API keys regularly
- Use least-privilege API keys
- Test keys before running scans

## Result Processing Issues

### Missing Report Files

**Symptoms:**

- `Report not found`
- `No report files in output directory`
- Empty findings despite successful execution

**Root Causes:**

1. Garak didn't generate output
2. Wrong output directory
3. Permissions issues
4. Disk space full

**Solutions:**

```bash
# Check output directory
ls -la ./results/

# Verify disk space
df -h

# Check directory permissions
ls -la ./results/

# Run with explicit output directory
sci run --provider openai --model gpt-4 \
    --output-dir ./my_results
```

### Parsing Errors

**Symptoms:**

- `JSONDecodeError: Invalid JSON`
- `Report parse error`
- Corrupted report files

**Root Causes:**

1. Garak crash during execution
2. Incomplete write due to timeout
3. Encoding issues

**Solutions:**

```bash
# Validate JSON manually
python -m json.tool ./results/report.json

# Check file encoding
file ./results/report.json

# Re-run the scan
sci run --provider openai --model gpt-4 --profile minimal
```

### Storage Failures

**Symptoms:**

- `StorageError: Failed to save report`
- `Permission denied`
- `No space left on device`

**Root Causes:**

1. Insufficient disk space
2. Directory permissions
3. Invalid path

**Solutions:**

```bash
# Check disk space
df -h

# Verify/create output directory
mkdir -p ./results
chmod 755 ./results

# Use different output location
sci run --provider openai --model gpt-4 \
    --output-dir /tmp/sci_results
```

## Provider-Specific Issues

### OpenAI

**Common Issues:**

- Model not available for account tier
- Organization ID required
- API key rotation

**Solutions:**

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    # For organization-specific keys
    # Set via environment: OPENAI_ORGANIZATION
```

### Anthropic

**Common Issues:**

- Rate limits stricter than other providers
- Model name format changes

**Solutions:**

```yaml
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    model: claude-3-opus-20240229  # Full model name required

garak:
  parallelism: 3  # Lower for Anthropic rate limits
```

### Azure OpenAI

**Common Issues:**

- Endpoint format incorrect
- Deployment name vs model name confusion
- API version compatibility

**Solutions:**

```yaml
providers:
  azure:
    api_key: ${AZURE_OPENAI_KEY}
    # Full endpoint URL including https://
    endpoint: https://your-resource.openai.azure.com
    # Deployment name, not model name
    deployment_name: my-gpt4-deployment
    # Use supported API version
    api_version: 2024-02-15-preview
```

### AWS Bedrock

**Common Issues:**

- IAM permissions insufficient
- Model not available in region
- Credential chain issues

**Solutions:**

```yaml
providers:
  aws:
    # Use IAM credentials or instance profile
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    # Ensure model is available in this region
    region: us-east-1
    # Use correct model identifier
    model: anthropic.claude-v2
```

```bash
# Test AWS credentials
aws sts get-caller-identity

# List available Bedrock models
aws bedrock list-foundation-models --region us-east-1
```

### Google Cloud

**Common Issues:**

- Project billing not enabled
- Vertex AI API not enabled
- Quota exceeded

**Solutions:**

```yaml
providers:
  google:
    api_key: ${GOOGLE_API_KEY}
    project_id: your-project-id  # Must have billing enabled
    location: us-central1
    model: gemini-pro
```

```bash
# Enable Vertex AI API
gcloud services enable aiplatform.googleapis.com

# Check quota
gcloud compute project-info describe --project=your-project
```

## Performance Issues

### Slow Scan Execution

**Symptoms:**

- Scans take much longer than expected
- Progress seems stuck
- High memory usage

**Root Causes:**

1. Too many probes in profile
2. Large sample sizes
3. Extended detectors enabled
4. Low API response times

**Solutions:**

```yaml
garak:
  # Limit sample size
  limit_samples: 50

  # Reduce parallelism to avoid memory issues
  parallelism: 5

  # Disable extended detectors for faster scans
  extended_detectors: false
```

```bash
# Use minimal profile for quick tests
sci run --provider openai --model gpt-4 --profile minimal
```

### Memory Usage

**Symptoms:**

- `MemoryError`
- System becomes unresponsive
- OOM killer terminates process

**Root Causes:**

1. Too many concurrent probes
2. Large report files in memory
3. Memory leaks in long-running scans

**Solutions:**

```yaml
garak:
  # Reduce parallelism
  parallelism: 3

  # Enable continue-on-error to process in batches
  continue_on_error: true
```

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep -E "sci|garak" | grep -v grep'
```

### Parallelism Tuning

**Recommendation Matrix:**

| API Provider | Recommended Parallelism | Notes |
|--------------|------------------------|-------|
| OpenAI | 10-20 | Good rate limits |
| Anthropic | 3-5 | Stricter rate limits |
| Azure | 5-10 | Depends on deployment |
| AWS Bedrock | 5-10 | Region dependent |
| Hugging Face | 3-5 | API tier dependent |

## Getting Help

### Debug Mode

Enable debug logging for more information:

```bash
sci --log-level DEBUG run --provider openai --model gpt-4
```

### Gathering Diagnostic Information

```bash
# Collect diagnostic info
echo "=== Python Version ===" && python --version
echo "=== Garak Version ===" && python -c "import garak; print(garak.__version__)"
echo "=== SCI Version ===" && sci --version
echo "=== Configuration ===" && sci config show
```

### Reporting Issues

When reporting issues, include:

1. Full error message and stack trace
2. SCI and garak versions
3. Configuration (without secrets)
4. Steps to reproduce
5. Expected vs actual behavior

### Community Resources

- [SCI GitHub Issues](https://github.com/sci-project/sci/issues)
- [Garak GitHub](https://github.com/leondz/garak)
- [Garak Documentation](https://garak.readthedocs.io/)

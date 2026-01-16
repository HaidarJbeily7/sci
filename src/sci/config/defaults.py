"""
Default configuration values for SCI.

This module provides default configuration values used when no configuration
file is specified or when values are missing from the configuration.
"""

from typing import Any

# Default configuration dictionary
DEFAULT_CONFIG: dict[str, Any] = {
    # Logging defaults
    "logging": {
        "level": "INFO",
        "format": "console",
        "output": "stdout",
        "structured": True,
    },
    # Output defaults
    "output": {
        "directory": "./results",
        "format": "json",
        "compression": False,
        "include_timestamps": True,
    },
    # Compliance defaults
    "compliance": {
        "articles": [],
        "annexes": [],
        "risk_threshold": 0.7,
        "strict_mode": False,
        "generate_evidence": True,
    },
    # Default test profiles
    "profiles": {
        "minimal": {
            "name": "minimal",
            "description": "Quick smoke test with essential probes only",
            "probes": [
                "prompt_injection_basic",
                "jailbreak_basic",
            ],
            "detectors": [
                "toxicity_basic",
                "leakage_basic",
            ],
            "compliance_tags": [],
            "max_parallel": 3,
            "timeout": 120,
        },
        "standard": {
            "name": "standard",
            "description": "Standard security assessment covering major vulnerability categories",
            "probes": [
                "prompt_injection_basic",
                "prompt_injection_advanced",
                "jailbreak_basic",
                "jailbreak_roleplay",
                "extraction_system_prompt",
                "extraction_training_data",
            ],
            "detectors": [
                "toxicity_basic",
                "toxicity_advanced",
                "leakage_basic",
                "leakage_pii",
                "bias_detection",
            ],
            "compliance_tags": [
                "article-9",
                "article-15",
            ],
            "max_parallel": 5,
            "timeout": 300,
        },
        "comprehensive": {
            "name": "comprehensive",
            "description": "Full security assessment with all probes and EU AI Act compliance mapping",
            "probes": [
                "prompt_injection_basic",
                "prompt_injection_advanced",
                "prompt_injection_multilingual",
                "jailbreak_basic",
                "jailbreak_roleplay",
                "jailbreak_encoding",
                "extraction_system_prompt",
                "extraction_training_data",
                "extraction_model_info",
                "manipulation_output",
                "manipulation_context",
                "compliance_transparency",
                "compliance_human_oversight",
            ],
            "detectors": [
                "toxicity_basic",
                "toxicity_advanced",
                "toxicity_subtle",
                "leakage_basic",
                "leakage_pii",
                "leakage_credentials",
                "bias_detection",
                "bias_demographic",
                "hallucination_factual",
                "compliance_violation",
            ],
            "compliance_tags": [
                "article-9",
                "article-10",
                "article-13",
                "article-14",
                "article-15",
                "annex-iv",
            ],
            "max_parallel": 10,
            "timeout": 600,
        },
    },
    # Provider defaults (without credentials)
    "providers": {
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "timeout": 30,
            "max_retries": 3,
            "model": "gpt-4",
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com",
            "timeout": 30,
            "max_retries": 3,
            "model": "claude-3-opus-20240229",
        },
        "google": {
            "location": "us-central1",
            "timeout": 30,
            "max_retries": 3,
            "model": "gemini-pro",
        },
        "azure": {
            "api_version": "2024-02-15-preview",
            "timeout": 30,
            "max_retries": 3,
        },
        "aws": {
            "region": "us-east-1",
            "timeout": 30,
            "max_retries": 3,
        },
        "huggingface": {
            "base_url": "https://api-inference.huggingface.co",
            "timeout": 60,
            "max_retries": 3,
        },
    },
}


def get_default_config_yaml() -> str:
    """
    Generate default configuration as YAML string.

    Returns:
        YAML-formatted default configuration with documentation comments.
    """
    return '''# =============================================================================
# SCI - Security-Centered Intelligence
# Configuration File
# =============================================================================
# This file configures the SCI security testing framework.
# Copy this file to settings.yaml and customize as needed.
# =============================================================================

# -----------------------------------------------------------------------------
# Logging Configuration
# -----------------------------------------------------------------------------
logging:
  # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
  level: INFO

  # Log format: "json" for CI/CD, "console" for development
  format: console

  # Output destination: stdout, stderr, or file path
  output: stdout

  # Enable structured logging with context
  structured: true

# -----------------------------------------------------------------------------
# Output Configuration
# -----------------------------------------------------------------------------
output:
  # Directory for test results
  directory: ./results

  # Output format: json, yaml, html
  format: json

  # Enable compression for output files
  compression: false

  # Include timestamps in output filenames
  include_timestamps: true

# -----------------------------------------------------------------------------
# EU AI Act Compliance Configuration
# -----------------------------------------------------------------------------
compliance:
  # EU AI Act articles to evaluate
  articles:
    - article-9   # Risk management
    - article-10  # Data governance
    - article-13  # Transparency
    - article-14  # Human oversight
    - article-15  # Accuracy and robustness

  # EU AI Act annexes to include
  annexes:
    - annex-iv    # Technical documentation

  # Risk threshold for compliance (0.0-1.0)
  risk_threshold: 0.7

  # Enable strict compliance mode
  strict_mode: false

  # Generate evidence documentation
  generate_evidence: true

# -----------------------------------------------------------------------------
# Test Profiles
# -----------------------------------------------------------------------------
# Profiles define which probes and detectors to run during testing.
# Use --profile to select a profile when running tests.
profiles:
  minimal:
    name: minimal
    description: Quick smoke test with essential probes only
    probes:
      - prompt_injection_basic
      - jailbreak_basic
    detectors:
      - toxicity_basic
      - leakage_basic
    compliance_tags: []
    max_parallel: 3
    timeout: 120

  standard:
    name: standard
    description: Standard security assessment covering major vulnerability categories
    probes:
      - prompt_injection_basic
      - prompt_injection_advanced
      - jailbreak_basic
      - jailbreak_roleplay
      - extraction_system_prompt
      - extraction_training_data
    detectors:
      - toxicity_basic
      - toxicity_advanced
      - leakage_basic
      - leakage_pii
      - bias_detection
    compliance_tags:
      - article-9
      - article-15
    max_parallel: 5
    timeout: 300

  comprehensive:
    name: comprehensive
    description: Full security assessment with all probes and EU AI Act compliance mapping
    probes:
      - prompt_injection_basic
      - prompt_injection_advanced
      - prompt_injection_multilingual
      - jailbreak_basic
      - jailbreak_roleplay
      - jailbreak_encoding
      - extraction_system_prompt
      - extraction_training_data
      - extraction_model_info
      - manipulation_output
      - manipulation_context
      - compliance_transparency
      - compliance_human_oversight
    detectors:
      - toxicity_basic
      - toxicity_advanced
      - toxicity_subtle
      - leakage_basic
      - leakage_pii
      - leakage_credentials
      - bias_detection
      - bias_demographic
      - hallucination_factual
      - compliance_violation
    compliance_tags:
      - article-9
      - article-10
      - article-13
      - article-14
      - article-15
      - annex-iv
    max_parallel: 10
    timeout: 600

# -----------------------------------------------------------------------------
# LLM Provider Configuration
# -----------------------------------------------------------------------------
# Provider credentials should be stored in .secrets.yaml or environment variables.
# This section configures provider-specific settings (non-sensitive).
providers:
  openai:
    base_url: https://api.openai.com/v1
    timeout: 30
    max_retries: 3
    model: gpt-4

  anthropic:
    base_url: https://api.anthropic.com
    timeout: 30
    max_retries: 3
    model: claude-3-opus-20240229

  google:
    location: us-central1
    timeout: 30
    max_retries: 3
    model: gemini-pro

  azure:
    api_version: 2024-02-15-preview
    timeout: 30
    max_retries: 3
    # Set endpoint, deployment_name via environment or .secrets.yaml

  aws:
    region: us-east-1
    timeout: 30
    max_retries: 3

  huggingface:
    base_url: https://api-inference.huggingface.co
    timeout: 60
    max_retries: 3
'''

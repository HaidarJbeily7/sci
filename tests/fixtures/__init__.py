"""Test fixtures for SCI garak integration tests."""

from tests.fixtures.garak_reports import (
    cleanup_temp_directory,
    create_mock_garak_output_directory,
    create_temp_report_file,
    get_mock_available_generators,
    get_mock_available_probes,
    get_mock_client_run_scan_response,
    get_sample_anthropic_config,
    get_sample_aws_config,
    get_sample_azure_config,
    get_sample_garak_config,
    get_sample_garak_report_json,
    get_sample_garak_report_jsonl,
    get_sample_google_config,
    get_sample_huggingface_config,
    get_sample_openai_config,
    get_sample_scan_result_error,
    get_sample_scan_result_partial,
    get_sample_scan_result_success,
    get_sample_test_profile_comprehensive,
    get_sample_test_profile_minimal,
    get_sample_test_profile_standard,
    get_sample_vulnerability_findings,
)

__all__ = [
    # Report data
    "get_sample_garak_report_json",
    "get_sample_garak_report_jsonl",
    # Scan results
    "get_sample_scan_result_success",
    "get_sample_scan_result_partial",
    "get_sample_scan_result_error",
    # Provider configs
    "get_sample_openai_config",
    "get_sample_anthropic_config",
    "get_sample_azure_config",
    "get_sample_aws_config",
    "get_sample_google_config",
    "get_sample_huggingface_config",
    # Test profiles
    "get_sample_test_profile_minimal",
    "get_sample_test_profile_standard",
    "get_sample_test_profile_comprehensive",
    # Vulnerability findings
    "get_sample_vulnerability_findings",
    # Mock client responses
    "get_mock_client_run_scan_response",
    "get_mock_available_probes",
    "get_mock_available_generators",
    # Garak config
    "get_sample_garak_config",
    # Utility functions
    "create_temp_report_file",
    "create_mock_garak_output_directory",
    "cleanup_temp_directory",
]

"""
Integration tests for GarakEngine.

Tests the full scan execution workflow with mocked GarakClientWrapper,
including profile loading, probe mapping, result processing, and error handling.
"""

import json
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from sci.config.manager import ConfigManager
from sci.config.models import GarakConfig, OutputConfig, ProviderConfig, TestProfile
from sci.engine.exceptions import (
    GarakConfigurationError,
    GarakConnectionError,
    GarakExecutionError,
    GarakValidationError,
)

# Import fixtures
from tests.fixtures.garak_reports import (
    get_mock_available_probes,
    get_mock_client_run_scan_response,
    get_sample_garak_config,
    get_sample_openai_config,
    get_sample_scan_result_success,
    get_sample_test_profile_standard,
)


class TestGarakEngineInitialization:
    """Tests for GarakEngine initialization."""

    @pytest.fixture
    def mock_dependencies(self) -> Generator[dict, None, None]:
        """Mock all external dependencies for engine initialization."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.validate_installation.return_value = True
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                yield {"client": mock_client, "garak": mock_garak}

    def test_initialization_success(
        self, mock_dependencies: dict, tmp_path: Path
    ) -> None:
        """Test successful engine initialization."""
        from sci.engine.garak_engine import GarakEngine

        config = GarakConfig(**get_sample_garak_config())
        config_manager = MagicMock(spec=ConfigManager)
        config_manager.get.return_value = {}

        engine = GarakEngine(config, config_manager)

        assert engine is not None
        assert engine.config == config
        assert engine.client is not None

    def test_initialization_creates_mappers(
        self, mock_dependencies: dict
    ) -> None:
        """Test that initialization creates probe and detector mappers."""
        from sci.engine.garak_engine import GarakEngine

        config = GarakConfig(**get_sample_garak_config())
        config_manager = MagicMock(spec=ConfigManager)
        config_manager.get.return_value = {}

        engine = GarakEngine(config, config_manager)

        assert engine.probe_mapper is not None
        assert engine.detector_mapper is not None
        assert engine.compliance_mapper is not None


class TestGarakEngineProfileLoading:
    """Tests for profile loading functionality."""

    @pytest.fixture
    def engine(self, tmp_path: Path) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.side_effect = lambda key, default=None: {
                    "profiles.standard": get_sample_test_profile_standard(),
                    "profiles.minimal": {
                        "name": "minimal",
                        "description": "Minimal profile",
                        "probes": ["prompt_injection_basic"],
                        "detectors": ["toxicity_basic"],
                    },
                    "providers.openai": get_sample_openai_config(),
                    "output": {"directory": str(tmp_path)},
                }.get(key, default)

                engine = GarakEngine(config, config_manager)
                engine.client = mock_client
                yield engine

    def test_get_profile_standard(self, engine: Any) -> None:
        """Test getting the standard built-in profile."""
        profile = engine.get_profile("standard")

        assert profile is not None
        assert profile.name == "standard"
        assert len(profile.probes) > 0

    def test_get_profile_minimal(self, engine: Any) -> None:
        """Test getting the minimal built-in profile."""
        profile = engine.get_profile("minimal")

        assert profile is not None
        assert profile.name == "minimal"

    def test_get_profile_not_found(self, engine: Any) -> None:
        """Test getting non-existent profile returns None."""
        profile = engine.get_profile("nonexistent_profile")

        assert profile is None

    def test_get_builtin_profiles(self, engine: Any) -> None:
        """Test that built-in profiles are available."""
        profiles = engine.list_available_profiles()

        assert "standard" in profiles
        assert "minimal" in profiles
        assert "comprehensive" in profiles


class TestGarakEngineProbeValidation:
    """Tests for probe validation functionality."""

    @pytest.fixture
    def engine(self) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.return_value = {}

                engine = GarakEngine(config, config_manager)
                engine.client = mock_client
                yield engine

    def test_validate_probes_available_success(self, engine: Any) -> None:
        """Test validating available probes succeeds."""
        # These should be in the mock available probes
        engine.validate_probes_available(["prompt_injection_basic"])
        # Should not raise

    def test_validate_probes_unavailable_raises(self, engine: Any) -> None:
        """Test validating unavailable probes raises error."""
        # Mock the client to return empty list
        engine.client.list_available_probes.return_value = []

        with pytest.raises(GarakValidationError) as exc_info:
            engine.validate_probes_available(["nonexistent_probe_xyz"])

        assert "VAL" in exc_info.value.error_code


class TestGarakEngineScanExecution:
    """Tests for scan execution workflow."""

    @pytest.fixture
    def engine_with_mocks(
        self, tmp_path: Path
    ) -> Generator[tuple[Any, MagicMock], None, None]:
        """Create engine with mocked client for testing execution."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()
        mock_client.run_scan.return_value = get_mock_client_run_scan_response()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.side_effect = lambda key, default=None: {
                    "profiles.standard": get_sample_test_profile_standard(),
                    "providers.openai": get_sample_openai_config(),
                    "output": {"directory": str(tmp_path)},
                }.get(key, default)

                engine = GarakEngine(config, config_manager)
                engine.client = mock_client
                yield engine, mock_client

    def test_execute_scan_success(
        self, engine_with_mocks: tuple[Any, MagicMock], tmp_path: Path
    ) -> None:
        """Test successful scan execution."""
        engine, mock_client = engine_with_mocks

        result = engine.execute_scan(
            provider_name="openai",
            model_name="gpt-4",
            profile_name="standard",
            output_dir=tmp_path,
        )

        assert result["status"] in ("success", "partial_success")
        assert result["provider"] == "openai"
        assert result["model"] == "gpt-4"
        assert "scan_id" in result
        assert "findings" in result
        mock_client.run_scan.assert_called()

    def test_execute_scan_invalid_profile_raises(
        self, engine_with_mocks: tuple[Any, MagicMock], tmp_path: Path
    ) -> None:
        """Test that invalid profile raises error."""
        engine, _ = engine_with_mocks

        with pytest.raises(GarakValidationError) as exc_info:
            engine.execute_scan(
                provider_name="openai",
                model_name="gpt-4",
                profile_name="nonexistent_profile",
                output_dir=tmp_path,
            )

        assert "profile" in str(exc_info.value).lower()

    def test_execute_scan_with_progress_callback(
        self, engine_with_mocks: tuple[Any, MagicMock], tmp_path: Path
    ) -> None:
        """Test scan execution with progress callback."""
        engine, _ = engine_with_mocks
        progress_updates: list[tuple[str, float, str]] = []

        def progress_callback(probe: str, completion: float, status: str) -> None:
            progress_updates.append((probe, completion, status))

        engine.execute_scan(
            provider_name="openai",
            model_name="gpt-4",
            profile_name="standard",
            output_dir=tmp_path,
            progress_callback=progress_callback,
        )

        assert len(progress_updates) > 0
        # Should have initialization progress
        assert any("initializing" in u[2] for u in progress_updates)
        # Should have completion progress
        assert any(u[1] == 1.0 for u in progress_updates)


class TestGarakEngineProviderConfiguration:
    """Tests for provider configuration loading and validation."""

    @pytest.fixture
    def engine(self) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.side_effect = lambda key, default=None: {
                    "providers.openai": get_sample_openai_config(),
                    "providers.azure": {
                        "api_key": "azure-key",
                        "endpoint": "https://test.openai.azure.com",
                        "deployment_name": "gpt-4",
                    },
                }.get(key, default)

                engine = GarakEngine(config, config_manager)
                yield engine

    def test_load_provider_config_openai(self, engine: Any) -> None:
        """Test loading OpenAI provider configuration."""
        config = engine._load_provider_config("openai")

        assert config is not None
        assert config.api_key is not None

    def test_load_provider_config_azure(self, engine: Any) -> None:
        """Test loading Azure provider configuration."""
        from sci.config.models import AzureProviderConfig

        config = engine._load_provider_config("azure")

        assert config is not None
        assert isinstance(config, AzureProviderConfig)


class TestGarakEngineConfigurationValidation:
    """Tests for configuration validation."""

    @pytest.fixture
    def engine(self) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()
        mock_client.validate_installation.return_value = True

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.side_effect = lambda key, default=None: {
                    "profiles.standard": get_sample_test_profile_standard(),
                    "providers.openai": get_sample_openai_config(),
                }.get(key, default)

                engine = GarakEngine(config, config_manager)
                engine.client = mock_client
                yield engine

    def test_validate_configuration_success(self, engine: Any) -> None:
        """Test successful configuration validation."""
        result = engine.validate_configuration(
            provider_name="openai",
            profile_name="standard",
        )

        assert result["is_valid"] is True
        assert len(result["errors"]) == 0

    def test_validate_configuration_invalid_profile(self, engine: Any) -> None:
        """Test validation with invalid profile."""
        result = engine.validate_configuration(
            provider_name="openai",
            profile_name="nonexistent",
        )

        assert result["is_valid"] is False
        assert len(result["errors"]) > 0
        assert any("profile" in e.lower() for e in result["errors"])


class TestGarakEngineComplianceTagging:
    """Tests for compliance tag aggregation."""

    @pytest.fixture
    def engine(self) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.return_value = {}

                engine = GarakEngine(config, config_manager)
                yield engine

    def test_compliance_tags_aggregation(self, engine: Any) -> None:
        """Test that compliance tags are aggregated from probes."""
        tags = engine.compliance_mapper.get_compliance_tags(
            probes=["prompt_injection_basic", "extraction_system_prompt"],
            detectors=["toxicity_basic"],
        )

        assert len(tags) > 0
        # Should include articles related to robustness and data
        assert "article-9" in tags or "article-15" in tags


class TestGarakEngineProbeListing:
    """Tests for probe and detector listing."""

    @pytest.fixture
    def engine(self) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.return_value = {}

                engine = GarakEngine(config, config_manager)
                yield engine

    def test_list_probes(self, engine: Any) -> None:
        """Test listing available probes."""
        probes = engine.list_probes()

        assert len(probes) > 0
        assert all("sci_name" in p for p in probes)
        assert all("garak_module" in p for p in probes)

    def test_list_probes_with_category_filter(self, engine: Any) -> None:
        """Test listing probes filtered by category."""
        probes = engine.list_probes(category="prompt")

        # All probes should be in the prompt category
        assert all("prompt" in p["category"] for p in probes)

    def test_list_detectors(self, engine: Any) -> None:
        """Test listing available detectors."""
        detectors = engine.list_detectors()

        assert len(detectors) > 0
        assert all("sci_name" in d for d in detectors)
        assert all("garak_detectors" in d for d in detectors)


class TestGarakEngineCheckpoints:
    """Tests for checkpoint save/load functionality."""

    @pytest.fixture
    def engine(self, tmp_path: Path) -> Generator[Any, None, None]:
        """Create a mock engine for testing."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.return_value = {}

                engine = GarakEngine(config, config_manager)
                yield engine

    def test_save_checkpoint(self, engine: Any, tmp_path: Path) -> None:
        """Test saving a checkpoint."""
        from sci.engine.exceptions import ScanCheckpoint

        checkpoint = ScanCheckpoint(
            scan_id="test-checkpoint",
            completed_probes=["probe1"],
            pending_probes=["probe2", "probe3"],
        )

        path = engine._save_checkpoint(checkpoint, tmp_path)

        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        assert data["scan_id"] == "test-checkpoint"

    def test_load_checkpoint(self, engine: Any, tmp_path: Path) -> None:
        """Test loading a checkpoint."""
        checkpoint_data = {
            "scan_id": "test-load",
            "completed_probes": ["probe1"],
            "failed_probes": [],
            "pending_probes": ["probe2"],
            "partial_results": {},
            "checkpoint_time": "2024-01-15T10:00:00+00:00",
        }
        checkpoint_path = tmp_path / "checkpoint_test-load.json"
        with open(checkpoint_path, "w") as f:
            json.dump(checkpoint_data, f)

        checkpoint = engine._load_checkpoint(checkpoint_path)

        assert checkpoint.scan_id == "test-load"
        assert "probe1" in checkpoint.completed_probes


class TestGarakEngineErrorRecovery:
    """Tests for error recovery during scan execution."""

    @pytest.fixture
    def engine_with_failing_client(
        self, tmp_path: Path
    ) -> Generator[tuple[Any, MagicMock], None, None]:
        """Create engine with client that fails on first attempts."""
        mock_garak = MagicMock()
        mock_garak.__version__ = "2.0.0"

        mock_client = MagicMock()
        mock_client.list_available_probes.return_value = get_mock_available_probes()

        # Configure to fail first then succeed
        call_count = 0

        def mock_run_scan(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise GarakExecutionError(
                    message="First attempt failed",
                    exit_code=1,
                )
            return get_mock_client_run_scan_response()

        mock_client.run_scan.side_effect = mock_run_scan

        with patch.dict(
            "sys.modules", {"garak": mock_garak, "garak.cli": MagicMock()}
        ):
            with patch(
                "sci.engine.garak_engine.GarakClientWrapper", return_value=mock_client
            ):
                from sci.engine.garak_engine import GarakEngine

                config = GarakConfig(**get_sample_garak_config())
                config.continue_on_error = True  # Enable error recovery
                config_manager = MagicMock(spec=ConfigManager)
                config_manager.get.side_effect = lambda key, default=None: {
                    "profiles.standard": {
                        "name": "standard",
                        "probes": ["prompt_injection_basic"],
                        "detectors": [],
                    },
                    "providers.openai": get_sample_openai_config(),
                }.get(key, default)

                engine = GarakEngine(config, config_manager)
                engine.client = mock_client
                yield engine, mock_client


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

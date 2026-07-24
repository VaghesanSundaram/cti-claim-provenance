from __future__ import annotations

from decimal import Decimal

import pytest

from cti_provenance.config import AppConfig, redact_known_secrets


def test_environment_loader_ignores_undocumented_variables() -> None:
    config = AppConfig.from_environment(
        {
            "PATH": "not part of application config",
            "UNTRUSTED_SETTING": "ignored",
            "CTI_EVAL_COST_CAP_USD": "2.50",
        }
    )
    assert config.cost_cap_usd == Decimal("2.50")
    assert config.provider is None


def test_provider_key_is_validated_only_for_model_runs() -> None:
    config = AppConfig.from_environment(
        {
            "CTI_EVAL_PROVIDER": "openai",
            "CTI_EVAL_MODEL": "example-model",
        }
    )
    assert config.provider == "openai"
    with pytest.raises(ValueError, match="selected provider"):
        config.require_model_run()


def test_model_run_requires_exactly_selected_provider_key() -> None:
    valid = AppConfig.from_environment(
        {
            "CTI_EVAL_PROVIDER": "openai",
            "CTI_EVAL_MODEL": "example-model",
            "OPENAI_API_KEY": "test-only-placeholder",
        }
    )
    assert valid.require_model_run() is valid

    extra_key = AppConfig.from_environment(
        {
            "CTI_EVAL_PROVIDER": "openai",
            "CTI_EVAL_MODEL": "example-model",
            "OPENAI_API_KEY": "test-only-placeholder",
            "ANTHROPIC_API_KEY": "second-test-only-placeholder",
        }
    )
    with pytest.raises(ValueError, match="exactly"):
        extra_key.require_model_run()


def test_safe_serialization_never_contains_secret_values() -> None:
    secret_value = "test-secret-must-not-escape"
    config = AppConfig.from_environment(
        {
            "NVD_API_KEY": secret_value,
            "OPENAI_API_KEY": secret_value,
            "CTI_EVAL_PROVIDER": "openai",
            "CTI_EVAL_MODEL": "example-model",
        }
    )
    safe = config.safe_environment()
    redacted = config.redacted_environment()
    assert secret_value not in repr(safe)
    assert secret_value not in repr(redacted)
    assert set(safe) <= set(AppConfig.SAFE_ENV_NAMES)
    assert redacted["OPENAI_API_KEY"] == "[REDACTED]"
    assert redacted["NVD_API_KEY"] == "[REDACTED]"


def test_known_secret_values_are_redacted_before_logging() -> None:
    secret_value = "log-canary-value"
    config = AppConfig.from_environment(
        {
            "NVD_API_KEY": secret_value,
            "OPENAI_API_KEY": secret_value,
        }
    )
    message = f"request header={secret_value}; query={secret_value}"
    redacted = redact_known_secrets(message, config)
    assert secret_value not in redacted
    assert redacted.count("[REDACTED]") == 2

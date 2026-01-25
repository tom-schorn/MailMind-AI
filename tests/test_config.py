"""Tests for configuration management."""

import os

import pytest

from mailmind.config import ConfigError, load_config


class TestSensitivityToThreshold:
    """Test sensitivity to threshold conversion."""

    def test_sensitivity_1_gives_high_threshold(self, monkeypatch):
        """Sensitivity 1 (relaxed) should give threshold 0.95."""
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_SENSITIVITY", "1")

        config = load_config()
        assert config.spam.threshold == 0.95

    def test_sensitivity_10_gives_low_threshold(self, monkeypatch):
        """Sensitivity 10 (strict) should give threshold 0.50."""
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_SENSITIVITY", "10")

        config = load_config()
        assert config.spam.threshold == pytest.approx(0.50)

    def test_sensitivity_5_gives_middle_threshold(self, monkeypatch):
        """Sensitivity 5 (default) should give threshold 0.75."""
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_SENSITIVITY", "5")

        config = load_config()
        assert config.spam.threshold == 0.75

    def test_invalid_sensitivity_too_low(self, monkeypatch):
        """Sensitivity below 1 should raise error."""
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_SENSITIVITY", "0")

        with pytest.raises(ConfigError):
            load_config()

    def test_invalid_sensitivity_too_high(self, monkeypatch):
        """Sensitivity above 10 should raise error."""
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_SENSITIVITY", "11")

        with pytest.raises(ConfigError):
            load_config()

    def _set_required_env(self, monkeypatch):
        """Set required environment variables."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USER", "user@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("IMAP_SPAM_FOLDER", "Spam")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")


class TestModelSelection:
    """Test Claude model selection."""

    def test_default_model_is_haiku(self, monkeypatch):
        self._set_required_env(monkeypatch)

        config = load_config()
        assert config.spam.model == "haiku"

    def test_valid_models(self, monkeypatch):
        self._set_required_env(monkeypatch)

        for model in ["haiku", "sonnet", "opus"]:
            monkeypatch.setenv("CLAUDE_MODEL", model)
            config = load_config()
            assert config.spam.model == model

    def test_invalid_model(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("CLAUDE_MODEL", "invalid")

        with pytest.raises(ConfigError):
            load_config()

    def test_model_case_insensitive(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("CLAUDE_MODEL", "HAIKU")

        config = load_config()
        assert config.spam.model == "haiku"

    def _set_required_env(self, monkeypatch):
        """Set required environment variables."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USER", "user@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("IMAP_SPAM_FOLDER", "Spam")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")


class TestCustomPrompt:
    """Test custom prompt configuration."""

    def test_default_prompt_is_none(self, monkeypatch):
        self._set_required_env(monkeypatch)

        config = load_config()
        assert config.spam.prompt is None

    def test_standard_prompt_is_none(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_PROMPT", "Standard")

        config = load_config()
        assert config.spam.prompt is None

    def test_custom_prompt(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("SPAM_PROMPT", "You are a custom analyzer...")

        config = load_config()
        assert config.spam.prompt == "You are a custom analyzer..."

    def _set_required_env(self, monkeypatch):
        """Set required environment variables."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USER", "user@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("IMAP_SPAM_FOLDER", "Spam")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")


class TestSSLAutoDetection:
    """Test SSL/STARTTLS auto-detection."""

    def test_port_993_uses_ssl(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("IMAP_PORT", "993")

        config = load_config()
        assert config.imap.use_ssl is True

    def test_port_143_uses_starttls(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("IMAP_PORT", "143")

        config = load_config()
        assert config.imap.use_ssl is False

    def test_explicit_ssl_override(self, monkeypatch):
        self._set_required_env(monkeypatch)
        monkeypatch.setenv("IMAP_PORT", "143")
        monkeypatch.setenv("IMAP_SSL", "true")

        config = load_config()
        assert config.imap.use_ssl is True

    def _set_required_env(self, monkeypatch):
        """Set required environment variables."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USER", "user@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("IMAP_SPAM_FOLDER", "Spam")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

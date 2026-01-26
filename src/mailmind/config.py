"""Configuration management for MailMind-AI."""

import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


@dataclass
class IMAPConfig:
    """IMAP server configuration."""

    host: str
    port: int
    user: str
    password: str
    folder: str
    spam_folder: str
    use_idle: bool
    poll_interval: int
    use_ssl: bool  # True=SSL, False=STARTTLS


@dataclass
class SpamConfig:
    """Spam detection configuration."""

    sensitivity: int  # 1-10 scale
    threshold: float  # Calculated from sensitivity
    prompt: Optional[str]  # Custom prompt or None for default
    model: str  # haiku, sonnet, opus


@dataclass
class Config:
    """Application configuration."""

    imap: IMAPConfig
    anthropic_api_key: str
    spam: SpamConfig
    log_level: str
    log_dir: str
    log_retention_days: int
    analysis_limit: int  # Max emails to analyze on startup (0 = unlimited)


class ConfigError(Exception):
    """Configuration validation error."""

    pass


def _get_required(key: str) -> str:
    """Get required environment variable or raise error."""
    value = os.environ.get(key)
    if not value:
        raise ConfigError(f"Missing required environment variable: {key}")
    return value


def _get_optional(key: str, default: str) -> str:
    """Get optional environment variable with default."""
    return os.environ.get(key, default)


def _get_bool(key: str, default: bool) -> bool:
    """Get boolean environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


def _get_int(key: str, default: int) -> int:
    """Get integer environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ConfigError(f"Invalid integer value for {key}: {value}")


def _get_float(key: str, default: float) -> float:
    """Get float environment variable."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        raise ConfigError(f"Invalid float value for {key}: {value}")


def _get_optional_bool(key: str) -> Optional[bool]:
    """Get optional boolean environment variable."""
    value = os.environ.get(key)
    if value is None:
        return None
    return value.lower() in ("true", "1", "yes")


def load_config() -> Config:
    """Load and validate configuration from environment variables."""
    port = _get_int("IMAP_PORT", 993)

    # Auto-detect SSL based on port if not explicitly set
    use_ssl_env = _get_optional_bool("IMAP_SSL")
    if use_ssl_env is not None:
        use_ssl = use_ssl_env
    else:
        # Port 993 = SSL, Port 143 = STARTTLS
        use_ssl = port == 993

    imap = IMAPConfig(
        host=_get_required("IMAP_HOST"),
        port=port,
        user=_get_required("IMAP_USER"),
        password=_get_required("IMAP_PASSWORD"),
        folder=_get_optional("IMAP_FOLDER", "INBOX"),
        spam_folder=_get_required("IMAP_SPAM_FOLDER"),
        use_idle=_get_bool("IMAP_USE_IDLE", True),
        poll_interval=_get_int("IMAP_POLL_INTERVAL", 60),
        use_ssl=use_ssl,
    )

    # Spam configuration
    sensitivity = _get_int("SPAM_SENSITIVITY", 5)
    if sensitivity < 1 or sensitivity > 10:
        raise ConfigError("SPAM_SENSITIVITY must be between 1 and 10")

    # Convert sensitivity to threshold: 1=0.95 (relaxed), 10=0.50 (strict)
    threshold = 0.95 - (sensitivity - 1) * 0.05

    # Custom prompt (None if "Standard" or not set)
    prompt_value = _get_optional("SPAM_PROMPT", "Standard")
    custom_prompt = None if prompt_value == "Standard" else prompt_value

    # Model selection
    model = _get_optional("CLAUDE_MODEL", "haiku").lower()
    if model not in ("haiku", "sonnet", "opus"):
        raise ConfigError("CLAUDE_MODEL must be haiku, sonnet, or opus")

    spam = SpamConfig(
        sensitivity=sensitivity,
        threshold=threshold,
        prompt=custom_prompt,
        model=model,
    )

    return Config(
        imap=imap,
        anthropic_api_key=_get_required("ANTHROPIC_API_KEY"),
        spam=spam,
        log_level=_get_optional("LOG_LEVEL", "INFO"),
        log_dir=_get_optional("LOG_DIR", "logs"),
        log_retention_days=_get_int("LOG_RETENTION_DAYS", 3),
        analysis_limit=_get_int("ANALYSIS_LIMIT", 50),
    )


def cleanup_old_logs(log_dir: str, days: int) -> None:
    """Delete log files older than N days."""
    cutoff = datetime.now() - timedelta(days=days)
    log_path = Path(log_dir)

    if not log_path.exists():
        return

    for log_file in log_path.glob("*.log*"):
        try:
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
            if mtime < cutoff:
                log_file.unlink()
                logging.info(f"Deleted old log: {log_file.name}")
        except Exception as e:
            logging.warning(f"Could not delete {log_file.name}: {e}")


def setup_logging(
    level: str,
    log_dir: str = "logs",
    retention_days: int = 3
) -> None:
    """Configure logging for the application."""
    from logging.handlers import TimedRotatingFileHandler

    # Create logs directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    # Cleanup old logs
    cleanup_old_logs(log_dir, retention_days)

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Console handler with UTF-8 encoding for Windows
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setStream(open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1))
    console_handler.setFormatter(logging.Formatter(log_format, date_format))

    # File handler with daily rotation
    log_file = Path(log_dir) / f"{datetime.now().strftime('%Y-%m-%d')}.log"
    file_handler = TimedRotatingFileHandler(
        str(log_file),
        when='midnight',
        interval=1,
        backupCount=retention_days,
        encoding='utf-8',
    )
    file_handler.suffix = "%Y-%m-%d"
    file_handler.setFormatter(logging.Formatter(log_format, date_format))

    logging.basicConfig(
        level=numeric_level,
        handlers=[console_handler, file_handler],
    )

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict


class LoggingService:
    """Singleton logging service for centralized logging configuration."""

    _instance: Optional['LoggingService'] = None
    _loggers: Dict[str, logging.Logger] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(LoggingService, cls).__new__(cls)
        return cls._instance

    @classmethod
    def setup(cls, config: dict) -> logging.Logger:
        """
        Setup logging with console and file handlers based on config.

        Args:
            config: Configuration dictionary containing log settings

        Returns:
            Configured logger instance
        """
        log_level = config.get('log_level', 'INFO').upper()
        log_to_file = config.get('log_to_file', True)
        log_file_path = config.get('log_file_path', 'logs/mailmind.log')

        logger = logging.getLogger('MailMind')
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        if logger.hasHandlers():
            logger.handlers.clear()

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_level, logging.INFO))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        if log_to_file:
            log_dir = os.path.dirname(log_file_path)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=100 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_level, logging.INFO))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        cls._loggers['MailMind'] = logger
        return logger

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get or create a logger instance by name.

        Args:
            name: Logger name

        Returns:
            Logger instance
        """
        if name not in cls._loggers:
            cls._loggers[name] = logging.getLogger(name)
        return cls._loggers[name]

    @classmethod
    def set_level(cls, level: str):
        """
        Dynamically change log level for all registered loggers.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        log_level = getattr(logging, level.upper(), logging.INFO)
        for logger in cls._loggers.values():
            logger.setLevel(log_level)
            for handler in logger.handlers:
                handler.setLevel(log_level)

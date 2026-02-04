import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(config: dict) -> logging.Logger:
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

    return logger

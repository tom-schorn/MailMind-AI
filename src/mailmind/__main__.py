"""MailMind-AI entry point."""

import logging
import signal
import sys
from threading import Event

from dotenv import load_dotenv

from .ai.claude import ClaudeAnalyzer
from .config import ConfigError, load_config, setup_logging
from .imap.client import Email, IMAPClient, IMAPError
from .workflow.runner import WorkflowRunner

logger = logging.getLogger(__name__)

# Global stop event for graceful shutdown
stop_event = Event()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info("Shutdown signal received")
    stop_event.set()


def main() -> int:
    """Main entry point."""
    # Load .env file if present
    load_dotenv()

    # Load configuration
    try:
        config = load_config()
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(config.log_level)
    logger.info("MailMind-AI starting")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize components
    imap = IMAPClient(config.imap)
    analyzer = ClaudeAnalyzer(config.anthropic_api_key)
    runner = WorkflowRunner(
        imap,
        analyzer,
        config.imap.spam_folder,
        config.spam_threshold,
    )

    def process_email(email: Email) -> None:
        """Callback for processing new emails."""
        try:
            result = runner.process_email(email)
            if result.is_spam:
                logger.info(
                    f"SPAM detected: {email.subject[:50]} "
                    f"(score: {result.final_score:.2f})"
                )
            else:
                logger.info(
                    f"Legitimate: {email.subject[:50]} "
                    f"(score: {result.final_score:.2f})"
                )
        except Exception as e:
            logger.error(f"Failed to process email {email.uid}: {e}")

    # Connect and start watching
    try:
        imap.connect()
        logger.info(f"Watching folder: {config.imap.folder}")
        imap.watch(process_email, stop_event.is_set)
    except IMAPError as e:
        logger.error(f"IMAP error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    finally:
        imap.disconnect()

    logger.info("MailMind-AI stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

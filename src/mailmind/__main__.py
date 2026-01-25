"""MailMind-AI entry point."""

import logging
import signal
import sys
from threading import Event

from dotenv import load_dotenv

from .ai.claude import ClaudeAnalyzer
from .config import ConfigError, load_config, setup_logging
from .imap.client import Email, IMAPClient, IMAPError
from .logging_format import console
from .state import StateManager
from .workflow.runner import WorkflowRunner

logger = logging.getLogger(__name__)

# Global stop event for graceful shutdown
stop_event = Event()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print("\n Shutdown signal received")
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
    console.info("MailMind-AI starting")

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize state manager
    state = StateManager()

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
        # Skip if already analyzed
        if state.is_analyzed(email.uid):
            return

        try:
            runner.process_email(email)
            state.mark_analyzed(email.uid)
        except Exception as e:
            console.error(f"Failed to process email {email.uid}: {e}")

    # Connect and start watching
    try:
        imap.connect()
        imap.select_folder()

        # Process unanalyzed emails (limited to most recent)
        console.status("Checking for unanalyzed emails...")
        all_uids = imap.get_all_uids()
        unanalyzed = [uid for uid in all_uids if not state.is_analyzed(uid)]

        # Apply limit (0 = unlimited), take most recent (last in list)
        limit = config.analysis_limit
        if limit > 0 and len(unanalyzed) > limit:
            console.status(f"Found {len(unanalyzed)} unanalyzed, limiting to {limit} most recent")
            unanalyzed = unanalyzed[-limit:]
            # Mark older ones as analyzed to skip them
            for uid in all_uids:
                if uid not in unanalyzed and not state.is_analyzed(uid):
                    state.mark_analyzed(uid)
        else:
            console.status(f"Found {len(unanalyzed)} unanalyzed emails")

        for uid in unanalyzed:
            if stop_event.is_set():
                break
            email = imap.fetch_email(uid)
            process_email(email)

        # Then watch for new emails
        if not stop_event.is_set():
            console.info(f"Watching folder: {config.imap.folder}")
            imap.watch(process_email, stop_event.is_set)

    except IMAPError as e:
        console.error(f"IMAP error: {e}")
        return 1
    except Exception as e:
        console.error(f"Unexpected error: {e}")
        return 1
    finally:
        imap.disconnect()

    console.info("MailMind-AI stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

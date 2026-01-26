"""Monitor spam folder for user-initiated moves."""

import logging
from typing import Dict, Set, TYPE_CHECKING

from .imap.client import IMAPClient
from .lists import DomainLists
from .logging_format import console
from .ai.claude import SpamCategory

if TYPE_CHECKING:
    from .ai.claude import ClaudeAnalyzer
    from .workflow.spam_handler import SpamHandler
    from .state import StateManager

logger = logging.getLogger(__name__)


class SpamFolderMonitor:
    """Monitor spam folder for learning opportunities.

    Detects:
    - Emails moved TO spam by user (other clients) → blacklist sender
    - Emails moved FROM spam by user → whitelist sender
    """

    def __init__(
        self,
        imap_client: IMAPClient,
        spam_folder: str,
        domain_lists: DomainLists,
        analyzer: "ClaudeAnalyzer" = None,
        spam_handler: "SpamHandler" = None,
        state: "StateManager" = None,
    ):
        self.imap = imap_client
        self.spam_folder = spam_folder
        self.domain_lists = domain_lists
        self.analyzer = analyzer
        self.spam_handler = spam_handler
        self.state = state
        self._spam_senders: Dict[str, str] = {}  # uid -> sender
        self._our_moves: Set[str] = set()  # UIDs we moved to spam

    def record_our_move(self, uid: str) -> None:
        """Record that we moved this email to spam."""
        self._our_moves.add(uid)

    def initial_scan(self) -> None:
        """Scan spam folder on startup to establish baseline."""
        try:
            self.imap.select_folder(self.spam_folder)
            uids = self.imap.get_all_uids()

            # Store sender for each email for later whitelist learning
            for uid in uids:
                try:
                    email = self.imap.fetch_email(uid)
                    self._spam_senders[uid] = email.sender
                except Exception:
                    pass

            console.status(f"Spam folder: {len(uids)} existing emails tracked")
            # Re-select inbox
            self.imap.select_folder()
        except Exception as e:
            logger.warning(f"Could not scan spam folder: {e}")

    def categorize_existing_spam(self) -> None:
        """Scan spam folder and categorize all uncategorized emails."""
        if not self.analyzer or not self.spam_handler or not self.state:
            logger.warning("Spam categorization disabled - missing dependencies")
            return

        console.print("\n[cyan]📂 Scanning spam folder for categorization...[/cyan]")

        try:
            # Select spam folder
            self.imap.select_folder(self.spam_folder)
            spam_uids = self.imap.get_all_uids()

            if not spam_uids:
                console.print("[dim]No emails in spam folder[/dim]")
                self.imap.select_folder()
                return

            categorized = 0
            skipped = 0

            for uid in spam_uids:
                # Skip if already processed
                if self.state.is_analyzed(uid):
                    skipped += 1
                    continue

                try:
                    email = self.imap.fetch_email(uid)

                    # Quick category determination (content analysis only)
                    category = self._analyze_for_category(email)

                    # Move to subfolder
                    if category != SpamCategory.UNKNOWN and category != SpamCategory.LEGITIMATE:
                        self.spam_handler.move_to_spam(email, category)
                        categorized += 1

                    # Mark as processed
                    self.state.mark_analyzed(uid)

                except Exception as e:
                    logger.error(f"Failed to categorize spam {uid}: {e}")

            console.print(
                f"[green]✓[/green] Categorized {categorized} emails, skipped {skipped}"
            )

            # Return to inbox
            self.imap.select_folder()

        except Exception as e:
            logger.error(f"Spam categorization failed: {e}")
            try:
                self.imap.select_folder()
            except Exception:
                pass

    def _analyze_for_category(self, email) -> SpamCategory:
        """Analyze email content to determine spam category."""
        try:
            # Use only content analysis for speed (1 API call instead of 4)
            result = self.analyzer.analyze_content(
                email.subject, email.body_text or email.body_html or ""
            )
            return result.category if result.category else SpamCategory.UNKNOWN
        except Exception as e:
            logger.error(f"Category analysis failed: {e}")
            return SpamCategory.UNKNOWN

    def check_for_changes(self) -> None:
        """Check spam folder for user-initiated changes."""
        try:
            # Temporarily select spam folder
            self.imap.select_folder(self.spam_folder)
            current_uids = set(self.imap.get_all_uids())
            known_uids = set(self._spam_senders.keys())

            # Find new emails (moved to spam by user)
            new_in_spam = current_uids - known_uids - self._our_moves
            for uid in new_in_spam:
                self._handle_user_spam_move(uid)

            # Find removed emails (moved from spam by user)
            removed_from_spam = known_uids - current_uids
            for uid in removed_from_spam:
                self._handle_user_unspam_move(uid)

            # Update our_moves set
            self._our_moves = self._our_moves & current_uids

            # Re-select inbox
            self.imap.select_folder()

        except Exception as e:
            logger.warning(f"Spam folder check failed: {e}")
            try:
                self.imap.select_folder()
            except Exception:
                pass

    def _handle_user_spam_move(self, uid: str) -> None:
        """Handle email moved to spam by user - blacklist sender."""
        try:
            email = self.imap.fetch_email(uid)
            self._spam_senders[uid] = email.sender
            self.domain_lists.blacklist(email.sender)
            domain = DomainLists.extract_domain(email.sender)
            console.status(f"  >> Learned: blacklisted {domain}")
        except Exception as e:
            logger.warning(f"Could not process spam move for {uid}: {e}")

    def _handle_user_unspam_move(self, uid: str) -> None:
        """Handle email moved from spam by user - whitelist sender."""
        sender = self._spam_senders.pop(uid, None)
        if sender:
            self.domain_lists.whitelist(sender)
            domain = DomainLists.extract_domain(sender)
            console.status(f"  >> Learned: whitelisted {domain}")

"""Monitor spam folder for user-initiated moves."""

import logging
from typing import Dict, Set, TYPE_CHECKING

from .imap.client import IMAPClient, IMAPError
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

    def categorize_existing_spam(self, limit: int = 0) -> None:
        """Scan spam folder and categorize all uncategorized emails."""
        if not self.analyzer or not self.spam_handler or not self.state:
            logger.warning("Spam categorization disabled - missing dependencies")
            return

        console.status("\n📂 Scanning spam folder for categorization...")

        try:
            # Select spam folder
            self.imap.select_folder(self.spam_folder)

            categorized = 0
            skipped = 0
            total_limit = limit  # Store original limit

            # Process emails one by one, refreshing UID list after each move to avoid stale UIDs
            while True:
                # Get current UIDs in spam folder
                spam_uids = self.imap.get_all_uids()

                # Filter unanalyzed
                unanalyzed = [uid for uid in spam_uids if not self.state.is_analyzed(uid)]

                # Check if we reached limit or no more emails
                if not unanalyzed:
                    break
                if total_limit > 0 and categorized >= total_limit:
                    break

                # Apply limit to remaining count
                if total_limit > 0:
                    remaining = total_limit - categorized
                    if len(unanalyzed) > remaining:
                        console.status(f"Found {len(unanalyzed)} unanalyzed spam, limiting to {remaining} more")
                        unanalyzed = unanalyzed[-remaining:]  # Most recent

                # Process only the first email, then refresh UID list
                uid = unanalyzed[0]

                try:
                    email = self.imap.fetch_email(uid)
                except IMAPError as e:
                    # UID no longer exists (moved/deleted by concurrent operation)
                    if "Failed to fetch email" in str(e):
                        logger.debug(f"Email {uid} no longer exists, skipping")
                        # Mark as analyzed to avoid reprocessing
                        self.state.mark_analyzed(uid)
                        continue
                    else:
                        logger.error(f"Failed to fetch spam {uid}: {e}")
                        continue
                except Exception as e:
                    logger.error(f"Failed to categorize spam {uid}: {e}")
                    continue

                try:
                    category = self._analyze_for_category(email)

                    if category != SpamCategory.UNKNOWN and category != SpamCategory.LEGITIMATE:
                        # Clear category: move to category folder and mark as analyzed
                        self.spam_handler.move_to_spam(email, category)
                        self.state.mark_analyzed(uid)
                        categorized += 1
                    elif category == SpamCategory.UNKNOWN:
                        # UNKNOWN: move to Spam/Unknown folder and mark as analyzed
                        self.spam_handler.move_to_spam(email, SpamCategory.UNKNOWN)
                        self.state.mark_analyzed(uid)
                        categorized += 1
                    else:
                        # LEGITIMATE: do not mark as analyzed, will be reanalyzed next time
                        skipped += 1
                        logger.debug(f"Skipped email {uid} (category: {category})")

                except Exception as e:
                    logger.error(f"Failed to process spam {uid}: {e}")
                    # Continue to next email even if processing failed

            console.status(
                f"✓ Categorized {categorized} emails, skipped {skipped}"
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

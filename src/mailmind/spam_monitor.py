"""Monitor spam folder for user-initiated moves."""

import logging
from typing import Dict, Set

from .imap.client import IMAPClient
from .lists import DomainLists
from .logging_format import console

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
    ):
        self.imap = imap_client
        self.spam_folder = spam_folder
        self.domain_lists = domain_lists
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

import logging
from dataclasses import dataclass
from datetime import datetime
from email.message import Message
from typing import Callable, Optional
import time

from imap_tools import MailBox, AND, MailMessage

from Entities import EmailCredential


@dataclass
class EmailMessage:
    """Dataclass representing a parsed email message."""
    uid: str
    subject: str
    sender: str
    recipients: list[str]
    date: datetime
    headers: dict[str, str]
    body_text: str
    body_html: str
    raw_message: MailMessage


class IMAPClient:
    """IMAP client wrapper using imap-tools library."""

    def __init__(self, credential: EmailCredential, config: dict, logger: logging.Logger):
        """
        Initialize IMAP client.

        Args:
            credential: EmailCredential entity from database
            config: Configuration dictionary
            logger: Logger instance
        """
        self.credential = credential
        self.config = config
        self.logger = logger
        self.mailbox: Optional[MailBox] = None
        self.connected = False

    def connect(self) -> None:
        """Establish IMAP connection."""
        try:
            self.logger.info(f"Connecting to IMAP server {self.credential.host}:{self.credential.port}")

            if self.credential.use_ssl:
                self.mailbox = MailBox(self.credential.host, self.credential.port)
                self.mailbox.login(self.credential.username, self.credential.password, initial_folder='INBOX')
            elif self.credential.use_tls:
                from imap_tools import MailBoxStartTls
                self.mailbox = MailBoxStartTls(self.credential.host, self.credential.port)
                self.mailbox.login(self.credential.username, self.credential.password, initial_folder='INBOX')
            else:
                from imap_tools import MailBoxUnencrypted
                self.mailbox = MailBoxUnencrypted(self.credential.host, self.credential.port)
                self.mailbox.login(self.credential.username, self.credential.password, initial_folder='INBOX')

            self.connected = True
            self.logger.info(f"Successfully connected to {self.credential.email_address}")

        except Exception as e:
            self.connected = False
            self.logger.error(f"Failed to connect to IMAP: {e}")
            raise

    def disconnect(self) -> None:
        """Close IMAP connection."""
        if self.mailbox and self.connected:
            try:
                self.mailbox.logout()
                self.connected = False
                self.logger.info(f"Disconnected from {self.credential.email_address}")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")

    def fetch_email(self, uid: str) -> EmailMessage:
        """
        Fetch and parse a single email by UID.

        Args:
            uid: Email UID

        Returns:
            EmailMessage dataclass
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            for msg in self.mailbox.fetch(AND(uid=uid)):
                headers = {k: v for k, v in msg.headers.items()}

                return EmailMessage(
                    uid=msg.uid,
                    subject=msg.subject or "",
                    sender=msg.from_ or "",
                    recipients=msg.to or [],
                    date=msg.date or datetime.now(),
                    headers=headers,
                    body_text=msg.text or "",
                    body_html=msg.html or "",
                    raw_message=msg
                )

            raise ValueError(f"Email with UID {uid} not found")

        except Exception as e:
            self.logger.error(f"Failed to fetch email {uid}: {e}")
            raise

    def get_all_uids(self, folder: str = "INBOX", limit: int = 0) -> list[str]:
        """
        Get all UIDs in folder.

        Args:
            folder: Folder name (default: INBOX)
            limit: Maximum number of UIDs to return (0 = no limit)

        Returns:
            List of UIDs
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.folder.set(folder)
            uids = []

            for msg in self.mailbox.fetch(AND(all=True), mark_seen=False, reverse=True):
                uids.append(msg.uid)
                if limit > 0 and len(uids) >= limit:
                    break

            self.logger.debug(f"Found {len(uids)} emails in {folder}")
            return uids

        except Exception as e:
            self.logger.error(f"Failed to get UIDs from {folder}: {e}")
            raise

    def get_unseen_uids(self, folder: str = "INBOX") -> list[str]:
        """
        Get only unseen/new email UIDs.

        Args:
            folder: Folder name (default: INBOX)

        Returns:
            List of unseen UIDs
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.folder.set(folder)
            uids = []

            for msg in self.mailbox.fetch(AND(seen=False), mark_seen=False):
                uids.append(msg.uid)

            self.logger.debug(f"Found {len(uids)} unseen emails in {folder}")
            return uids

        except Exception as e:
            self.logger.error(f"Failed to get unseen UIDs from {folder}: {e}")
            raise

    def move_to_folder(self, uid: str, folder: str) -> None:
        """Move email to another folder."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.move(uid, folder)
            self.logger.debug(f"Moved email {uid} to {folder}")
        except Exception as e:
            self.logger.error(f"Failed to move email {uid} to {folder}: {e}")
            raise

    def copy_to_folder(self, uid: str, folder: str) -> None:
        """Copy email to another folder."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.copy(uid, folder)
            self.logger.debug(f"Copied email {uid} to {folder}")
        except Exception as e:
            self.logger.error(f"Failed to copy email {uid} to {folder}: {e}")
            raise

    def mark_as_read(self, uid: str) -> None:
        """Mark email as read."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.flag(uid, ['\\Seen'], True)
            self.logger.debug(f"Marked email {uid} as read")
        except Exception as e:
            self.logger.error(f"Failed to mark email {uid} as read: {e}")
            raise

    def mark_as_unread(self, uid: str) -> None:
        """Mark email as unread."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.flag(uid, ['\\Seen'], False)
            self.logger.debug(f"Marked email {uid} as unread")
        except Exception as e:
            self.logger.error(f"Failed to mark email {uid} as unread: {e}")
            raise

    def add_flag(self, uid: str, flag: str) -> None:
        """Add custom flag to email."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.flag(uid, [flag], True)
            self.logger.debug(f"Added flag {flag} to email {uid}")
        except Exception as e:
            self.logger.error(f"Failed to add flag {flag} to email {uid}: {e}")
            raise

    def delete_email(self, uid: str) -> None:
        """Delete email (move to trash or permanent delete)."""
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            self.mailbox.delete(uid)
            self.logger.debug(f"Deleted email {uid}")
        except Exception as e:
            self.logger.error(f"Failed to delete email {uid}: {e}")
            raise

    def watch(self, callback: Callable, stop_check: Callable) -> None:
        """
        Watch for new emails using IDLE or polling.

        Args:
            callback: Function to call with new email UID
            stop_check: Function returning True when watching should stop
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        use_idle = self.config.get('service', {}).get('use_imap_idle', True)
        poll_interval = self.config.get('service', {}).get('imap_poll_interval', 60)

        self.logger.info(f"Starting email watch (mode: {'IDLE' if use_idle else 'POLLING'})")

        try:
            if use_idle:
                self._watch_idle(callback, stop_check)
            else:
                self._watch_polling(callback, stop_check, poll_interval)

        except Exception as e:
            self.logger.error(f"Error in watch loop: {e}")
            raise

    def _watch_idle(self, callback: Callable, stop_check: Callable) -> None:
        """Watch using IMAP IDLE command."""
        self.mailbox.folder.set('INBOX')
        last_uids = set(self.get_all_uids())

        while not stop_check():
            try:
                responses = self.mailbox.idle.wait(timeout=30)

                if responses:
                    current_uids = set(self.get_all_uids())
                    new_uids = current_uids - last_uids

                    for uid in new_uids:
                        self.logger.info(f"New email detected: {uid}")
                        callback(uid)

                    last_uids = current_uids

            except Exception as e:
                self.logger.error(f"Error in IDLE watch: {e}")
                time.sleep(5)

    def _watch_polling(self, callback: Callable, stop_check: Callable, interval: int) -> None:
        """Watch using polling."""
        self.mailbox.folder.set('INBOX')
        last_uids = set(self.get_all_uids())

        while not stop_check():
            try:
                time.sleep(interval)

                current_uids = set(self.get_all_uids())
                new_uids = current_uids - last_uids

                for uid in new_uids:
                    self.logger.info(f"New email detected: {uid}")
                    callback(uid)

                last_uids = current_uids

            except Exception as e:
                self.logger.error(f"Error in polling watch: {e}")
                time.sleep(5)

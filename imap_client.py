import logging
from dataclasses import dataclass
from datetime import datetime
from email.message import Message
from typing import Callable, Optional
import time
import socket
import errno

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

    def reconnect(self) -> None:
        """Reconnect to IMAP server after connection loss."""
        self.logger.warning("Connection lost, attempting to reconnect...")
        try:
            if self.mailbox:
                try:
                    self.mailbox.logout()
                except:
                    pass
            self.connected = False
            self.connect()
            self.logger.info("Reconnection successful")
        except Exception as e:
            self.logger.error(f"Reconnection failed: {e}")
            raise

    def list_folders(self) -> list[dict]:
        """
        List all IMAP folders.

        Returns:
            List of folder dicts: [{'name': 'INBOX', 'flags': [...], 'delim': '/'}, ...]
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            folders = []
            for folder in self.mailbox.folder.list():
                folders.append({
                    'name': folder.name,
                    'flags': folder.flags,
                    'delim': folder.delim
                })
            self.logger.debug(f"Found {len(folders)} folders")
            return folders
        except Exception as e:
            self.logger.error(f"Failed to list folders: {e}")
            raise

    def create_folder(self, folder_name: str) -> bool:
        """
        Create IMAP folder if it doesn't exist.

        Args:
            folder_name: Folder path (e.g., 'INBOX/Processed')

        Returns:
            True if created or already exists
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        try:
            existing_folders = [f['name'] for f in self.list_folders()]
            if folder_name in existing_folders:
                self.logger.debug(f"Folder '{folder_name}' already exists")
                return True

            self.mailbox.folder.create(folder_name)
            self.logger.info(f"Created folder '{folder_name}'")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create folder '{folder_name}': {e}")
            raise

    def folder_exists(self, folder_name: str) -> bool:
        """Check if folder exists."""
        try:
            existing_folders = [f['name'] for f in self.list_folders()]
            return folder_name in existing_folders
        except Exception as e:
            self.logger.error(f"Failed to check folder existence: {e}")
            return False

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
            self.logger.debug(f"Fetching email UID {uid}")
            for msg in self.mailbox.fetch(AND(uid=uid), mark_seen=False):
                self.logger.debug(f"Parsing email: {msg.subject[:50] if msg.subject else 'No subject'}")
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
        Get all UIDs in folder with auto-reconnect on broken pipe.

        Args:
            folder: Folder name (default: INBOX)
            limit: Maximum number of UIDs to return (0 = no limit)

        Returns:
            List of UIDs
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        max_retries = 2
        for attempt in range(max_retries):
            try:
                self.mailbox.folder.set(folder)
                uids = []

                for msg in self.mailbox.fetch(AND(all=True), mark_seen=False, reverse=True):
                    uids.append(msg.uid)
                    if limit > 0 and len(uids) >= limit:
                        break

                self.logger.debug(f"Found {len(uids)} emails in {folder}")
                return uids

            except (socket.error, OSError) as e:
                if hasattr(e, 'errno') and e.errno in (errno.EPIPE, errno.ECONNRESET):
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Socket error (broken pipe), reconnecting... (attempt {attempt + 1}/{max_retries})")
                        self.reconnect()
                        continue
                self.logger.error(f"Failed to get UIDs from {folder}: {e}")
                raise
            except Exception as e:
                self.logger.error(f"Failed to get UIDs from {folder}: {e}")
                raise

        raise ConnectionError("Failed to get UIDs after reconnection attempts")

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

    def watch(self, callback: Callable, stop_check: Callable, folder: str = "INBOX") -> None:
        """
        Watch for new emails using IDLE or polling.

        Args:
            callback: Function to call with new email UID
            stop_check: Function returning True when watching should stop
            folder: Folder to monitor (default: INBOX)
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        use_idle = self.config.get('service', {}).get('use_imap_idle', True)
        poll_interval = self.config.get('service', {}).get('imap_poll_interval', 60)

        self.logger.info(f"Starting email watch (mode: {'IDLE' if use_idle else 'POLLING'})")

        try:
            if use_idle:
                self._watch_idle(callback, stop_check, folder)
            else:
                self._watch_polling(callback, stop_check, folder, poll_interval)

        except Exception as e:
            self.logger.error(f"Error in watch loop: {e}")
            raise

    def _watch_idle(self, callback: Callable, stop_check: Callable, folder: str = 'INBOX') -> None:
        """Watch using IMAP IDLE command with auto-reconnect."""
        self.mailbox.folder.set(folder)
        last_uids = set(self.get_all_uids(folder))

        while not stop_check():
            try:
                responses = self.mailbox.idle.wait(timeout=30)

                if responses:
                    current_uids = set(self.get_all_uids(folder))
                    new_uids = current_uids - last_uids

                    for uid in new_uids:
                        self.logger.info(f"New email detected: {uid}")
                        callback(uid)

                    last_uids = current_uids

            except (socket.error, OSError) as e:
                if hasattr(e, 'errno') and e.errno in (errno.EPIPE, errno.ECONNRESET):
                    self.logger.warning("Socket error in IDLE watch, reconnecting...")
                    try:
                        self.reconnect()
                        self.mailbox.folder.set(folder)
                        last_uids = set(self.get_all_uids(folder))
                    except Exception as reconnect_error:
                        self.logger.error(f"Reconnection failed: {reconnect_error}")
                        time.sleep(5)
                else:
                    self.logger.error(f"Socket error in IDLE watch: {e}")
                    time.sleep(5)
            except Exception as e:
                self.logger.error(f"Error in IDLE watch: {e}")
                time.sleep(5)

    def _watch_polling(self, callback: Callable, stop_check: Callable, folder: str = 'INBOX', interval: int = 60) -> None:
        """Watch using polling with auto-reconnect on broken pipe."""
        self.mailbox.folder.set(folder)
        last_uids = set(self.get_all_uids(folder))

        while not stop_check():
            try:
                # Send NOOP to keep connection alive before sleeping
                try:
                    self.mailbox.client.noop()
                except:
                    pass

                time.sleep(interval)

                current_uids = set(self.get_all_uids(folder))
                new_uids = current_uids - last_uids

                for uid in new_uids:
                    self.logger.info(f"New email detected: {uid}")
                    callback(uid)

                last_uids = current_uids

            except (socket.error, OSError) as e:
                if hasattr(e, 'errno') and e.errno in (errno.EPIPE, errno.ECONNRESET):
                    self.logger.warning("Socket error in polling watch, reconnecting...")
                    try:
                        self.reconnect()
                        self.mailbox.folder.set(folder)
                        last_uids = set(self.get_all_uids(folder))
                    except Exception as reconnect_error:
                        self.logger.error(f"Reconnection failed: {reconnect_error}")
                        time.sleep(5)
                else:
                    self.logger.error(f"Socket error in polling watch: {e}")
                    time.sleep(5)
            except Exception as e:
                self.logger.error(f"Error in polling watch: {e}")
                time.sleep(5)

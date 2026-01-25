"""IMAP client with IDLE support and polling fallback."""

import email
import imaplib
import logging
import time
from dataclasses import dataclass
from email.header import decode_header
from email.message import Message
from typing import Callable, Iterator, Optional

from ..config import IMAPConfig

logger = logging.getLogger(__name__)


@dataclass
class Email:
    """Parsed email data."""

    uid: str
    subject: str
    sender: str
    headers: dict[str, str]
    body_text: str
    body_html: str
    raw_message: Message


class IMAPError(Exception):
    """IMAP operation error."""

    pass


class IMAPClient:
    """IMAP client with IDLE and polling support."""

    def __init__(self, config: IMAPConfig):
        self.config = config
        self._connection: Optional[imaplib.IMAP4] = None
        self._supports_idle: Optional[bool] = None

    def connect(self) -> None:
        """Connect to IMAP server."""
        logger.info(
            f"Connecting to {self.config.host}:{self.config.port} "
            f"(SSL={self.config.use_ssl})"
        )
        try:
            if self.config.use_ssl:
                # Direct SSL connection (port 993)
                self._connection = imaplib.IMAP4_SSL(
                    self.config.host, self.config.port
                )
            else:
                # Plain connection with STARTTLS (port 143)
                self._connection = imaplib.IMAP4(
                    self.config.host, self.config.port
                )
                self._connection.starttls()

            self._connection.login(self.config.user, self.config.password)
            logger.info("Connected successfully")

            # Check IDLE capability
            self._supports_idle = self._check_idle_support()
            if self._supports_idle:
                logger.info("Server supports IDLE")
            else:
                logger.info("Server does not support IDLE, using polling")

        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to connect: {e}")

    def disconnect(self) -> None:
        """Disconnect from IMAP server."""
        if self._connection:
            try:
                self._connection.logout()
            except Exception:
                pass
            self._connection = None
            logger.info("Disconnected")

    def _check_idle_support(self) -> bool:
        """Check if server supports IDLE command."""
        if not self._connection:
            return False
        try:
            capabilities = self._connection.capability()[1][0].decode()
            return "IDLE" in capabilities.upper()
        except Exception:
            return False

    def select_folder(self, folder: Optional[str] = None) -> int:
        """Select mailbox folder. Returns message count."""
        if not self._connection:
            raise IMAPError("Not connected")

        folder = folder or self.config.folder
        try:
            status, data = self._connection.select(folder)
            if status != "OK":
                raise IMAPError(f"Failed to select folder: {folder}")
            count = int(data[0])
            logger.debug(f"Selected folder {folder} with {count} messages")
            return count
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to select folder {folder}: {e}")

    def get_unseen_uids(self) -> list[str]:
        """Get UIDs of unseen messages."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            status, data = self._connection.uid("SEARCH", None, "UNSEEN")
            if status != "OK":
                raise IMAPError("Failed to search for unseen messages")

            uids = data[0].decode().split() if data[0] else []
            logger.debug(f"Found {len(uids)} unseen messages")
            return uids
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to search messages: {e}")

    def get_all_uids(self) -> list[str]:
        """Get UIDs of all messages in current folder."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            status, data = self._connection.uid("SEARCH", None, "ALL")
            if status != "OK":
                raise IMAPError("Failed to search for all messages")

            uids = data[0].decode().split() if data[0] else []
            logger.debug(f"Found {len(uids)} total messages")
            return uids
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to search messages: {e}")

    def fetch_email(self, uid: str) -> Email:
        """Fetch and parse email by UID."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            status, data = self._connection.uid("FETCH", uid, "(RFC822)")
            if status != "OK" or not data or not data[0]:
                raise IMAPError(f"Failed to fetch email {uid}")

            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            return Email(
                uid=uid,
                subject=self._decode_header(msg.get("Subject", "")),
                sender=self._decode_header(msg.get("From", "")),
                headers=self._extract_headers(msg),
                body_text=self._get_body(msg, "text/plain"),
                body_html=self._get_body(msg, "text/html"),
                raw_message=msg,
            )
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to fetch email {uid}: {e}")

    def _decode_header(self, header: str) -> str:
        """Decode email header."""
        if not header:
            return ""
        decoded_parts = decode_header(header)
        result = []
        for content, charset in decoded_parts:
            if isinstance(content, bytes):
                charset = charset or "utf-8"
                try:
                    content = content.decode(charset)
                except (UnicodeDecodeError, LookupError):
                    content = content.decode("utf-8", errors="replace")
            result.append(content)
        return "".join(result)

    def _extract_headers(self, msg: Message) -> dict[str, str]:
        """Extract relevant headers from message."""
        headers = {}
        relevant_headers = [
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "Return-Path",
            "Received",
            "Authentication-Results",
            "DKIM-Signature",
            "Received-SPF",
            "ARC-Authentication-Results",
        ]
        for header in relevant_headers:
            value = msg.get(header)
            if value:
                headers[header] = self._decode_header(value)
        return headers

    def _get_body(self, msg: Message, content_type: str) -> str:
        """Extract body content of specified type."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == content_type:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            return payload.decode(charset)
                        except (UnicodeDecodeError, LookupError):
                            return payload.decode("utf-8", errors="replace")
        else:
            if msg.get_content_type() == content_type:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        return payload.decode(charset)
                    except (UnicodeDecodeError, LookupError):
                        return payload.decode("utf-8", errors="replace")
        return ""

    def move_to_folder(self, uid: str, folder: str) -> None:
        """Move email to specified folder."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            # Copy to destination
            status, _ = self._connection.uid("COPY", uid, folder)
            if status != "OK":
                raise IMAPError(f"Failed to copy email to {folder}")

            # Mark original as deleted
            self._connection.uid("STORE", uid, "+FLAGS", "\\Deleted")
            self._connection.expunge()

            logger.info(f"Moved email {uid} to {folder}")
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to move email {uid}: {e}")

    def create_folder(self, folder: str) -> None:
        """Create mailbox folder if it doesn't exist."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            # Check if folder exists
            status, _ = self._connection.select(folder)
            if status == "OK":
                # Folder exists, re-select original folder
                self._connection.select(self.config.folder)
                return

        except imaplib.IMAP4.error:
            pass  # Folder doesn't exist, create it

        try:
            self._connection.create(folder)
            logger.info(f"Created folder: {folder}")
            # Re-select original folder
            self._connection.select(self.config.folder)
        except imaplib.IMAP4.error as e:
            # Folder might already exist (race condition)
            logger.debug(f"Could not create folder {folder}: {e}")
            self._connection.select(self.config.folder)

    def update_email(self, uid: str, new_subject: str, new_body: str) -> None:
        """Update email subject and body by replacing the message."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            # Fetch original message
            email_data = self.fetch_email(uid)
            msg = email_data.raw_message

            # Update subject
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = new_subject

            # Update body - create new message with modified body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        part.set_payload(new_body.encode("utf-8"))
                        break
                    elif part.get_content_type() == "text/plain":
                        part.set_payload(new_body.encode("utf-8"))
            else:
                msg.set_payload(new_body.encode("utf-8"))

            # Append modified message
            status, _ = self._connection.append(
                self.config.folder,
                "\\Seen",
                None,
                msg.as_bytes(),
            )
            if status != "OK":
                raise IMAPError("Failed to append modified message")

            # Delete original
            self._connection.uid("STORE", uid, "+FLAGS", "\\Deleted")
            self._connection.expunge()

            logger.info(f"Updated email {uid}")
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to update email {uid}: {e}")

    def modify_and_move_to_spam(
        self, email_obj: Email, new_subject: str, new_body: str, spam_folder: str
    ) -> None:
        """Modify email and move it to spam folder in one operation."""
        if not self._connection:
            raise IMAPError("Not connected")

        try:
            msg = email_obj.raw_message

            # Update subject
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = new_subject

            # Update body
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        part.set_payload(new_body.encode("utf-8"))
                        break
                    elif part.get_content_type() == "text/plain":
                        part.set_payload(new_body.encode("utf-8"))
            else:
                msg.set_payload(new_body.encode("utf-8"))

            # Append modified message directly to spam folder
            status, _ = self._connection.append(
                spam_folder,
                "\\Seen",
                None,
                msg.as_bytes(),
            )
            if status != "OK":
                raise IMAPError(f"Failed to append message to {spam_folder}")

            # Delete original from inbox
            self._connection.uid("STORE", email_obj.uid, "+FLAGS", "\\Deleted")
            self._connection.expunge()

            logger.info(f"Modified and moved email {email_obj.uid} to {spam_folder}")
        except imaplib.IMAP4.error as e:
            raise IMAPError(f"Failed to modify and move email {email_obj.uid}: {e}")

    def watch(
        self, callback: Callable[[Email], None], stop_check: Callable[[], bool]
    ) -> None:
        """Watch for new emails using IDLE or polling."""
        self.select_folder()

        # Remember existing unseen emails - don't process them
        known_uids = set(self.get_unseen_uids())
        logger.info(f"Ignoring {len(known_uids)} existing unseen emails")

        if self.config.use_idle and self._supports_idle:
            self._watch_idle(callback, stop_check, known_uids)
        else:
            self._watch_poll(callback, stop_check, known_uids)

    def _watch_idle(
        self,
        callback: Callable[[Email], None],
        stop_check: Callable[[], bool],
        known_uids: set[str],
    ) -> None:
        """Watch for new emails using IDLE."""
        logger.info("Starting IDLE watch (only new emails)")

        while not stop_check():
            try:
                # Process only NEW unseen emails
                for uid in self.get_unseen_uids():
                    if uid not in known_uids:
                        known_uids.add(uid)
                        email_data = self.fetch_email(uid)
                        callback(email_data)

                # Enter IDLE mode
                self._connection.send(b"a001 IDLE\r\n")

                # Wait for response (with timeout)
                response = self._connection.readline()
                if b"EXISTS" in response or b"RECENT" in response:
                    # New message arrived
                    self._connection.send(b"DONE\r\n")
                    self._connection.readline()  # Read OK response
                elif stop_check():
                    self._connection.send(b"DONE\r\n")
                    self._connection.readline()
                    break
                else:
                    # Timeout or other response, restart IDLE
                    self._connection.send(b"DONE\r\n")
                    self._connection.readline()

            except Exception as e:
                logger.error(f"IDLE error: {e}, reconnecting...")
                self.disconnect()
                time.sleep(5)
                self.connect()
                self.select_folder()

    def _watch_poll(
        self,
        callback: Callable[[Email], None],
        stop_check: Callable[[], bool],
        known_uids: set[str],
    ) -> None:
        """Watch for new emails using polling."""
        logger.info(
            f"Starting polling watch (interval: {self.config.poll_interval}s, only new emails)"
        )

        while not stop_check():
            try:
                # Process only NEW unseen emails
                for uid in self.get_unseen_uids():
                    if uid not in known_uids:
                        known_uids.add(uid)
                        email_data = self.fetch_email(uid)
                        callback(email_data)

                time.sleep(self.config.poll_interval)

            except Exception as e:
                logger.error(f"Polling error: {e}, reconnecting...")
                self.disconnect()
                time.sleep(5)
                self.connect()
                self.select_folder()

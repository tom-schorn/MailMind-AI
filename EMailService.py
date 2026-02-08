import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional, Dict, Tuple
import socket
import errno
import imaplib
import ssl

from imap_tools import MailBox, AND, MailMessage
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from config_manager import load_config
from LoggingService import LoggingService
from utils import get_database_url
from DatabaseService import EmailCredential, EmailRule, RuleCondition, RuleAction, ProcessedEmail, EmailRuleApplication


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
                except Exception as e:
                    self.logger.debug(f"Logout during reconnect failed: {e}")
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

    def get_flags(self, folder: str = 'INBOX') -> list[str]:
        """
        Scan messages and collect custom IMAP flags.

        Args:
            folder: Folder to scan

        Returns:
            Sorted, deduplicated list of custom flag names
        """
        if not self.connected:
            raise ConnectionError("Not connected to IMAP server")

        standard_flags = {'\\Seen', '\\Answered', '\\Flagged', '\\Deleted', '\\Draft', '\\Recent'}

        try:
            self.mailbox.folder.set(folder)
            custom_flags = set()
            count = 0

            for msg in self.mailbox.fetch(AND(all=True), mark_seen=False, headers_only=True):
                if hasattr(msg, 'flags') and msg.flags:
                    for flag in msg.flags:
                        if flag not in standard_flags:
                            custom_flags.add(flag)
                count += 1
                if count >= 200:
                    break

            self.logger.debug(f"Found {len(custom_flags)} custom flags in {folder}")
            return sorted(custom_flags)

        except Exception as e:
            self.logger.error(f"Failed to get flags from {folder}: {e}")
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
        """Watch using IMAP IDLE command with proactive reconnect (RFC 2177 hybrid)."""
        idle_cycle_timeout = self.config.get('service', {}).get('imap_idle_cycle_timeout', 180)
        max_connection_age = self.config.get('service', {}).get('imap_max_connection_age', 1500)

        connection_start = time.monotonic()
        self.mailbox.folder.set(folder)
        last_uids = set(self.get_all_uids(folder))

        while not stop_check():
            try:
                # Proactive reconnect after max_connection_age (default 25 min)
                connection_age = time.monotonic() - connection_start
                if connection_age >= max_connection_age:
                    self.logger.info(f"Proactive reconnect after {connection_age:.0f}s")
                    self.reconnect()
                    self.mailbox.folder.set(folder)
                    current_uids = set(self.get_all_uids(folder))
                    new_uids = current_uids - last_uids
                    for uid in new_uids:
                        self.logger.info(f"New email detected during reconnect: {uid}")
                        callback(uid)
                    last_uids = current_uids
                    connection_start = time.monotonic()
                    continue

                # 3-min IDLE cycle (default)
                responses = self.mailbox.idle.wait(timeout=idle_cycle_timeout)

                if responses:
                    current_uids = set(self.get_all_uids(folder))
                    new_uids = current_uids - last_uids
                    for uid in new_uids:
                        self.logger.info(f"New email detected: {uid}")
                        callback(uid)
                    last_uids = current_uids

            except (socket.error, OSError, imaplib.IMAP4.abort, TimeoutError,
                    ssl.SSLError, BrokenPipeError, ConnectionError) as e:
                self.logger.warning(f"Connection error in IDLE watch: {e}")
                try:
                    self.reconnect()
                    self.mailbox.folder.set(folder)
                    current_uids = set(self.get_all_uids(folder))
                    new_uids = current_uids - last_uids
                    for uid in new_uids:
                        self.logger.info(f"New email detected after reconnect: {uid}")
                        callback(uid)
                    last_uids = current_uids
                    connection_start = time.monotonic()
                except Exception as reconnect_error:
                    self.logger.error(f"Reconnection failed: {reconnect_error}")
                    time.sleep(5)
            except Exception as e:
                self.logger.error(f"Unexpected error in IDLE watch: {e}")
                time.sleep(5)

    def _watch_polling(self, callback: Callable, stop_check: Callable, folder: str = 'INBOX', interval: int = 60) -> None:
        """Watch using polling with auto-reconnect on connection errors."""
        self.mailbox.folder.set(folder)
        last_uids = set(self.get_all_uids(folder))

        while not stop_check():
            try:
                # Send NOOP to keep connection alive before sleeping
                try:
                    self.mailbox.client.noop()
                except (socket.error, OSError, imaplib.IMAP4.abort, TimeoutError,
                        ssl.SSLError, BrokenPipeError, ConnectionError) as e:
                    self.logger.warning(f"NOOP keepalive failed, reconnecting: {e}")
                    self.reconnect()
                    self.mailbox.folder.set(folder)

                time.sleep(interval)

                current_uids = set(self.get_all_uids(folder))
                new_uids = current_uids - last_uids

                for uid in new_uids:
                    self.logger.info(f"New email detected: {uid}")
                    callback(uid)

                last_uids = current_uids

            except (socket.error, OSError, imaplib.IMAP4.abort, TimeoutError,
                    ssl.SSLError, BrokenPipeError, ConnectionError) as e:
                self.logger.warning(f"Connection error in polling watch: {e}")
                try:
                    self.reconnect()
                    self.mailbox.folder.set(folder)
                    current_uids = set(self.get_all_uids(folder))
                    new_uids = current_uids - last_uids
                    for uid in new_uids:
                        self.logger.info(f"New email detected after reconnect: {uid}")
                        callback(uid)
                    last_uids = current_uids
                except Exception as reconnect_error:
                    self.logger.error(f"Reconnection failed: {reconnect_error}")
                    time.sleep(5)
            except Exception as e:
                self.logger.error(f"Unexpected error in polling watch: {e}")
                time.sleep(5)


class ConditionEvaluator:
    """Evaluates individual rule conditions against email messages."""

    def __init__(self, logger: logging.Logger):
        """
        Initialize condition evaluator.

        Args:
            logger: Logger instance
        """
        self.logger = logger

    def evaluate(self, email: EmailMessage, condition: RuleCondition) -> Tuple[bool, str]:
        """
        Evaluate a single condition against an email.

        Args:
            email: EmailMessage to evaluate
            condition: RuleCondition to check

        Returns:
            Tuple of (matched: bool, reason: str)
        """
        field_value = self._extract_field_value(email, condition)
        if field_value is None:
            return False, f"Field '{condition.field}' not found"

        try:
            matched = self._apply_operator(field_value, condition.operator, condition.value, email.date)
            reason = f"{condition.field} {condition.operator} '{condition.value}'"

            if matched:
                reason = f"Matched: {reason}"
            else:
                reason = f"Not matched: {reason}"

            self.logger.debug(f"Condition evaluation: {reason}")
            return matched, reason

        except Exception as e:
            self.logger.error(f"Error evaluating condition: {e}")
            return False, f"Error: {str(e)}"

    def _extract_field_value(self, email: EmailMessage, condition: RuleCondition) -> Optional[str]:
        """Extract field value from email based on condition field."""
        field = condition.field.lower()

        if field == 'from':
            return email.sender
        elif field == 'subject':
            return email.subject
        elif field == 'body':
            return email.body_text if email.body_text else email.body_html
        elif field == 'to':
            return ', '.join(email.recipients)
        elif field == 'date':
            return email.date.isoformat() if email.date else ''
        elif field == 'label':
            flags = list(email.raw_message.flags) if hasattr(email.raw_message, 'flags') and email.raw_message.flags else []
            return ','.join(flags)
        elif field == 'header':
            header_name = condition.value.split(':')[0] if ':' in condition.value else condition.value
            return email.headers.get(header_name, '')
        else:
            return None

    def _apply_operator(self, field_value: str, operator: str, compare_value: str, email_date: datetime) -> bool:
        """Apply operator to compare field value with expected value."""
        operator = operator.lower()

        if operator == 'contains':
            return compare_value.lower() in field_value.lower()

        elif operator == 'equals':
            return field_value.lower() == compare_value.lower()

        elif operator == 'not_equals':
            return field_value.lower() != compare_value.lower()

        elif operator == 'starts_with':
            return field_value.lower().startswith(compare_value.lower())

        elif operator == 'ends_with':
            return field_value.lower().endswith(compare_value.lower())

        elif operator == 'greater_than':
            try:
                return float(field_value) > float(compare_value)
            except ValueError:
                return False

        elif operator == 'less_than':
            try:
                return float(field_value) < float(compare_value)
            except ValueError:
                return False

        elif operator == 'greater_equal':
            try:
                return float(field_value) >= float(compare_value)
            except ValueError:
                return False

        elif operator == 'less_equal':
            try:
                return float(field_value) <= float(compare_value)
            except ValueError:
                return False

        elif operator == 'date_older_than':
            try:
                days = int(compare_value)
                age = datetime.now() - email_date
                return age.days > days
            except ValueError:
                return False

        elif operator == 'date_before':
            try:
                cutoff = datetime.strptime(compare_value, '%Y-%m-%d')
                return email_date < cutoff
            except ValueError:
                return False

        elif operator == 'has_label':
            flags = [f.strip() for f in field_value.split(',') if f.strip()]
            return compare_value in flags

        elif operator == 'not_has_label':
            flags = [f.strip() for f in field_value.split(',') if f.strip()]
            return compare_value not in flags

        else:
            self.logger.warning(f"Unknown operator: {operator}")
            return False


class RuleEngine:
    """Orchestrates rule evaluation and action execution."""

    def __init__(self, imap_client: IMAPClient, logger: logging.Logger):
        """
        Initialize rule engine.

        Args:
            imap_client: IMAPClient instance
            logger: Logger instance
        """
        self.imap = imap_client
        self.evaluator = ConditionEvaluator(logger)
        self.logger = logger

    def evaluate_rule(self, email: EmailMessage, rule: EmailRule, conditions: list[RuleCondition]) -> Tuple[bool, dict]:
        """
        Evaluate all conditions of a rule.

        Args:
            email: EmailMessage to evaluate
            rule: EmailRule to check
            conditions: List of RuleCondition objects

        Returns:
            Tuple of (matched: bool, details: dict)
        """
        if not conditions:
            self.logger.warning(f"Rule {rule.name} has no conditions")
            return False, {'logic': rule.condition, 'condition_results': [], 'overall_match': False}

        condition_results = []
        for condition in conditions:
            matched, reason = self.evaluator.evaluate(email, condition)
            condition_results.append({
                'field': condition.field,
                'operator': condition.operator,
                'value': condition.value,
                'matched': matched,
                'reason': reason
            })

        logic = rule.condition.upper()
        if logic == 'AND':
            overall_match = all(c['matched'] for c in condition_results)
        elif logic == 'OR':
            overall_match = any(c['matched'] for c in condition_results)
        else:
            self.logger.warning(f"Unknown logic: {logic}, defaulting to AND")
            overall_match = all(c['matched'] for c in condition_results)

        details = {
            'logic': logic,
            'condition_results': condition_results,
            'overall_match': overall_match
        }

        self.logger.info(f"Rule '{rule.name}' evaluation: {overall_match}")
        return overall_match, details

    def execute_actions(self, email: EmailMessage, actions: list[RuleAction], dry_run: bool = False) -> list[str]:
        """
        Execute all actions for a matched rule.

        Args:
            email: EmailMessage to act upon
            actions: List of RuleAction objects
            dry_run: If True, only simulate actions

        Returns:
            List of action descriptions
        """
        if not actions:
            return []

        action_logs = []

        sorted_actions = self._sort_actions(actions)

        for action in sorted_actions:
            try:
                description = self._execute_action(email, action, dry_run)
                action_logs.append(description)
                self.logger.info(f"{'[DRY-RUN] ' if dry_run else ''}Action: {description}")

            except Exception as e:
                error_msg = f"Failed to execute action {action.action_type}: {e}"
                self.logger.error(error_msg)
                action_logs.append(error_msg)

        return action_logs

    def _sort_actions(self, actions: list[RuleAction]) -> list[RuleAction]:
        """Sort actions by execution priority."""
        priority_order = {
            'mark_as_read': 1,
            'add_label': 2,
            'copy_to_folder': 3,
            'modify_subject': 4,
            'move_to_folder': 5,
            'delete': 6
        }

        return sorted(actions, key=lambda a: priority_order.get(a.action_type, 99))

    def _execute_action(self, email: EmailMessage, action: RuleAction, dry_run: bool) -> str:
        """Execute a single action."""
        action_type = action.action_type.lower()

        if action_type == 'move_to_folder':
            target_folder = action.folder or action.action_value

            if not dry_run:
                if not self.imap.folder_exists(target_folder):
                    self.logger.info(f"Folder '{target_folder}' does not exist, creating...")
                    self.imap.create_folder(target_folder)

                self.imap.move_to_folder(email.uid, target_folder)
            return f"move_to_folder: {target_folder}"

        elif action_type == 'copy_to_folder':
            target_folder = action.folder or action.action_value

            if not dry_run:
                if not self.imap.folder_exists(target_folder):
                    self.logger.info(f"Folder '{target_folder}' does not exist, creating...")
                    self.imap.create_folder(target_folder)

                self.imap.copy_to_folder(email.uid, target_folder)
            return f"copy_to_folder: {target_folder}"

        elif action_type == 'add_label':
            label_name = action.label or action.action_value
            if not dry_run:
                self.imap.add_flag(email.uid, label_name)
            return f"add_label: {label_name}"

        elif action_type == 'mark_as_read':
            if not dry_run:
                self.imap.mark_as_read(email.uid)
            return "mark_as_read"

        elif action_type == 'delete':
            if not dry_run:
                self.imap.delete_email(email.uid)
            return "delete"

        elif action_type == 'modify_subject':
            return f"modify_subject: {action.action_value} (not implemented)"

        else:
            self.logger.warning(f"Unknown action type: {action_type}")
            return f"unknown_action: {action_type}"


@dataclass
class ProcessingResult:
    """Result of email processing."""
    email_uid: str
    rules_matched: list[int]
    actions_taken: list[str]
    errors: list[str]


class EmailProcessor:
    """Orchestrates email processing workflow."""

    def __init__(self, session: Session, rule_engine: RuleEngine, logger: logging.Logger):
        """
        Initialize email processor.

        Args:
            session: SQLAlchemy database session
            rule_engine: RuleEngine instance
            logger: Logger instance
        """
        self.session = session
        self.rule_engine = rule_engine
        self.logger = logger

    def process_email(self, email: EmailMessage, credential_id: int) -> ProcessingResult:
        """
        Process a single email through all applicable rules.

        Args:
            email: EmailMessage to process
            credential_id: Email credential ID

        Returns:
            ProcessingResult with processing details
        """
        self.logger.info(f"Processing email {email.uid} from {email.sender}")

        enabled_rules = self._load_enabled_rules(credential_id)
        self.logger.debug(f"Found {len(enabled_rules)} enabled rules for credential {credential_id}")

        rules_matched = []
        actions_taken = []
        errors = []

        for rule in enabled_rules:
            try:
                if self._is_already_processed(email.uid, credential_id, rule.id):
                    self.logger.debug(f"Email {email.uid} already processed by rule '{rule.name}', skipping")
                    continue

                conditions = self._load_conditions(rule.id)
                matched, details = self.rule_engine.evaluate_rule(email, rule, conditions)

                if matched:
                    self.logger.info(f"Rule '{rule.name}' matched for email {email.uid}")
                    rules_matched.append(rule.id)

                    actions = self._load_actions(rule.id)
                    action_logs = self.rule_engine.execute_actions(email, actions, dry_run=False)
                    actions_taken.extend(action_logs)

                    self._mark_as_processed(email.uid, credential_id, rule.id, json.dumps(action_logs))

            except Exception as e:
                error_msg = f"Error processing rule {rule.name}: {e}"
                self.logger.error(error_msg)
                errors.append(error_msg)

        result = ProcessingResult(
            email_uid=email.uid,
            rules_matched=rules_matched,
            actions_taken=actions_taken,
            errors=errors
        )

        self.logger.info(f"Completed processing email {email.uid}: {len(rules_matched)} rules matched")
        return result

    def _is_already_processed(self, email_uid: str, credential_id: int, rule_id: int) -> bool:
        """Check if email has already been processed by a specific rule."""
        existing = self.session.query(EmailRuleApplication).filter_by(
            email_uid=email_uid,
            email_credential_id=credential_id,
            rule_id=rule_id
        ).first()

        return existing is not None

    def _load_enabled_rules(self, credential_id: int) -> list[EmailRule]:
        """Load all enabled rules for a credential."""
        return self.session.query(EmailRule).filter_by(
            email_credential_id=credential_id,
            enabled=True
        ).all()

    def _load_conditions(self, rule_id: int) -> list[RuleCondition]:
        """Load all conditions for a rule."""
        return self.session.query(RuleCondition).filter_by(
            rule_id=rule_id
        ).all()

    def _load_actions(self, rule_id: int) -> list[RuleAction]:
        """Load all actions for a rule."""
        return self.session.query(RuleAction).filter_by(
            rule_id=rule_id
        ).all()

    def _mark_as_processed(self, email_uid: str, credential_id: int, rule_id: int, actions_taken: str) -> None:
        """Mark email as processed by a specific rule."""
        try:
            application = EmailRuleApplication(
                email_uid=email_uid,
                email_credential_id=credential_id,
                rule_id=rule_id,
                applied_at=datetime.now(),
                actions_taken=actions_taken
            )

            self.session.add(application)
            self.session.commit()

            self.logger.debug(f"Marked email {email_uid} as processed by rule {rule_id}")

        except Exception as e:
            self.logger.error(f"Failed to mark email as processed: {e}")
            self.session.rollback()


class ServiceManager:
    """Manages service status tracking and heartbeat."""

    def __init__(self, session: Session, logger: logging.Logger, service_name: str = "EmailService"):
        """
        Initialize service manager.

        Args:
            session: SQLAlchemy database session
            logger: Logger instance
            service_name: Name of the service
        """
        self.session = session
        self.logger = logger
        self.service_name = service_name
        self.status_id = None

    def register_service(self) -> None:
        """Register service in database."""
        try:
            from DatabaseService import ServiceStatus
            existing = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if existing:
                existing.status = 'running'
                existing.last_check = datetime.now()
                existing.last_error = None
                self.status_id = existing.id
                self.logger.info(f"Service '{self.service_name}' re-registered")
            else:
                status = ServiceStatus(
                    service_name=self.service_name,
                    status='running',
                    last_check=datetime.now(),
                    last_error=None,
                    emails_processed=0,
                    rules_executed=0
                )
                self.session.add(status)
                self.session.commit()
                self.status_id = status.id
                self.logger.info(f"Service '{self.service_name}' registered")

            self.session.commit()

        except Exception as e:
            self.logger.error(f"Failed to register service: {e}")
            self.session.rollback()

    def update_status(self, status: str, error: str = None) -> None:
        """
        Update service status.

        Args:
            status: New status (running/stopped/error)
            error: Optional error message
        """
        try:
            from DatabaseService import ServiceStatus
            service_status = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if service_status:
                service_status.status = status
                service_status.last_check = datetime.now()
                if error:
                    service_status.last_error = error

                self.session.commit()
                self.logger.debug(f"Service status updated to: {status}")

        except Exception as e:
            self.logger.error(f"Failed to update status: {e}")
            self.session.rollback()

    def increment_emails_processed(self) -> None:
        """Increment emails processed counter."""
        try:
            from DatabaseService import ServiceStatus
            service_status = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if service_status:
                service_status.emails_processed += 1
                self.session.commit()

        except Exception as e:
            self.logger.error(f"Failed to increment emails processed: {e}")
            self.session.rollback()

    def increment_rules_executed(self) -> None:
        """Increment rules executed counter."""
        try:
            from DatabaseService import ServiceStatus
            service_status = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if service_status:
                service_status.rules_executed += 1
                self.session.commit()

        except Exception as e:
            self.logger.error(f"Failed to increment rules executed: {e}")
            self.session.rollback()

    def heartbeat(self) -> None:
        """Update last check timestamp."""
        try:
            from DatabaseService import ServiceStatus
            service_status = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if service_status:
                service_status.last_check = datetime.now()
                self.session.commit()

        except Exception as e:
            self.logger.error(f"Failed to update heartbeat: {e}")
            self.session.rollback()

    def get_status(self) -> dict:
        """
        Get current service status.

        Returns:
            Dictionary with status information
        """
        try:
            from DatabaseService import ServiceStatus
            service_status = self.session.query(ServiceStatus).filter_by(
                service_name=self.service_name
            ).first()

            if service_status:
                return {
                    'service_name': service_status.service_name,
                    'status': service_status.status,
                    'last_check': service_status.last_check,
                    'last_error': service_status.last_error,
                    'emails_processed': service_status.emails_processed,
                    'rules_executed': service_status.rules_executed
                }

            return None

        except Exception as e:
            self.logger.error(f"Failed to get status: {e}")
            return None


class EMailService:
    """Main email service orchestrator."""

    def __init__(self):
        """Initialize email service."""
        self.config = load_config()
        self.logger = LoggingService.setup(self.config)

        db_url = get_database_url()
        self.engine = create_engine(db_url)

        from DatabaseService import DatabaseService
        db_service = DatabaseService(db_url)
        db_service.init_db()
        db_service.run_migrations(self.logger)

        self.session_factory = sessionmaker(bind=self.engine)

        self.service_manager = ServiceManager(
            self.session_factory(),
            self.logger,
            "EmailService"
        )

        self.imap_clients: Dict[str, IMAPClient] = {}
        self.stop_event = threading.Event()
        self.threads = []

        self.auto_apply_rules = self.config.get('auto_apply_rules', False)

        self.logger.info(f"EMailService initialized (auto_apply_rules: {self.auto_apply_rules})")

    def start(self) -> None:
        """Start the email service."""
        self.logger.info("Starting EMailService...")

        try:
            self.service_manager.register_service()

            heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop,
                daemon=True,
                name="Heartbeat"
            )
            heartbeat_thread.start()
            self.threads.append(heartbeat_thread)

            dry_run_thread = threading.Thread(
                target=self._dry_run_loop,
                daemon=True,
                name="DryRun"
            )
            dry_run_thread.start()
            self.threads.append(dry_run_thread)

            if self.auto_apply_rules:
                self._start_email_watchers()

            self.logger.info("EMailService started successfully")

            while not self.stop_event.is_set():
                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
            self.stop()

        except Exception as e:
            self.logger.error(f"Error in EMailService: {e}")
            self.service_manager.update_status('error', str(e))
            raise

    def stop(self) -> None:
        """Stop the email service."""
        self.logger.info("Stopping EMailService...")

        self.stop_event.set()

        for client in self.imap_clients.values():
            try:
                client.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting IMAP client: {e}")

        for thread in self.threads:
            thread.join(timeout=5)

        self.service_manager.update_status('stopped')
        self.logger.info("EMailService stopped")

    def _start_email_watchers(self) -> None:
        """Start email watcher threads for all credentials."""
        session = self.session_factory()

        try:
            credentials = session.query(EmailCredential).all()
            self.logger.info(f"Starting email watchers for {len(credentials)} accounts")

            for credential in credentials:
                watcher_thread = threading.Thread(
                    target=self._email_watcher_loop,
                    args=(credential,),
                    daemon=True,
                    name=f"Watcher-{credential.email_address}"
                )
                watcher_thread.start()
                self.threads.append(watcher_thread)

        finally:
            session.close()

    def _email_watcher_loop(self, credential: EmailCredential) -> None:
        """
        Email watcher loop for a single credential.
        Starts separate watchers for each monitored folder.

        Args:
            credential: EmailCredential to watch
        """
        self.logger.info(f"Starting email watcher for {credential.email_address}")

        session = self.session_factory()
        try:
            
            rules = session.query(EmailRule).filter_by(
                email_credential_id=credential.id,
                enabled=True
            ).all()

            monitored_folders = set()
            for rule in rules:
                folder = rule.monitored_folder if hasattr(rule, 'monitored_folder') and rule.monitored_folder else 'INBOX'
                monitored_folders.add(folder)

            if not monitored_folders:
                monitored_folders.add('INBOX')

            self.logger.info(f"Monitoring {len(monitored_folders)} folders: {monitored_folders}")
        finally:
            session.close()

        folder_threads = []
        for folder in monitored_folders:
            folder_thread = threading.Thread(
                target=self._folder_watcher,
                args=(credential, folder),
                daemon=True,
                name=f"Watcher-{credential.email_address}-{folder}"
            )
            folder_thread.start()
            folder_threads.append(folder_thread)

        for thread in folder_threads:
            thread.join()

    def _folder_watcher(self, credential: EmailCredential, folder: str) -> None:
        """
        Watch a single folder for a credential.

        Args:
            credential: EmailCredential to watch
            folder: Folder name to monitor
        """
        self.logger.info(f"Starting folder watcher for {credential.email_address}/{folder}")
        base_delay = self.config.get('service', {}).get('imap_reconnect_delay', 30)
        max_delay = self.config.get('service', {}).get('imap_max_reconnect_delay', 300)
        current_delay = base_delay

        while not self.stop_event.is_set():
            try:
                imap_client = IMAPClient(credential, self.config, self.logger)
                imap_client.connect()

                client_key = f"{credential.id}_{folder}"
                self.imap_clients[client_key] = imap_client

                # Process all existing emails on startup (skip already processed ones)
                all_uids = imap_client.get_all_uids(folder)
                self.logger.info(f"Processing {len(all_uids)} existing emails in {folder}")
                for uid in all_uids:
                    self._process_new_email(uid, credential.id, folder)

                def callback(uid: str):
                    self._process_new_email(uid, credential.id, folder)

                def stop_check():
                    return self.stop_event.is_set()

                imap_client.watch(callback, stop_check, folder)
                current_delay = base_delay  # Reset on successful connection

            except Exception as e:
                self.logger.error(f"Error in folder watcher for {folder}: {e}")
                self.logger.info(f"Retrying in {current_delay}s...")
                time.sleep(current_delay)
                current_delay = min(current_delay * 2, max_delay)

            finally:
                client_key = f"{credential.id}_{folder}"
                if client_key in self.imap_clients:
                    try:
                        self.imap_clients[client_key].disconnect()
                        del self.imap_clients[client_key]
                    except Exception as e:
                        self.logger.debug(f"Client disconnect cleanup failed: {e}")

    def _process_new_email(self, uid: str, credential_id: int, folder: str = 'INBOX') -> None:
        """
        Process a new email.

        Args:
            uid: Email UID
            credential_id: Email credential ID
            folder: Folder where email was found
        """
        session = self.session_factory()

        try:
            client_key = f"{credential_id}_{folder}"
            imap_client = self.imap_clients.get(client_key)

            if not imap_client:
                imap_client = self.imap_clients.get(credential_id)

            if not imap_client:
                self.logger.warning(f"No IMAP client for credential {credential_id}/{folder}")
                return

            email = imap_client.fetch_email(uid)

            rule_engine = RuleEngine(imap_client, self.logger)
            email_processor = EmailProcessor(session, rule_engine, self.logger)

            result = email_processor.process_email(email, credential_id)

            self.service_manager.increment_emails_processed()
            self.service_manager.increment_rules_executed()

            self.logger.info(
                f"Email {uid} from {folder} processed: {len(result.rules_matched)} rules matched, "
                f"{len(result.actions_taken)} actions taken"
            )

        except Exception as e:
            self.logger.error(f"Error processing email {uid} from {folder}: {e}")

        finally:
            session.close()

    def _dry_run_loop(self) -> None:
        """Poll for and process dry-run requests."""
        poll_interval = self.config.get('service', {}).get('dry_run_poll_interval', 5)

        self.logger.info("Starting dry-run handler loop")

        while not self.stop_event.is_set():
            try:
                session = self.session_factory()

                try:
                    handler = DryRunHandler(session, self.config, self.logger)
                    pending_requests = handler.check_pending_requests()

                    for request in pending_requests:
                        if self.stop_event.is_set():
                            break

                        handler.process_request(request)

                finally:
                    session.close()

            except Exception as e:
                self.logger.error(f"Error in dry-run loop: {e}")

            time.sleep(poll_interval)

    def _heartbeat_loop(self) -> None:
        """Update service heartbeat."""
        heartbeat_interval = self.config.get('service', {}).get('heartbeat_interval', 10)

        self.logger.info("Starting heartbeat loop")

        while not self.stop_event.is_set():
            try:
                self.service_manager.heartbeat()
            except Exception as e:
                self.logger.error(f"Error in heartbeat: {e}")

            time.sleep(heartbeat_interval)


if __name__ == "__main__":
    service = EMailService()
    service.start()


class DryRunHandler:
    """Handles dry-run processing of email rules."""

    def __init__(self, session: Session, config: dict, logger: logging.Logger):
        """
        Initialize dry-run handler.

        Args:
            session: SQLAlchemy database session
            config: Configuration dictionary
            logger: Logger instance
        """
        self.session = session
        self.config = config
        self.logger = logger

    def check_pending_requests(self):
        """
        Check for pending dry-run requests.

        Returns:
            List of pending DryRunRequest objects
        """
        try:
            from DatabaseService import DryRunRequest
            pending = self.session.query(DryRunRequest).filter_by(
                status='pending'
            ).all()

            return pending

        except Exception as e:
            self.logger.error(f"Failed to check pending requests: {e}")
            return []

    def process_request(self, request) -> None:
        """
        Process a dry-run request.

        Args:
            request: DryRunRequest to process
        """
        self.logger.info(f"Processing dry-run request {request.id}")

        try:
            from DatabaseService import EmailRule, EmailCredential, RuleCondition, RuleAction
            
            request.status = 'processing'
            self.session.commit()

            rule = self.session.query(EmailRule).filter_by(id=request.rule_id).first()
            if not rule:
                raise ValueError(f"Rule {request.rule_id} not found")

            credential = self.session.query(EmailCredential).filter_by(
                id=request.email_credential_id
            ).first()
            if not credential:
                raise ValueError(f"Credential {request.email_credential_id} not found")

            imap_client = IMAPClient(credential, self.config, self.logger)
            imap_client.connect()

            try:
                self._process_emails(request, rule, imap_client)

                request.status = 'completed'
                request.processed_at = datetime.now()
                self.session.commit()

                self.logger.info(f"Dry-run request {request.id} completed")

            finally:
                imap_client.disconnect()

        except Exception as e:
            error_msg = f"Failed to process dry-run request {request.id}: {e}"
            self.logger.error(error_msg)

            request.status = 'failed'
            request.processed_at = datetime.now()
            self.session.commit()

    def _process_emails(self, request, rule, imap_client: 'IMAPClient') -> None:
        """Process emails for dry-run evaluation."""
        from DatabaseService import RuleCondition, RuleAction, DryRunResult
        
        conditions = self.session.query(RuleCondition).filter_by(rule_id=rule.id).all()
        actions = self.session.query(RuleAction).filter_by(rule_id=rule.id).all()

        rule_engine = RuleEngine(imap_client, self.logger)

        uids = imap_client.get_all_uids(limit=0)
        self.logger.info(f"Processing emails for dry-run (max 10 matches)")

        matched_count = 0
        max_matches = 10

        for uid in uids:
            if matched_count >= max_matches:
                self.logger.info(f"Reached {max_matches} matches, stopping dry-run")
                break

            try:
                email = imap_client.fetch_email(uid)

                matched, details = rule_engine.evaluate_rule(email, rule, conditions)

                if matched:
                    matched_count += 1
                    actions_would_apply = rule_engine.execute_actions(email, actions, dry_run=True)

                    result = DryRunResult(
                        request_id=request.id,
                        email_uid=uid,
                        email_subject=email.subject,
                        email_from=email.sender,
                        email_date=email.date,
                        matched=matched,
                        condition_results=json.dumps(details),
                        actions_would_apply=json.dumps(actions_would_apply)
                    )

                    self.session.add(result)
                    self.session.commit()

            except Exception as e:
                self.logger.error(f"Failed to process email {uid} in dry-run: {e}")
                continue


def test_imap_connection(credential) -> Tuple[bool, str, Optional[dict]]:
    """
    Test IMAP connection and auto-detect best settings.

    Args:
        credential: EmailCredential to test

    Returns:
        Tuple of (success: bool, message: str, suggested_settings: dict)
    """
    from imap_tools import MailBoxStartTls, MailBoxUnencrypted
    import logging
    
    logger = logging.getLogger('MailMind')

    test_configs = []

    if credential.port == 993:
        test_configs = [
            ('SSL', MailBox, True, False),
        ]
    elif credential.port == 143:
        test_configs = [
            ('TLS', MailBoxStartTls, False, True),
            ('Unencrypted', MailBoxUnencrypted, False, False),
        ]
    else:
        test_configs = [
            ('SSL', MailBox, True, False),
            ('TLS', MailBoxStartTls, False, True),
            ('Unencrypted', MailBoxUnencrypted, False, False),
        ]

    for name, mailbox_class, use_ssl, use_tls in test_configs:
        try:
            logger.info(f"Testing {name} connection to {credential.host}:{credential.port}")

            mailbox = mailbox_class(credential.host, credential.port)
            mailbox.login(credential.username, credential.password, initial_folder='INBOX')
            mailbox.logout()

            return (
                True,
                f"Connection successful using {name}",
                {'use_ssl': use_ssl, 'use_tls': use_tls, 'port': credential.port}
            )

        except Exception as e:
            logger.debug(f"{name} failed: {e}")
            continue

    return (
        False,
        f"All connection methods failed. Check credentials and server settings.",
        None
    )


def suggest_imap_settings(host: str, port: int) -> dict:
    """
    Suggest IMAP settings based on common configurations.

    Args:
        host: IMAP server hostname
        port: IMAP server port

    Returns:
        Dictionary with suggested settings
    """
    common_configs = {
        'imap.gmail.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'outlook.office365.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.mail.yahoo.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.aol.com': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.gmx.net': {'port': 993, 'use_ssl': True, 'use_tls': False},
        'imap.web.de': {'port': 993, 'use_ssl': True, 'use_tls': False},
    }

    if host in common_configs:
        return common_configs[host]

    if port == 993:
        return {'port': 993, 'use_ssl': True, 'use_tls': False}
    elif port == 143:
        return {'port': 143, 'use_ssl': False, 'use_tls': True}
    else:
        return {'port': 993, 'use_ssl': True, 'use_tls': False}

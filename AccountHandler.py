"""Account Handler for email processing lifecycle management."""

import hashlib
import json
import logging
import threading
from datetime import datetime
from typing import Set, Optional

from DatabaseService import EmailRule, EmailRuleApplication, LLMConfig, AccountHandlerConfig


class AccountHandler:
    """
    Manages email processing state for a single account.

    Responsibilities:
    - Calculate and track rule hash for change detection
    - Maintain thread-safe in-memory cache of processed UIDs
    - Load LLM and handler configuration
    """

    def __init__(self, credential, session_factory, config, logger: logging.Logger):
        """
        Initialize account handler.

        Args:
            credential: EmailCredential instance
            session_factory: SQLAlchemy session factory
            config: Application config dict
            logger: Logger instance
        """
        self.credential = credential
        self.session_factory = session_factory
        self.config = config
        self.logger = logger

        # State
        self.rule_hash = None
        self.processed_uids: Set[str] = set()
        self._uids_lock = threading.Lock()
        self.llm_config: Optional[LLMConfig] = None
        self.handler_config: Optional[AccountHandlerConfig] = None
        self.persistent_tracking = True

    def calculate_rule_hash(self) -> str:
        """
        Calculate SHA256 hash of all rules for this account.

        Hash includes: rule ID, name, enabled, condition, monitored_folder, conditions, actions.
        This allows detecting ANY change to rules configuration.

        Returns:
            Hex string of SHA256 hash
        """
        self.logger.debug(f"Calculating rule hash for account {self.credential.id}")
        session = self.session_factory()
        try:
            rules = session.query(EmailRule).filter_by(
                email_credential_id=self.credential.id
            ).order_by(EmailRule.id).all()

            self.logger.debug(f"Found {len(rules)} rules for hash calculation")

            # Serialize rules to JSON (sorted by ID for consistency)
            rule_data = []
            for rule in rules:
                rule_dict = {
                    "id": rule.id,
                    "name": rule.name,
                    "enabled": rule.enabled,
                    "condition": rule.condition,
                    "monitored_folder": rule.monitored_folder,
                    "conditions": [
                        {"field": c.field, "operator": c.operator, "value": c.value}
                        for c in rule.conditions
                    ],
                    "actions": [
                        {"action_type": a.action_type, "action_value": a.action_value}
                        for a in rule.rule_actions
                    ]
                }
                rule_data.append(rule_dict)

            json_str = json.dumps(rule_data, sort_keys=True)
            rule_hash = hashlib.sha256(json_str.encode()).hexdigest()

            self.logger.debug(f"Rule hash: {rule_hash}")
            return rule_hash

        finally:
            session.close()

    def load_processed_uids(self):
        """
        Load processed UIDs for current rule hash from DB into memory cache.

        Only loads if persistent_tracking is enabled.
        """
        if not self.persistent_tracking:
            with self._uids_lock:
                self.processed_uids = set()
            self.logger.info("Session-only tracking enabled, not loading UIDs from DB")
            return

        self.logger.debug(f"Loading processed UIDs for hash {self.rule_hash[:8]}...")
        session = self.session_factory()
        try:
            applications = session.query(EmailRuleApplication).filter_by(
                email_credential_id=self.credential.id,
                rule_config_hash=self.rule_hash
            ).all()

            new_uids = {app.email_uid for app in applications}
            with self._uids_lock:
                self.processed_uids = new_uids
            self.logger.info(
                f"Loaded {len(new_uids)} processed UIDs for hash {self.rule_hash[:8]}"
            )

        finally:
            session.close()

    def is_processed(self, uid: str) -> bool:
        """
        Check if UID is already processed (O(1) set lookup).

        Args:
            uid: Email UID string

        Returns:
            True if already processed
        """
        with self._uids_lock:
            return uid in self.processed_uids

    def mark_processed(self, uid: str, rule_id: int, actions_taken: str, email_subject: str = ""):
        """
        Mark UID as processed in cache and optionally DB.

        Args:
            uid: Email UID
            rule_id: Rule ID that processed this email
            actions_taken: Description of actions taken
            email_subject: Email subject line
        """
        self.logger.debug(f"Marking UID {uid} as processed (rule_id={rule_id})")
        with self._uids_lock:
            self.processed_uids.add(uid)
            cache_size = len(self.processed_uids)
        self.logger.debug(f"Cache size after mark: {cache_size}")

        if self.persistent_tracking:
            session = self.session_factory()
            try:
                application = EmailRuleApplication(
                    email_uid=uid,
                    email_credential_id=self.credential.id,
                    rule_id=rule_id,
                    rule_config_hash=self.rule_hash,
                    email_subject=email_subject,
                    applied_at=datetime.now(),
                    actions_taken=actions_taken
                )
                session.add(application)
                session.commit()
                self.logger.debug(f"Persisted UID {uid} to database")

            except Exception as e:
                self.logger.error(f"Failed to persist UID {uid}: {e}")
                session.rollback()
            finally:
                session.close()
        else:
            self.logger.debug(f"Session-only: UID {uid} NOT persisted")

    def load_llm_config(self):
        """Load LLM configuration for this account."""
        self.logger.debug(f"Loading LLM config for account {self.credential.id}")
        session = self.session_factory()
        try:
            self.llm_config = session.query(LLMConfig).filter_by(
                credential_id=self.credential.id
            ).first()

            if self.llm_config:
                self.logger.info(
                    f"Loaded LLM config: provider={self.llm_config.provider}, model={self.llm_config.model}"
                )
            else:
                self.logger.debug("No LLM config found for this account")

        finally:
            session.close()

    def load_handler_config(self):
        """Load handler configuration for this account."""
        self.logger.debug(f"Loading handler config for account {self.credential.id}")
        session = self.session_factory()
        try:
            self.handler_config = session.query(AccountHandlerConfig).filter_by(
                credential_id=self.credential.id
            ).first()

            if not self.handler_config:
                # Create default config
                self.handler_config = AccountHandlerConfig(
                    credential_id=self.credential.id,
                    persistent_processed_tracking=True
                )
                session.add(self.handler_config)
                session.commit()
                self.logger.info("Created default handler config")

            self.persistent_tracking = self.handler_config.persistent_processed_tracking
            self.logger.info(f"Persistent tracking: {self.persistent_tracking}")

        finally:
            session.close()

    def refresh_state(self):
        """Refresh all handler state (rule hash, config, UIDs, LLM)."""
        self.rule_hash = self.calculate_rule_hash()
        self.load_handler_config()
        self.load_processed_uids()
        self.load_llm_config()

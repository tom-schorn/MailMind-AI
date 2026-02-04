import json
import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from Entities import EmailRule, RuleCondition, RuleAction, ProcessedEmail
from imap_client import EmailMessage
from rule_engine import RuleEngine


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

        if self._is_already_processed(email.uid, credential_id):
            self.logger.info(f"Email {email.uid} already processed, skipping")
            return ProcessingResult(
                email_uid=email.uid,
                rules_matched=[],
                actions_taken=[],
                errors=["Email already processed"]
            )

        enabled_rules = self._load_enabled_rules(credential_id)
        self.logger.debug(f"Found {len(enabled_rules)} enabled rules for credential {credential_id}")

        rules_matched = []
        actions_taken = []
        errors = []

        for rule in enabled_rules:
            try:
                conditions = self._load_conditions(rule.id)
                matched, details = self.rule_engine.evaluate_rule(email, rule, conditions)

                if matched:
                    self.logger.info(f"Rule '{rule.name}' matched for email {email.uid}")
                    rules_matched.append(rule.id)

                    actions = self._load_actions(rule.id)
                    action_logs = self.rule_engine.execute_actions(email, actions, dry_run=False)
                    actions_taken.extend(action_logs)

            except Exception as e:
                error_msg = f"Error processing rule {rule.name}: {e}"
                self.logger.error(error_msg)
                errors.append(error_msg)

        self._mark_as_processed(email.uid, credential_id, rules_matched)

        result = ProcessingResult(
            email_uid=email.uid,
            rules_matched=rules_matched,
            actions_taken=actions_taken,
            errors=errors
        )

        self.logger.info(f"Completed processing email {email.uid}: {len(rules_matched)} rules matched")
        return result

    def _is_already_processed(self, email_uid: str, credential_id: int) -> bool:
        """Check if email has already been processed."""
        existing = self.session.query(ProcessedEmail).filter_by(
            email_uid=email_uid,
            email_credential_id=credential_id
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

    def _mark_as_processed(self, email_uid: str, credential_id: int, rules_applied: list[int]) -> None:
        """Mark email as processed in database."""
        try:
            processed = ProcessedEmail(
                email_uid=email_uid,
                email_credential_id=credential_id,
                processed_at=datetime.now(),
                rules_applied=json.dumps(rules_applied)
            )

            self.session.add(processed)
            self.session.commit()

            self.logger.debug(f"Marked email {email_uid} as processed")

        except Exception as e:
            self.logger.error(f"Failed to mark email as processed: {e}")
            self.session.rollback()

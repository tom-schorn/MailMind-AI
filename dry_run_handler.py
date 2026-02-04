import json
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from Entities import DryRunRequest, DryRunResult, EmailRule, EmailCredential, RuleCondition, RuleAction
from imap_client import IMAPClient
from rule_engine import RuleEngine


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

    def check_pending_requests(self) -> list[DryRunRequest]:
        """
        Check for pending dry-run requests.

        Returns:
            List of pending DryRunRequest objects
        """
        try:
            pending = self.session.query(DryRunRequest).filter_by(
                status='pending'
            ).all()

            return pending

        except Exception as e:
            self.logger.error(f"Failed to check pending requests: {e}")
            return []

    def process_request(self, request: DryRunRequest) -> None:
        """
        Process a dry-run request.

        Args:
            request: DryRunRequest to process
        """
        self.logger.info(f"Processing dry-run request {request.id}")

        try:
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

    def _process_emails(self, request: DryRunRequest, rule: EmailRule, imap_client: IMAPClient) -> None:
        """Process emails for dry-run evaluation."""
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

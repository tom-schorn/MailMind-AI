import logging
import threading
import time
from typing import Dict

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from config_manager import load_config
from logger_config import setup_logging
from path_manager import get_database_url
from Entities import EmailCredential, init_db
from imap_client import IMAPClient
from rule_engine import RuleEngine
from email_processor import EmailProcessor
from service_manager import ServiceManager
from dry_run_handler import DryRunHandler


class EmailService:
    """Main email service orchestrator."""

    def __init__(self):
        """Initialize email service."""
        self.config = load_config()
        self.logger = setup_logging(self.config)

        db_url = get_database_url()
        self.engine = create_engine(db_url)
        init_db(self.engine)

        self.session_factory = sessionmaker(bind=self.engine)

        self.service_manager = ServiceManager(
            self.session_factory(),
            self.logger,
            "EmailService"
        )

        self.imap_clients: Dict[int, IMAPClient] = {}
        self.stop_event = threading.Event()
        self.threads = []

        self.auto_apply_rules = self.config.get('auto_apply_rules', False)

        self.logger.info(f"EmailService initialized (auto_apply_rules: {self.auto_apply_rules})")

    def start(self) -> None:
        """Start the email service."""
        self.logger.info("Starting EmailService...")

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

            self.logger.info("EmailService started successfully")

            while not self.stop_event.is_set():
                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("Received shutdown signal")
            self.stop()

        except Exception as e:
            self.logger.error(f"Error in EmailService: {e}")
            self.service_manager.update_status('error', str(e))
            raise

    def stop(self) -> None:
        """Stop the email service."""
        self.logger.info("Stopping EmailService...")

        self.stop_event.set()

        for client in self.imap_clients.values():
            try:
                client.disconnect()
            except Exception as e:
                self.logger.error(f"Error disconnecting IMAP client: {e}")

        for thread in self.threads:
            thread.join(timeout=5)

        self.service_manager.update_status('stopped')
        self.logger.info("EmailService stopped")

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

        Args:
            credential: EmailCredential to watch
        """
        self.logger.info(f"Starting email watcher for {credential.email_address}")

        reconnect_delay = self.config.get('service', {}).get('imap_reconnect_delay', 30)

        while not self.stop_event.is_set():
            try:
                imap_client = IMAPClient(credential, self.config, self.logger)
                imap_client.connect()

                self.imap_clients[credential.id] = imap_client

                unseen_uids = imap_client.get_unseen_uids()
                for uid in unseen_uids:
                    self._process_new_email(uid, credential.id)

                def callback(uid: str):
                    self._process_new_email(uid, credential.id)

                def stop_check():
                    return self.stop_event.is_set()

                imap_client.watch(callback, stop_check)

            except Exception as e:
                self.logger.error(f"Error in email watcher for {credential.email_address}: {e}")
                time.sleep(reconnect_delay)

            finally:
                if credential.id in self.imap_clients:
                    try:
                        self.imap_clients[credential.id].disconnect()
                        del self.imap_clients[credential.id]
                    except:
                        pass

    def _process_new_email(self, uid: str, credential_id: int) -> None:
        """
        Process a new email.

        Args:
            uid: Email UID
            credential_id: Email credential ID
        """
        session = self.session_factory()

        try:
            imap_client = self.imap_clients.get(credential_id)
            if not imap_client:
                self.logger.warning(f"No IMAP client for credential {credential_id}")
                return

            email = imap_client.fetch_email(uid)

            rule_engine = RuleEngine(imap_client, self.logger)
            email_processor = EmailProcessor(session, rule_engine, self.logger)

            result = email_processor.process_email(email, credential_id)

            self.service_manager.increment_emails_processed()
            self.service_manager.increment_rules_executed()

            self.logger.info(
                f"Email {uid} processed: {len(result.rules_matched)} rules matched, "
                f"{len(result.actions_taken)} actions taken"
            )

        except Exception as e:
            self.logger.error(f"Error processing email {uid}: {e}")

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
    service = EmailService()
    service.start()

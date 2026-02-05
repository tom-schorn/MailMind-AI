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

        migration_session = sessionmaker(bind=self.engine)()
        try:
            from db_migrations import DatabaseMigrator
            migrator = DatabaseMigrator(migration_session, self.logger)
            if migrator.needs_migration():
                self.logger.info("Database migration needed, running migrations...")
                migrator.migrate()
            else:
                self.logger.info("Database is up to date")
        finally:
            migration_session.close()

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
        Starts separate watchers for each monitored folder.

        Args:
            credential: EmailCredential to watch
        """
        self.logger.info(f"Starting email watcher for {credential.email_address}")

        session = self.session_factory()
        try:
            from Entities import EmailRule
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
        reconnect_delay = self.config.get('service', {}).get('imap_reconnect_delay', 30)

        while not self.stop_event.is_set():
            try:
                imap_client = IMAPClient(credential, self.config, self.logger)
                imap_client.connect()

                client_key = f"{credential.id}_{folder}"
                self.imap_clients[client_key] = imap_client

                unseen_uids = imap_client.get_unseen_uids(folder)
                for uid in unseen_uids:
                    self._process_new_email(uid, credential.id, folder)

                def callback(uid: str):
                    self._process_new_email(uid, credential.id, folder)

                def stop_check():
                    return self.stop_event.is_set()

                imap_client.watch(callback, stop_check, folder)

            except Exception as e:
                self.logger.error(f"Error in folder watcher for {folder}: {e}")
                time.sleep(reconnect_delay)

            finally:
                client_key = f"{credential.id}_{folder}"
                if client_key in self.imap_clients:
                    try:
                        self.imap_clients[client_key].disconnect()
                        del self.imap_clients[client_key]
                    except:
                        pass

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
    service = EmailService()
    service.start()

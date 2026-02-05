import logging
from datetime import datetime

from sqlalchemy.orm import Session

from DatabaseService import ServiceStatus


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

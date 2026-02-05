import logging
from sqlalchemy.orm import Session
from sqlalchemy import text
from Entities import DatabaseVersion


class DatabaseMigrator:
    """Handles automatic database migrations."""

    def __init__(self, session: Session, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.current_version = "1.1.0"

    def get_db_version(self) -> str:
        """Get current database version."""
        try:
            result = self.session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table' AND name='databaseversion'")
            ).fetchone()

            if not result:
                return "1.0.0"

            version = self.session.query(DatabaseVersion).order_by(
                DatabaseVersion.applied_at.desc()
            ).first()

            return version.version if version else "1.0.0"

        except Exception as e:
            self.logger.error(f"Error getting DB version: {e}")
            return "1.0.0"

    def needs_migration(self) -> bool:
        """Check if migration is needed."""
        db_version = self.get_db_version()
        return db_version != self.current_version

    def migrate(self) -> None:
        """Run all pending migrations."""
        db_version = self.get_db_version()
        self.logger.info(f"Current DB version: {db_version}, Target: {self.current_version}")

        if db_version == self.current_version:
            self.logger.info("Database is up to date")
            return

        if db_version == "1.0.0":
            self._migrate_1_0_0_to_1_1_0()

        self.logger.info(f"Migration completed: {db_version} -> {self.current_version}")

    def _migrate_1_0_0_to_1_1_0(self) -> None:
        """Migrate from v1.0.0 to v1.1.0 (add monitored_folder)."""
        self.logger.info("Running migration 1.0.0 -> 1.1.0")

        try:
            self.session.execute(text("""
                CREATE TABLE IF NOT EXISTS databaseversion (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version VARCHAR(20) NOT NULL UNIQUE,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    description VARCHAR(255)
                )
            """))

            result = self.session.execute(
                text("PRAGMA table_info(emailrule)")
            ).fetchall()

            columns = [row[1] for row in result]
            if 'monitored_folder' not in columns:
                self.session.execute(text("""
                    ALTER TABLE emailrule ADD COLUMN monitored_folder VARCHAR(200) NOT NULL DEFAULT 'INBOX'
                """))
                self.logger.info("Added monitored_folder column to emailrule")

            version_record = DatabaseVersion(
                version="1.1.0",
                description="Add monitored_folder to EmailRule"
            )
            self.session.add(version_record)
            self.session.commit()

            self.logger.info("Migration 1.0.0 -> 1.1.0 completed successfully")

        except Exception as e:
            self.session.rollback()
            self.logger.error(f"Migration failed: {e}")
            raise

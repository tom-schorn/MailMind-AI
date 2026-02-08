import logging
from sqlalchemy import String, Integer, Boolean, Text, DateTime, ForeignKey, func, text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class EmailCredential(Base):
    __tablename__ = "emailcredential"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_address: Mapped[str] = mapped_column(String(100), nullable=False)
    host: Mapped[str] = mapped_column(String(100), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    use_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    use_tls: Mapped[bool] = mapped_column(Boolean, default=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    changed_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp())

    rules = relationship("EmailRule", back_populates="email_account", cascade="all, delete-orphan")


class EmailRule(Base):
    __tablename__ = "emailrule"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_credential_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailcredential.id'), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    condition: Mapped[str] = mapped_column(Text, nullable=False)
    actions: Mapped[str] = mapped_column(Text, nullable=False)
    monitored_folder: Mapped[str] = mapped_column(String(200), nullable=False, default='INBOX')

    created_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    changed_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp())

    email_account = relationship("EmailCredential", back_populates="rules")
    conditions = relationship("RuleCondition", back_populates="rule", cascade="all, delete-orphan")
    rule_actions = relationship("RuleAction", back_populates="rule", cascade="all, delete-orphan")


class RuleCondition(Base):
    __tablename__ = "rulecondition"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailrule.id'), nullable=False)
    field: Mapped[str] = mapped_column(String(100), nullable=False)
    operator: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)

    rule = relationship("EmailRule", back_populates="conditions")


class RuleAction(Base):
    __tablename__ = "ruleaction"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailrule.id'), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    action_value: Mapped[str] = mapped_column(String(255), nullable=False)
    folder: Mapped[str] = mapped_column(String(200), nullable=True)
    label: Mapped[str] = mapped_column(String(200), nullable=True)

    rule = relationship("EmailRule", back_populates="rule_actions")


class ServiceStatus(Base):
    __tablename__ = "servicestatus"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    service_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    last_check: Mapped[DateTime] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, nullable=True)
    emails_processed: Mapped[int] = mapped_column(Integer, default=0)
    rules_executed: Mapped[int] = mapped_column(Integer, default=0)


class DryRunRequest(Base):
    __tablename__ = "dryrunrequest"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailrule.id'), nullable=False)
    email_credential_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailcredential.id'), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default='pending')
    max_emails: Mapped[int] = mapped_column(Integer, default=10)
    created_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    processed_at: Mapped[DateTime] = mapped_column(DateTime, nullable=True)

    results = relationship("DryRunResult", back_populates="request", cascade="all, delete-orphan")


class DryRunResult(Base):
    __tablename__ = "dryrunresult"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(Integer, ForeignKey('dryrunrequest.id'), nullable=False)
    email_uid: Mapped[str] = mapped_column(String(100), nullable=False)
    email_subject: Mapped[str] = mapped_column(String(255), nullable=True)
    email_from: Mapped[str] = mapped_column(String(255), nullable=True)
    email_date: Mapped[DateTime] = mapped_column(DateTime, nullable=True)
    matched: Mapped[bool] = mapped_column(Boolean, nullable=False)
    condition_results: Mapped[str] = mapped_column(Text, nullable=True)
    actions_would_apply: Mapped[str] = mapped_column(Text, nullable=True)

    request = relationship("DryRunRequest", back_populates="results")


class ProcessedEmail(Base):
    __tablename__ = "processedemail"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_credential_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailcredential.id'), nullable=False)
    email_uid: Mapped[str] = mapped_column(String(100), nullable=False)
    processed_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    rules_applied: Mapped[str] = mapped_column(Text, nullable=True)


class EmailRuleApplication(Base):
    __tablename__ = "emailruleapplication"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email_credential_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailcredential.id'), nullable=False)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailrule.id'), nullable=False)
    email_uid: Mapped[str] = mapped_column(String(100), nullable=False)
    applied_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    actions_taken: Mapped[str] = mapped_column(Text, nullable=True)


class Label(Base):
    __tablename__ = "label"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    credential_id: Mapped[int] = mapped_column(Integer, ForeignKey('emailcredential.id'), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    color: Mapped[str] = mapped_column(String(7), nullable=True)
    is_imap_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())

    credential = relationship("EmailCredential")


class DatabaseVersion(Base):
    __tablename__ = "databaseversion"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    applied_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    description: Mapped[str] = mapped_column(String(255), nullable=True)


class DatabaseMigrator:
    """Handles automatic database migrations."""

    def __init__(self, session: Session, logger: logging.Logger):
        self.session = session
        self.logger = logger
        self.current_version = "1.3.0"

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
            db_version = "1.1.0"

        if db_version == "1.1.0":
            self._migrate_1_1_0_to_1_2_0()
            db_version = "1.2.0"

        if db_version == "1.2.0":
            self._migrate_1_2_0_to_1_3_0()
            db_version = "1.3.0"

        self.logger.info(f"Migration completed to {self.current_version}")

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

    def _migrate_1_1_0_to_1_2_0(self) -> None:
        """Migrate from v1.1.0 to v1.2.0 (add per-rule email tracking)."""
        self.logger.info("Running migration 1.1.0 -> 1.2.0")

        try:
            self.session.execute(text("""
                CREATE TABLE IF NOT EXISTS emailruleapplication (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_credential_id INTEGER NOT NULL,
                    rule_id INTEGER NOT NULL,
                    email_uid VARCHAR(100) NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    actions_taken TEXT,
                    FOREIGN KEY (email_credential_id) REFERENCES emailcredential (id),
                    FOREIGN KEY (rule_id) REFERENCES emailrule (id)
                )
            """))
            self.logger.info("Created emailruleapplication table")

            version_record = DatabaseVersion(
                version="1.2.0",
                description="Add per-rule email tracking with EmailRuleApplication table"
            )
            self.session.add(version_record)
            self.session.commit()

            self.logger.info("Migration 1.1.0 -> 1.2.0 completed successfully")

        except Exception as e:
            self.session.rollback()
            self.logger.error(f"Migration failed: {e}")
            raise


    def _migrate_1_2_0_to_1_3_0(self) -> None:
        """Migrate from v1.2.0 to v1.3.0 (add Label table)."""
        self.logger.info("Running migration 1.2.0 -> 1.3.0")

        try:
            self.session.execute(text("""
                CREATE TABLE IF NOT EXISTS label (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id INTEGER NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    color VARCHAR(7),
                    is_imap_flag BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (credential_id) REFERENCES emailcredential (id)
                )
            """))
            self.logger.info("Created label table")

            version_record = DatabaseVersion(
                version="1.3.0",
                description="Add Label table for label management"
            )
            self.session.add(version_record)
            self.session.commit()

            self.logger.info("Migration 1.2.0 -> 1.3.0 completed successfully")

        except Exception as e:
            self.session.rollback()
            self.logger.error(f"Migration failed: {e}")
            raise


class DatabaseService:
    """Central database service providing session management and initialization."""

    def __init__(self, db_url: str):
        self.db_url = db_url
        self.engine = create_engine(db_url)
        self._session_factory = sessionmaker(bind=self.engine)

    def get_session(self) -> Session:
        """Creates a new database session."""
        return self._session_factory()

    def init_db(self):
        """Creates all tables if they don't exist."""
        Base.metadata.create_all(self.engine)

    def run_migrations(self, logger: logging.Logger):
        """Run database migrations if needed."""
        session = self.get_session()
        try:
            migrator = DatabaseMigrator(session, logger)
            if migrator.needs_migration():
                migrator.migrate()
        finally:
            session.close()

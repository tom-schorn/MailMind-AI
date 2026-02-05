from sqlalchemy import String, Integer, Boolean, Text, DateTime, ForeignKey, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, relationship
from sqlalchemy import create_engine


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


class DatabaseVersion(Base):
    __tablename__ = "databaseversion"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)
    applied_at: Mapped[DateTime] = mapped_column(DateTime, default=func.current_timestamp())
    description: Mapped[str] = mapped_column(String(255), nullable=True)


def create_session(engine) -> Session:
    """Creates a new database session"""
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def init_db(engine):
    """Creates all tables if they don't exist"""
    Base.metadata.create_all(engine)

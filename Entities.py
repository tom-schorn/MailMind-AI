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


def create_session(engine) -> Session:
    """Creates a new database session"""
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def init_db(engine):
    """Creates all tables if they don't exist"""
    Base.metadata.create_all(engine)

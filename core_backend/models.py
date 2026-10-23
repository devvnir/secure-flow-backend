from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, JSON, Enum, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
try:
    from sqlalchemy.dialects.postgresql import INET
except ImportError:
    from sqlalchemy import String as INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

Base = declarative_base()

class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DELETED = "deleted"

class SessionStatus(str, enum.Enum):
    VALID = "valid"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"

class AuditStatus(str, enum.Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"

class DataFlowStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"

class RunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100))
    last_name = Column(String(100))
    status = Column(String(50), default=UserStatus.ACTIVE)
    email_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime)
    two_factor_enabled = Column(Boolean, default=False)
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    deleted_at = Column(DateTime)

    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

class Session(Base):
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), unique=True, nullable=False)
    ip_address = Column(INET)
    user_agent = Column(Text)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    invalidated_at = Column(DateTime)

    user = relationship("User", back_populates="sessions")

class Role(Base):
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    permissions = Column(JSONB, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    users = relationship("User", secondary="user_roles", back_populates="roles")

class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    assigned_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint('user_id', 'role_id'),)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action = Column(String(255), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(UUID(as_uuid=True))
    changes = Column(JSONB)
    ip_address = Column(INET)
    user_agent = Column(Text)
    status = Column(String(50), default=AuditStatus.SUCCESS)
    error_message = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")

class DataFlow(Base):
    __tablename__ = "data_flows"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    source_type = Column(String(100), nullable=False)
    destination_type = Column(String(100), nullable=False)
    source_config = Column(JSONB)
    destination_config = Column(JSONB)
    encryption_enabled = Column(Boolean, default=True)
    status = Column(String(50), default=DataFlowStatus.DRAFT)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    runs = relationship("DataFlowRun", back_populates="flow", cascade="all, delete-orphan")
    records = relationship("IngestedRecord", cascade="all, delete-orphan", passive_deletes=True)

class DataFlowRun(Base):
    __tablename__ = "data_flow_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("data_flows.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(50), default=RunStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    records_processed = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    error_log = Column(JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)

    flow = relationship("DataFlow", back_populates="runs")

class IngestedRecord(Base):
    __tablename__ = "ingested_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flow_id = Column(UUID(as_uuid=True), ForeignKey("data_flows.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id = Column(UUID(as_uuid=True), ForeignKey("data_flow_runs.id", ondelete="CASCADE"), nullable=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    source_key = Column(String(255))
    data = Column(JSONB, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    last_used_at = Column(DateTime)
    expires_at = Column(DateTime)
    revoked_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="api_keys")

class EncryptionKey(Base):
    __tablename__ = "encryption_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    key_type = Column(String(100), nullable=False)
    public_key = Column(Text)
    key_hash = Column(String(255), unique=True, nullable=False)
    rotation_date = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

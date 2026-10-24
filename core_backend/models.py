from sqlalchemy import Column, String, Boolean, DateTime, Integer, Text, JSON, Enum, ForeignKey, UniqueConstraint, LargeBinary
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
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
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

class EnclaveRecord(Base):
    """Append-only, hash-chained forensic record of one enclave sanitization."""
    __tablename__ = "enclave_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    verdict = Column(String(20), nullable=False)
    detected_type = Column(String(30))
    input_sha256 = Column(String(64))
    output_sha256 = Column(String(64))
    report = Column(JSONB, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("user_id", "seq"),)

class VaultConfig(Base):
    """Client-side vault parameters. The passphrase and derived key never reach the server."""
    __tablename__ = "vault_configs"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    kdf = Column(String(50), nullable=False)
    iterations = Column(Integer, nullable=False)
    salt = Column(String(128), nullable=False)
    verifier_iv = Column(String(32), nullable=False)
    verifier_ct = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class VaultItem(Base):
    """A file encrypted in the browser with the vault key; the server stores ciphertext only."""
    __tablename__ = "vault_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    record_id = Column(UUID(as_uuid=True), ForeignKey("enclave_records.id", ondelete="SET NULL"), unique=True)
    name_iv = Column(String(32), nullable=False)
    name_ct = Column(Text, nullable=False)
    iv = Column(String(32), nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)
    size_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Signature(Base):
    """Single-party canvas signature: raw vector strokes, UTC timestamp and the server-observed session IP."""
    __tablename__ = "signatures"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    document_ref = Column(String(120), nullable=False)
    strokes = Column(JSONB, nullable=False)
    canvas_width = Column(Integer, nullable=False)
    canvas_height = Column(Integer, nullable=False)
    stroke_count = Column(Integer, nullable=False)
    point_count = Column(Integer, nullable=False)
    signed_at_utc = Column(String(32), nullable=False)
    ip_address = Column(INET, nullable=False)
    user_agent = Column(Text)
    session_jti = Column(String(64))
    signature_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("user_id", "document_ref"),)

class BillingCustomer(Base):
    __tablename__ = "billing_customers"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    stripe_customer_id = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    stripe_subscription_id = Column(String(64), nullable=False, unique=True)
    stripe_customer_id = Column(String(64), nullable=False)
    price_id = Column(String(64))
    status = Column(String(32), nullable=False)
    current_period_end = Column(DateTime)
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)
    last_event_created = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class StripeEvent(Base):
    """Idempotency log and payment ledger of every webhook event Stripe delivered."""
    __tablename__ = "stripe_events"

    id = Column(String(64), primary_key=True)
    type = Column(String(80), nullable=False)
    livemode = Column(Boolean, nullable=False, default=False)
    event_created = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), index=True)
    object_id = Column(String(64))
    amount = Column(Integer)
    currency = Column(String(8))
    error = Column(Text)
    payload = Column(JSONB, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed_at = Column(DateTime)

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

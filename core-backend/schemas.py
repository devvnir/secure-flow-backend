from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import UUID

# User Schemas
class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @validator('password')
    def validate_password(cls, v):
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain digit')
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    two_factor_enabled: Optional[bool] = None

class UserResponse(UserBase):
    id: UUID
    status: str
    email_verified: bool
    two_factor_enabled: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Authentication Schemas
class TokenRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Session Schemas
class SessionResponse(BaseModel):
    id: UUID
    user_id: UUID
    ip_address: Optional[str]
    user_agent: Optional[str]
    expires_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True

# Role Schemas
class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: List[str] = []

class RoleCreate(RoleBase):
    pass

class RoleResponse(RoleBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Audit Log Schemas
class AuditLogBase(BaseModel):
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[UUID] = None
    changes: Optional[Dict[str, Any]] = None
    status: str = "success"
    error_message: Optional[str] = None

class AuditLogCreate(AuditLogBase):
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

class AuditLogResponse(AuditLogBase):
    id: UUID
    user_id: Optional[UUID]
    timestamp: datetime

    class Config:
        from_attributes = True

# Data Flow Schemas
class DataFlowConfigBase(BaseModel):
    source_type: str
    destination_type: str
    source_config: Dict[str, Any]
    destination_config: Dict[str, Any]

class DataFlowCreate(DataFlowConfigBase):
    name: str
    description: Optional[str] = None
    encryption_enabled: bool = True

class DataFlowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    encryption_enabled: Optional[bool] = None
    source_config: Optional[Dict[str, Any]] = None
    destination_config: Optional[Dict[str, Any]] = None

class DataFlowResponse(DataFlowConfigBase):
    id: UUID
    name: str
    description: Optional[str]
    encryption_enabled: bool
    status: str
    created_by: UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Data Flow Run Schemas
class DataFlowRunCreate(BaseModel):
    flow_id: UUID

class DataFlowRunResponse(BaseModel):
    id: UUID
    flow_id: UUID
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    records_processed: int
    records_failed: int
    error_log: Optional[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True

# API Key Schemas
class APIKeyCreate(BaseModel):
    name: str

class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

# Encryption Key Schemas
class EncryptionKeyCreate(BaseModel):
    name: str
    key_type: str
    public_key: Optional[str] = None
    rotation_date: Optional[datetime] = None

class EncryptionKeyResponse(EncryptionKeyCreate):
    id: UUID
    key_hash: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

# Pagination Schemas
class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    limit: int = Field(20, ge=1, le=100)

class PaginatedResponse(BaseModel):
    data: List[Any]
    total: int
    page: int
    limit: int
    pages: int

# Error Response Schema
class ErrorResponse(BaseModel):
    status: int
    message: str
    error_code: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

# Data Ingestion Schemas for Milestone 2
class RESOQueryFilter(BaseModel):
    """Token-bound RESO Web API query filters"""
    resource: str = Field(..., description="RESO resource type (e.g., Property, Agent)")
    filter: Optional[str] = None
    select: Optional[List[str]] = None
    top: int = Field(100, ge=1, le=1000)
    skip: int = Field(0, ge=0)

class DataPayload(BaseModel):
    """Ingested data payload with validation"""
    id: str
    source: str
    timestamp: datetime
    data: Dict[str, Any]
    schema_version: str = "1.0"
    validation_status: str = "pending"

class SchemaMapping(BaseModel):
    """Dynamic schema translation mapping"""
    source_schema: str
    destination_schema: str
    field_mappings: Dict[str, str]
    transformations: Optional[Dict[str, str]] = None

class DataIngestionRequest(BaseModel):
    """Request to ingest data from external source"""
    flow_id: UUID
    source_type: str
    query_filters: Optional[RESOQueryFilter] = None
    validate_schema: bool = True

class DataIngestionResponse(BaseModel):
    """Response from data ingestion"""
    run_id: UUID
    flow_id: UUID
    status: str
    records_ingested: int
    records_validated: int
    records_failed: int
    error_details: Optional[Dict[str, Any]] = None
    timestamp: datetime

class BatchDataPayload(BaseModel):
    """Batch of data payloads for bulk ingestion"""
    flow_id: UUID
    payloads: List[DataPayload]
    schema_version: str = "1.0"

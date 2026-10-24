-- Secure Flow database schema (PostgreSQL 13+)
--
-- Mirrors core_backend/models.py table for table. The backend creates the same tables itself on
-- startup (init_db), so this file is for provisioning a database ahead of time or reviewing it.
-- Re-runnable: every statement is IF NOT EXISTS / CREATE OR REPLACE.
-- No extensions are required: gen_random_uuid() is built into PostgreSQL 13+, which keeps the
-- schema identical on x64 and Windows 11 ARM64 installs.
-- All timestamps are stored as UTC in TIMESTAMP WITHOUT TIME ZONE columns.

-- --------------------------------------------------------------------------
-- Identity and access
-- --------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    status VARCHAR(50) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended', 'deleted')),
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    deleted_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    invalidated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    UNIQUE (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    changes JSONB,
    ip_address INET,
    user_agent TEXT,
    status VARCHAR(50) DEFAULT 'success' CHECK (status IN ('success', 'failure', 'pending')),
    error_message TEXT,
    timestamp TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_type VARCHAR(100) NOT NULL,
    public_key TEXT,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    rotation_date TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

-- --------------------------------------------------------------------------
-- Data flows and ingestion (Milestone 2)
-- --------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS data_flows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(100) NOT NULL,
    destination_type VARCHAR(100) NOT NULL,
    source_config JSONB,
    destination_config JSONB,
    encryption_enabled BOOLEAN DEFAULT TRUE,
    status VARCHAR(50) DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'paused', 'archived')),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS data_flow_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID NOT NULL REFERENCES data_flows(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    records_processed INTEGER DEFAULT 0,
    records_failed INTEGER DEFAULT 0,
    error_log JSONB,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS ingested_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_id UUID NOT NULL REFERENCES data_flows(id) ON DELETE CASCADE,
    run_id UUID REFERENCES data_flow_runs(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_key VARCHAR(255),
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

-- --------------------------------------------------------------------------
-- Process enclave and crypto vault (Milestone 3)
-- --------------------------------------------------------------------------

-- Append-only, hash-chained record of each enclave sanitization.
CREATE TABLE IF NOT EXISTS enclave_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    verdict VARCHAR(20) NOT NULL,
    detected_type VARCHAR(30),
    input_sha256 VARCHAR(64),
    output_sha256 VARCHAR(64),
    report JSONB NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    UNIQUE (user_id, seq)
);

-- Client-side vault parameters; the passphrase and derived key never reach the server.
CREATE TABLE IF NOT EXISTS vault_configs (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    kdf VARCHAR(50) NOT NULL,
    iterations INTEGER NOT NULL,
    salt VARCHAR(128) NOT NULL,
    verifier_iv VARCHAR(32) NOT NULL,
    verifier_ct TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

-- Files encrypted in the browser; the server stores ciphertext only.
CREATE TABLE IF NOT EXISTS vault_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_id UUID UNIQUE REFERENCES enclave_records(id) ON DELETE SET NULL,
    name_iv VARCHAR(32) NOT NULL,
    name_ct TEXT NOT NULL,
    iv VARCHAR(32) NOT NULL,
    ciphertext BYTEA NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

-- --------------------------------------------------------------------------
-- Signatures and billing (Milestone 4)
-- --------------------------------------------------------------------------

-- Single-party canvas signature: raw vector strokes [[{x, y, t}, ...], ...], the UTC timestamp
-- string (YYYY-MM-DDTHH:MM:SS.mmmZ) and the session IP observed by the server.
CREATE TABLE IF NOT EXISTS signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document_ref VARCHAR(120) NOT NULL,
    strokes JSONB NOT NULL,
    canvas_width INTEGER NOT NULL,
    canvas_height INTEGER NOT NULL,
    stroke_count INTEGER NOT NULL,
    point_count INTEGER NOT NULL,
    signed_at_utc VARCHAR(32) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    session_jti VARCHAR(64),
    signature_hash VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    UNIQUE (user_id, document_ref)
);

CREATE TABLE IF NOT EXISTS billing_customers (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(64) UNIQUE NOT NULL,
    stripe_customer_id VARCHAR(64) NOT NULL,
    price_id VARCHAR(64),
    status VARCHAR(32) NOT NULL,
    current_period_end TIMESTAMP,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    -- Stripe event.created of the last applied event; older, out-of-order events are skipped.
    last_event_created INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    updated_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
);

-- Idempotency log and payment ledger of every webhook event Stripe delivered (id = evt_...).
CREATE TABLE IF NOT EXISTS stripe_events (
    id VARCHAR(64) PRIMARY KEY,
    type VARCHAR(80) NOT NULL,
    livemode BOOLEAN NOT NULL DEFAULT FALSE,
    event_created INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('received', 'processed', 'ignored', 'failed')),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    object_id VARCHAR(64),
    amount INTEGER,
    currency VARCHAR(8),
    error TEXT,
    payload JSONB NOT NULL,
    received_at TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'),
    processed_at TIMESTAMP
);

-- --------------------------------------------------------------------------
-- Indexes
-- --------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_encryption_keys_active ON encryption_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_data_flows_created_by ON data_flows(created_by);
CREATE INDEX IF NOT EXISTS idx_data_flows_status ON data_flows(status);
CREATE INDEX IF NOT EXISTS idx_data_flow_runs_flow_id ON data_flow_runs(flow_id);
CREATE INDEX IF NOT EXISTS idx_data_flow_runs_status ON data_flow_runs(status);
CREATE INDEX IF NOT EXISTS ix_ingested_records_flow_id ON ingested_records(flow_id);
CREATE INDEX IF NOT EXISTS ix_ingested_records_user_id ON ingested_records(user_id);
CREATE INDEX IF NOT EXISTS ix_enclave_records_user_id ON enclave_records(user_id);
CREATE INDEX IF NOT EXISTS ix_vault_items_user_id ON vault_items(user_id);
CREATE INDEX IF NOT EXISTS ix_signatures_user_id ON signatures(user_id);
CREATE INDEX IF NOT EXISTS ix_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS ix_stripe_events_user_id ON stripe_events(user_id);

-- --------------------------------------------------------------------------
-- updated_at maintenance (UTC)
-- --------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = (CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
DROP TRIGGER IF EXISTS roles_updated_at ON roles;
CREATE TRIGGER roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
DROP TRIGGER IF EXISTS data_flows_updated_at ON data_flows;
CREATE TRIGGER data_flows_updated_at BEFORE UPDATE ON data_flows FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
DROP TRIGGER IF EXISTS encryption_keys_updated_at ON encryption_keys;
CREATE TRIGGER encryption_keys_updated_at BEFORE UPDATE ON encryption_keys FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
DROP TRIGGER IF EXISTS subscriptions_updated_at ON subscriptions;
CREATE TRIGGER subscriptions_updated_at BEFORE UPDATE ON subscriptions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

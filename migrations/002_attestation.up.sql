-- 002_attestation.up.sql
-- Creates attestation_records table

CREATE TABLE IF NOT EXISTS attestation_records (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    account_id    VARCHAR(255) NOT NULL,
    project_id    VARCHAR(255) NOT NULL,
    level         VARCHAR(50) NOT NULL DEFAULT 'software',
    proof_type    VARCHAR(50) NOT NULL,
    proof_value   TEXT NOT NULL,
    proof_hash    VARCHAR(64) NOT NULL,
    verified_at   TIMESTAMPTZ,
    is_verified   BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at    TIMESTAMPTZ,
    is_expired    BOOLEAN NOT NULL DEFAULT FALSE,
    credential_id UUID REFERENCES issued_credentials(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attestation_records_identity_id
    ON attestation_records (identity_id);

CREATE INDEX IF NOT EXISTS idx_attestation_records_tenant
    ON attestation_records (account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_attestation_records_is_verified
    ON attestation_records (is_verified);

CREATE INDEX IF NOT EXISTS idx_attestation_records_expiry
    ON attestation_records (expires_at)
    WHERE is_verified = TRUE AND is_expired = FALSE;

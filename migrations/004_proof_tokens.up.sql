-- 004_proof_tokens.up.sql
-- Creates proof_tokens table for WIMSE Proof Token (WPT) tracking

CREATE TABLE IF NOT EXISTS proof_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id   UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    account_id    VARCHAR(255) NOT NULL,
    project_id    VARCHAR(255) NOT NULL,
    jti           VARCHAR(255) NOT NULL UNIQUE,
    nonce         VARCHAR(255) NOT NULL UNIQUE, -- for replay prevention
    audience      TEXT NOT NULL,               -- target service URI
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    is_used       BOOLEAN NOT NULL DEFAULT FALSE,
    used_at       TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_proof_tokens_identity_id
    ON proof_tokens (identity_id);

CREATE INDEX IF NOT EXISTS idx_proof_tokens_nonce
    ON proof_tokens (nonce);

CREATE INDEX IF NOT EXISTS idx_proof_tokens_expires_at
    ON proof_tokens (expires_at);

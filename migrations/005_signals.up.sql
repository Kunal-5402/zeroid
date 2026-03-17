-- 005_signals.up.sql
-- Creates cae_signals table for Continuous Access Evaluation signals

CREATE TABLE IF NOT EXISTS cae_signals (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   VARCHAR(255) NOT NULL,
    project_id   VARCHAR(255) NOT NULL,
    identity_id  UUID REFERENCES identities(id) ON DELETE SET NULL,
    signal_type  VARCHAR(50) NOT NULL,
    severity     VARCHAR(20) NOT NULL DEFAULT 'low',
    source       VARCHAR(255) NOT NULL,
    payload      JSONB,
    processed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cae_signals_identity_id
    ON cae_signals (identity_id);

CREATE INDEX IF NOT EXISTS idx_cae_signals_signal_type
    ON cae_signals (signal_type);

CREATE INDEX IF NOT EXISTS idx_cae_signals_created_at
    ON cae_signals (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cae_signals_tenant
    ON cae_signals (account_id, project_id);

CREATE INDEX IF NOT EXISTS idx_cae_signals_severity
    ON cae_signals (severity);

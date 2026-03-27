-- Migration 002: Brute-force protection enhancements.
-- Run against an existing deployment that already has the base schema.

ALTER TABLE portfolio_gate_attempts
    ADD COLUMN IF NOT EXISTS fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_attempts_fp_time
    ON portfolio_gate_attempts (fingerprint, attempted_at DESC)
    WHERE fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_attempts_failed_recent
    ON portfolio_gate_attempts (attempted_at DESC)
    WHERE success = false;

CREATE TABLE IF NOT EXISTS portfolio_gate_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    prefix TEXT NOT NULL,
    difficulty INT NOT NULL DEFAULT 18,
    ip INET NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '3 minutes')
);

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_challenges_expires
    ON portfolio_gate_challenges (expires_at)
    WHERE used = false;

CREATE TABLE IF NOT EXISTS portfolio_gate_fingerprint_lockout (
    fingerprint TEXT PRIMARY KEY,
    locked_until TIMESTAMPTZ NOT NULL,
    lockout_count INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

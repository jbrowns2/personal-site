-- Migration 005: Unified access code event log (success + incorrect entries),
-- lookup-hash attribution, and optional outreach metadata on codes.

-- A. Unified access code events (success + failure)
CREATE TABLE IF NOT EXISTS portfolio_gate_access_code_events (
    id BIGSERIAL PRIMARY KEY,
    code_id BIGINT REFERENCES portfolio_gate_access_codes(id) ON DELETE SET NULL,
    outcome TEXT NOT NULL CHECK (outcome IN (
        'success',
        'incorrect',
        'disabled_code',
        'expired_code'
    )),
    attempt_lookup_hash TEXT,
    ip INET,
    fingerprint TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gate_code_events_code_created
    ON portfolio_gate_access_code_events (code_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_gate_code_events_outcome_created
    ON portfolio_gate_access_code_events (outcome, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_gate_code_events_created
    ON portfolio_gate_access_code_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_gate_code_events_lookup_hash
    ON portfolio_gate_access_code_events (attempt_lookup_hash, created_at DESC)
    WHERE attempt_lookup_hash IS NOT NULL;

-- B. Lookup hash on codes (safe employer attribution for exact wrong entries)
ALTER TABLE portfolio_gate_access_codes
    ADD COLUMN IF NOT EXISTS code_lookup_hash TEXT UNIQUE;

-- C. Optional outreach metadata on codes
ALTER TABLE portfolio_gate_access_codes
    ADD COLUMN IF NOT EXISTS contact_name TEXT,
    ADD COLUMN IF NOT EXISTS contact_email TEXT,
    ADD COLUMN IF NOT EXISTS role_title TEXT,
    ADD COLUMN IF NOT EXISTS notes TEXT;

-- D. Historical backfill: one synthetic success per code with prior usage
INSERT INTO portfolio_gate_access_code_events (code_id, outcome, created_at)
SELECT id, 'success', last_used_at
FROM portfolio_gate_access_codes
WHERE last_used_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM portfolio_gate_access_code_events e
      WHERE e.code_id = portfolio_gate_access_codes.id
        AND e.outcome = 'success'
  );

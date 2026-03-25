-- Run once in Neon SQL Editor (or psql against your branch).
-- Portfolio access gate: attempt audit + lockouts (server-enforced rate limits).

CREATE TABLE IF NOT EXISTS portfolio_gate_attempts (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_attempts_ip_time
    ON portfolio_gate_attempts (ip, attempted_at DESC);

CREATE TABLE IF NOT EXISTS portfolio_gate_lockout (
    ip INET PRIMARY KEY,
    locked_until TIMESTAMPTZ NOT NULL,
    lockout_count INT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- If upgrading an existing deployment, run this migration:
-- ALTER TABLE portfolio_gate_lockout
--   ADD COLUMN IF NOT EXISTS lockout_count INT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS portfolio_gate_status_checks (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_status_checks_ip_time
    ON portfolio_gate_status_checks (ip, checked_at DESC);

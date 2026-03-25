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
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Optional: schedule in Neon or cron to prune old attempts (e.g. > 30 days).
-- DELETE FROM portfolio_gate_attempts WHERE attempted_at < now() - interval '30 days';

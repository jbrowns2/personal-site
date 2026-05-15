-- Migration 003: Move access codes from ACCESS_CODE_BCRYPT env var into a
-- managed table so codes can be added / disabled without redeploying.
-- Run against an existing deployment that already has the base schema.
--
-- Manage codes from the CLI with:
--   npm run gate:add -- "RAW CODE" "Label / company"
--   npm run gate:list
--   npm run gate:disable -- <id|label>

CREATE TABLE IF NOT EXISTS portfolio_gate_access_codes (
    id BIGSERIAL PRIMARY KEY,
    label TEXT NOT NULL,
    bcrypt_hash TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial index: only the rows the verify path actually scans.
CREATE INDEX IF NOT EXISTS idx_portfolio_gate_access_codes_active
    ON portfolio_gate_access_codes (id)
    WHERE active = true;

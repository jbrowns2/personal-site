-- Migration 006: Store normalized access code for local CLI reporting.
-- Plaintext is not recoverable from bcrypt_hash; this column is set at add/rotate
-- and backfilled for existing invitations.

ALTER TABLE portfolio_gate_access_codes
    ADD COLUMN IF NOT EXISTS access_code TEXT;

-- Backfill known codes (from job-application materials + prior lookup-hash work)
UPDATE portfolio_gate_access_codes SET access_code = 'RGA' WHERE id = 1;
UPDATE portfolio_gate_access_codes SET access_code = 'HCSC2026' WHERE id = 4;
UPDATE portfolio_gate_access_codes SET access_code = 'ABBVIE' WHERE id = 5;
UPDATE portfolio_gate_access_codes SET access_code = 'WTW2026' WHERE id = 6;
UPDATE portfolio_gate_access_codes SET access_code = 'AON2026' WHERE id = 7;
UPDATE portfolio_gate_access_codes SET access_code = 'CAPONE2026' WHERE id = 8;
UPDATE portfolio_gate_access_codes SET access_code = 'BRUNSWICK2026' WHERE id = 9;
UPDATE portfolio_gate_access_codes SET access_code = 'GRAINGER2026' WHERE id = 10;
UPDATE portfolio_gate_access_codes SET access_code = 'MARKEL2026' WHERE id = 11;
UPDATE portfolio_gate_access_codes SET access_code = 'CULLIGAN2026' WHERE id = 12;
UPDATE portfolio_gate_access_codes SET access_code = 'WINTRUST2026' WHERE id = 13;
UPDATE portfolio_gate_access_codes SET access_code = 'STEWARD2026' WHERE id = 14;
UPDATE portfolio_gate_access_codes SET access_code = 'ABBVIE' WHERE id = 15;
UPDATE portfolio_gate_access_codes SET access_code = 'MOTOROLA2026' WHERE id = 16;
UPDATE portfolio_gate_access_codes SET access_code = 'JPMC210741105' WHERE id = 17;
UPDATE portfolio_gate_access_codes SET access_code = 'WESTBEND3518' WHERE id = 18;
UPDATE portfolio_gate_access_codes SET access_code = 'LEXISR111919' WHERE id = 19;
UPDATE portfolio_gate_access_codes SET access_code = 'ROADSCHOLAR' WHERE id = 20;

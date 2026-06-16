-- Migration 007: Tag access codes with employment type so the portfolio
-- can show contract vs full-time tailored content after unlock.
--
-- Manage from the CLI with:
--   npm run gate:add -- "CODE" "Label" --type contract
--   npm run gate:add -- "CODE" "Label" --type full-time

ALTER TABLE portfolio_gate_access_codes
    ADD COLUMN IF NOT EXISTS employment_type TEXT
    CHECK (employment_type IS NULL OR employment_type IN ('contract', 'full_time'));

-- Existing codes default to full-time positioning.
UPDATE portfolio_gate_access_codes
SET employment_type = 'full_time'
WHERE employment_type IS NULL;

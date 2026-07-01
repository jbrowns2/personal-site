-- Migration 008: Per-job site profile slug for tailored contract unlocks.
--
-- Manage from the CLI with:
--   npm run gate:add -- "CODE" "Label" --type contract --profile beacon-hill-uat

ALTER TABLE portfolio_gate_access_codes
    ADD COLUMN IF NOT EXISTS profile_slug TEXT;

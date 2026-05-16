-- Migration 004: Self-service access request workflow.
--
-- Visitors without an access code submit a small form (name, email,
-- referral) which is recorded here. The site emails Jonathan a one-click
-- approval link; on approval, a new access code is auto-generated, stored in
-- portfolio_gate_access_codes, and emailed to the requester. This table is
-- the audit trail for that workflow.

CREATE TABLE IF NOT EXISTS portfolio_gate_access_requests (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    referral TEXT,
    ip INET,
    fingerprint TEXT,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    code_id BIGINT REFERENCES portfolio_gate_access_codes(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    last_notified_at TIMESTAMPTZ
);

-- Rate-limit lookups by email / ip / fingerprint within the recent window.
CREATE INDEX IF NOT EXISTS idx_portfolio_gate_access_requests_email_created
    ON portfolio_gate_access_requests (LOWER(email), created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_access_requests_ip_created
    ON portfolio_gate_access_requests (ip, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portfolio_gate_access_requests_fp_created
    ON portfolio_gate_access_requests (fingerprint, created_at DESC)
    WHERE fingerprint IS NOT NULL;

-- Pending requests waiting on Jonathan's approval.
CREATE INDEX IF NOT EXISTS idx_portfolio_gate_access_requests_pending
    ON portfolio_gate_access_requests (created_at DESC)
    WHERE status = 'pending';

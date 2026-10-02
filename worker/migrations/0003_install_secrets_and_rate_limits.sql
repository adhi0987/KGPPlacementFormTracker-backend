-- ============================================================
-- 0003: installation secrets + rate limiting
-- ============================================================
--
-- Why this exists
-- ---------------
-- Before this migration an installation_id alone was enough to
-- call /verify-license, /create-order and /restore-license.
-- An installation_id is stored in chrome.storage.local, appears
-- in the /checkout?installation_id=... URL and is sent to
-- Cashfree as customer_id, so it is not a secret.
--
-- We now issue a random secret alongside every installation.
-- Only its SHA-256 hash is stored, so a database leak does not
-- hand out working credentials.
--
-- The ERP notice data never reaches this Worker: entitlement is
-- verified with a server-signed token instead of by moving data
-- server-side.
-- ============================================================


CREATE TABLE IF NOT EXISTS installation_secrets (
    installation_id TEXT PRIMARY KEY,

    -- hex(sha256(secret)). The plaintext is returned exactly once,
    -- at registration, and never stored.
    secret_hash TEXT NOT NULL,

    created_at INTEGER NOT NULL,

    FOREIGN KEY (installation_id)
        REFERENCES installations(installation_id)
        ON DELETE CASCADE
);


-- ============================================================
-- RATE LIMITS
-- ============================================================
--
-- Fixed-window counters keyed by an opaque string such as
-- "verify:<installation_id>" or "create-order:<ip>".
-- ============================================================

CREATE TABLE IF NOT EXISTS rate_limits (
    rl_key TEXT PRIMARY KEY,

    count INTEGER NOT NULL,

    window_start INTEGER NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_installation_secrets_created_at
ON installation_secrets(created_at);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start
ON rate_limits(window_start);

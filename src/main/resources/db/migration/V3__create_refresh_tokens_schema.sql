-- =============================================================================
-- Vaultix Authorization Service - Flyway Migration V3
-- Schema: Refresh Tokens and Device Session Store
-- Database: PostgreSQL 18+ (using native uuidv7)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Refresh Tokens Table (Device Session Store)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_jti UUID NOT NULL UNIQUE,
    access_token_jti UUID NOT NULL UNIQUE,
    gen INT NOT NULL DEFAULT 1 CHECK (gen >= 1),
    device_info VARCHAR(256) NOT NULL,
    ip_address VARCHAR(64) NOT NULL,
    location_info VARCHAR(256) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active_user ON refresh_tokens(user_id) WHERE revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

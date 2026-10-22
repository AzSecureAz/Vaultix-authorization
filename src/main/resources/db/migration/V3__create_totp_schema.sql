-- =============================================================================
-- Vaultix Authorization Service - Flyway Migration V3
-- Schema: Time-Based One-Time Password (TOTP) Authenticator Store
-- Database: PostgreSQL 18+ (using native uuidv7)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Table: user_totp
-- Stores TOTP authenticator secrets and verification state for 2FA.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_totp (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    digits INT NOT NULL DEFAULT 6 CHECK (digits IN (6, 8)),
    period INT NOT NULL DEFAULT 30 CHECK (period IN (30, 60)),
    algorithm VARCHAR(16) NOT NULL DEFAULT 'SHA1' CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    last_used_step BIGINT,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);

-- Index for fast lookup of verified active TOTP enrollments
CREATE INDEX IF NOT EXISTS idx_user_totp_verified ON user_totp(user_id) WHERE verified = TRUE;

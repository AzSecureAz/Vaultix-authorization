-- =============================================================================
-- Vaultix Authorization Service - Flyway Migration V4
-- Schema: MFA Emergency Recovery Codes Store
-- Database: PostgreSQL 18+ (using native uuidv7)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Table: user_recovery_codes
-- Stores single-use emergency backup recovery codes for MFA account recovery.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(256) NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Foreign key index for cascade lookups and deletion
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_user_id ON user_recovery_codes(user_id);

-- Fast partial index for locating unused backup recovery codes during MFA challenge
CREATE INDEX IF NOT EXISTS idx_user_recovery_codes_unused ON user_recovery_codes(user_id) WHERE used = FALSE;

/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V7
 * Schema: WebAuthn Passkeys / User Credentials Store
 * Database: PostgreSQL 18+ (using native uuidv7)
 * ============================================================================= */

/* -----------------------------------------------------------------------------
 * 1. Table: user_credentials
 * Stores registered FIDO2 / WebAuthn passkey public keys and metadata.
 * ----------------------------------------------------------------------------- */
CREATE TABLE IF NOT EXISTS user_credentials (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id VARCHAR(512) NOT NULL UNIQUE,
    user_entity_user_id VARCHAR(256) NOT NULL,
    public_key BYTEA NOT NULL,
    signature_count BIGINT NOT NULL DEFAULT 0,
    uv_initialized BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    authenticator_transports VARCHAR(256),
    public_key_credential_type VARCHAR(64) NOT NULL DEFAULT 'public-key',
    attestation_object BYTEA,
    attestation_client_data_json BYTEA,
    label VARCHAR(128),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);

/* Index for fast lookup of a user's registered passkeys */
CREATE INDEX IF NOT EXISTS idx_user_credentials_user_id ON user_credentials(user_id);

/* Index for fast lookup by WebAuthn user handle / user entity id */
CREATE INDEX IF NOT EXISTS idx_user_credentials_user_entity_user_id ON user_credentials(user_entity_user_id);

/* Index for fast lookup of users with passkeys enabled */
CREATE INDEX IF NOT EXISTS idx_users_passkey_enabled ON users(id) WHERE passkey_enabled = TRUE;

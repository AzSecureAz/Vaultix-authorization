/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V9
 * Schema: Federated Identities / User Social Accounts Store
 * Database: PostgreSQL 18+ (using native uuidv7)
 * ============================================================================= */

/* -----------------------------------------------------------------------------
 * 1. Table: user_social_accounts
 * Links Vaultix users with external OAuth2 / OIDC providers (Google, GitHub, etc.)
 * ----------------------------------------------------------------------------- */
CREATE TABLE IF NOT EXISTS user_social_accounts (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_user_id VARCHAR(256) NOT NULL,
    email VARCHAR(256),
    display_name VARCHAR(256),
    avatar_url VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    CONSTRAINT uq_social_accounts_provider_user_id UNIQUE (provider, provider_user_id),
    CONSTRAINT uq_social_accounts_user_provider UNIQUE (user_id, provider)
);

/* Index for fast lookup of a user's linked social accounts */
CREATE INDEX IF NOT EXISTS idx_user_social_accounts_user_id ON user_social_accounts(user_id);

/* Index for fast reverse-lookup by provider and external user ID */
CREATE INDEX IF NOT EXISTS idx_user_social_accounts_provider_uid ON user_social_accounts(provider, provider_user_id);

/* Index for fast lookup of users with social accounts enabled */
CREATE INDEX IF NOT EXISTS idx_users_has_social_accounts ON users(id) WHERE has_social_accounts = TRUE;

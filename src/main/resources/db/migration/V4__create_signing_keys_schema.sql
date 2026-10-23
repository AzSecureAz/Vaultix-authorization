-- =============================================================================
-- Vaultix Authorization Service - Flyway Migration V4
-- Schema: Cryptographic JWT Signing Keys and Rotation Store
-- Database: PostgreSQL 18+ (using native uuidv7)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Table: signing_keys
-- Stores asymmetric RSA/EC key pairs for token signing, verification, and rotation.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    kid VARCHAR(64) NOT NULL UNIQUE,
    algorithm VARCHAR(16) NOT NULL DEFAULT 'RS256',
    key_use VARCHAR(16) NOT NULL DEFAULT 'sig',
    public_key_pem TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'ROTATED', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID
);

-- Ensure there is strictly at most one ACTIVE signing key at any given moment
CREATE UNIQUE INDEX IF NOT EXISTS uq_signing_keys_single_active ON signing_keys (status) WHERE status = 'ACTIVE';

-- Index for retrieving keys for JWKS endpoint (ACTIVE and ROTATED)
CREATE INDEX IF NOT EXISTS idx_signing_keys_jwks ON signing_keys (status) WHERE status IN ('ACTIVE', 'ROTATED');

-- -----------------------------------------------------------------------------
-- 2. Seed Key Management Permissions and Bind to ROLE_ADMIN
-- -----------------------------------------------------------------------------
INSERT INTO permissions (name, description) VALUES
    ('key:read', 'Allowed to view cryptographic signing key metadata and JWKS configurations'),
    ('key:rotate', 'Allowed to trigger cryptographic signing key rotation')
ON CONFLICT (name) DO NOTHING;

-- Grant new key permissions to ROLE_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN' AND p.name IN ('key:read', 'key:rotate')
ON CONFLICT DO NOTHING;

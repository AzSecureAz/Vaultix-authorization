-- =============================================================================
-- Migration: V1__init_auth_schema.sql
-- Description: Core authentication, RBAC, sessions, and audit schema with native UUIDv7
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Roles Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(256),
    level INT NOT NULL CHECK (level >= 0),
    status VARCHAR(16) NOT NULL DEFAULT 'ENABLED' CHECK (status IN ('ENABLED', 'DISABLED', 'DELETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID
);

CREATE INDEX IF NOT EXISTS idx_roles_status ON roles(status);
CREATE INDEX IF NOT EXISTS idx_roles_level ON roles(level);

-- -----------------------------------------------------------------------------
-- 2. Permissions Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name VARCHAR(128) NOT NULL UNIQUE,
    description VARCHAR(256),
    status VARCHAR(16) NOT NULL DEFAULT 'ENABLED' CHECK (status IN ('ENABLED', 'DISABLED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID
);

CREATE INDEX IF NOT EXISTS idx_permissions_status ON permissions(status);

-- -----------------------------------------------------------------------------
-- 3. Role Permissions Mapping Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- -----------------------------------------------------------------------------
-- 4. Users Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    username VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(256) NOT NULL UNIQUE,
    password_hash VARCHAR(256),
    full_name VARCHAR(256),
    phone_number VARCHAR(32),
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED', 'DELETED', 'EXPIRED')),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    passkey_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    has_social_accounts BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID,
    updated_at TIMESTAMPTZ,
    updated_by UUID
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- -----------------------------------------------------------------------------
-- 5. User Roles Mapping Table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- -----------------------------------------------------------------------------
-- 6. Refresh Tokens Table (Device Session Store)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_jti UUID NOT NULL UNIQUE,
    access_token_jti UUID NOT NULL UNIQUE,
    gen INT NOT NULL DEFAULT 1 CHECK (gen >= 1),
    device_info VARCHAR(256) NOT NULL,
    ip_address VARCHAR(64) NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active_user ON refresh_tokens(user_id) WHERE revoked = FALSE;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- -----------------------------------------------------------------------------
-- 7. Seed Default Roles and Permissions
-- -----------------------------------------------------------------------------
INSERT INTO roles (name, description, level) VALUES
    ('ROLE_ADMIN', 'Platform super administrator with highest privileges', 0)
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    -- User Management
    ('user:create', 'Allowed to create new user accounts'),
    ('user:read', 'Allowed to view user profiles and listings'),
    ('user:update', 'Allowed to update user details and account status'),
    ('user:delete', 'Allowed to delete or deactivate user accounts'),

    -- Role Management
    ('role:create', 'Allowed to create new roles'),
    ('role:read', 'Allowed to view existing roles and hierarchies'),
    ('role:update', 'Allowed to edit role details, levels, and status'),
    ('role:delete', 'Allowed to delete roles'),

    -- Permission Management
    ('permission:read', 'Allowed to view system permissions')
ON CONFLICT (name) DO NOTHING;

-- Grant all permissions to ROLE_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN'
ON CONFLICT DO NOTHING;

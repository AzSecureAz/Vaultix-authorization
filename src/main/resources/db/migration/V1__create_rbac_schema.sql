-- =============================================================================
-- Vaultix Authorization Service - Flyway Migration V1
-- Schema: Hierarchical Roles, Permissions, Role Mappings, and Baseline Seed
-- Database: PostgreSQL 18+ (using native uuidv7)
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
-- 4. Seed Default Roles and Permissions
-- -----------------------------------------------------------------------------
INSERT INTO roles (name, description, level) VALUES
    ('ROLE_ADMIN', 'Platform administrator with administrative privileges', 1000)
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (name, description) VALUES
    -- User Management
    ('user:create', 'Allowed to create new user accounts'),
    ('user:read', 'Allowed to view user profiles and listings'),
    ('user:update', 'Allowed to update user details and account status'),
    ('user:delete', 'Allowed to delete or deactivate user accounts'),
    ('user:restore', 'Allowed to restore soft-deleted user accounts'),

    -- Role Management
    ('role:create', 'Allowed to create new roles'),
    ('role:read', 'Allowed to view existing roles and hierarchies'),
    ('role:update', 'Allowed to edit role details, levels, and status'),
    ('role:delete', 'Allowed to delete or deactivate roles'),
    ('role:restore', 'Allowed to restore soft-deleted roles'),

    -- Permission Management
    ('permission:read', 'Allowed to view system permissions')
ON CONFLICT (name) DO NOTHING;

-- Grant all permissions to ROLE_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN'
ON CONFLICT DO NOTHING;

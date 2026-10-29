/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V12
 * Schema: Roles Search and Audit Indexes
 * Database: PostgreSQL 18+ (using pg_trgm for text search)
 * ============================================================================= */

/* Ensure pg_trgm extension is active for trigram GIN text search */
CREATE EXTENSION IF NOT EXISTS pg_trgm;

/* GIN trigram index on role name for accelerated wildcard / substring LIKE queries */
CREATE INDEX IF NOT EXISTS idx_roles_name_trgm ON roles USING gin (name gin_trgm_ops);

/* GIN trigram expression index on UPPER(name) for case-insensitive uppercase LIKE queries */
CREATE INDEX IF NOT EXISTS idx_roles_name_upper_trgm ON roles USING gin (UPPER(name) gin_trgm_ops);

/* B-Tree index on created_at for default sorting and date range queries */
CREATE INDEX IF NOT EXISTS idx_roles_created_at ON roles(created_at DESC);

/* B-Tree index on updated_at for date range queries and cleanup batches */
CREATE INDEX IF NOT EXISTS idx_roles_updated_at ON roles(updated_at);

/* B-Tree index on created_by for creator actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_roles_created_by ON roles(created_by);

/* B-Tree index on updated_by for updater actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_roles_updated_by ON roles(updated_by);

/* B-Tree index on role_permissions(permission_id) for accelerating permission-based role queries */
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V10
 * Schema: Permissions Search and Audit Indexes
 * Database: PostgreSQL 18+ (using pg_trgm for text search)
 * ============================================================================= */

/* Enable pg_trgm extension for fast trigram GIN text search */
CREATE EXTENSION IF NOT EXISTS pg_trgm;

/* GIN trigram index on permission name for accelerated wildcard / substring LIKE queries */
CREATE INDEX IF NOT EXISTS idx_permissions_name_trgm ON permissions USING gin (name gin_trgm_ops);

/* GIN trigram expression index on LOWER(name) for case-insensitive lowercase LIKE queries */
CREATE INDEX IF NOT EXISTS idx_permissions_name_lower_trgm ON permissions USING gin (LOWER(name) gin_trgm_ops);

/* B-Tree index on updated_at for timestamp range queries */
CREATE INDEX IF NOT EXISTS idx_permissions_updated_at ON permissions(updated_at);

/* B-Tree index on updated_by for updater actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_permissions_updated_by ON permissions(updated_by);

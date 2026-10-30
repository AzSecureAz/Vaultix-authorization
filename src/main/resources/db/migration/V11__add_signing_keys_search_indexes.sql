/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V11
 * Schema: Signing Keys Search and Audit Indexes
 * Database: PostgreSQL 18+ (using pg_trgm for text search)
 * ============================================================================= */

/* Ensure pg_trgm extension is active for trigram GIN text search */
CREATE EXTENSION IF NOT EXISTS pg_trgm;

/* GIN trigram expression index on LOWER(kid) for wildcard / substring queries */
CREATE INDEX IF NOT EXISTS idx_signing_keys_kid_lower_trgm ON signing_keys USING gin (LOWER(kid) gin_trgm_ops);

/* B-Tree index on status to cover all statuses (ACTIVE, ROTATED, REVOKED) */
CREATE INDEX IF NOT EXISTS idx_signing_keys_status ON signing_keys(status);

/* B-Tree index on created_at for default sorting and date range queries */
CREATE INDEX IF NOT EXISTS idx_signing_keys_created_at ON signing_keys(created_at DESC);

/* B-Tree index on updated_at for date range queries and cleanup batches */
CREATE INDEX IF NOT EXISTS idx_signing_keys_updated_at ON signing_keys(updated_at);

/* B-Tree index on created_by for creator actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_signing_keys_created_by ON signing_keys(created_by);

/* B-Tree index on updated_by for updater actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_signing_keys_updated_by ON signing_keys(updated_by);

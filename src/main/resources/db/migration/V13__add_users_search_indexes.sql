/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V13
 * Schema: Users Search, Audit, and Association Indexes
 * Database: PostgreSQL 18+ (using pg_trgm for text search)
 * ============================================================================= */

/* Ensure pg_trgm extension is active for trigram GIN text search */
CREATE EXTENSION IF NOT EXISTS pg_trgm;

/* GIN trigram expression index on LOWER(username) for wildcard / substring queries */
CREATE INDEX IF NOT EXISTS idx_users_username_lower_trgm ON users USING gin (LOWER(username) gin_trgm_ops);

/* GIN trigram expression index on LOWER(email) for wildcard / substring queries */
CREATE INDEX IF NOT EXISTS idx_users_email_lower_trgm ON users USING gin (LOWER(email) gin_trgm_ops);

/* GIN trigram expression index on LOWER(full_name) for wildcard / substring queries */
CREATE INDEX IF NOT EXISTS idx_users_full_name_lower_trgm ON users USING gin (LOWER(full_name) gin_trgm_ops);

/* GIN trigram index on phone_number for wildcard / substring queries */
CREATE INDEX IF NOT EXISTS idx_users_phone_number_trgm ON users USING gin (phone_number gin_trgm_ops);

/* B-Tree index on created_at for default sorting and date range queries */
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);

/* B-Tree index on updated_at for date range queries and cleanup batches */
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at);

/* B-Tree index on created_by for creator actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_users_created_by ON users(created_by);

/* B-Tree index on updated_by for updater actor ID filtering */
CREATE INDEX IF NOT EXISTS idx_users_updated_by ON users(updated_by);

/* B-Tree index on locked_until for account lockout range queries and unlock batches */
CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);

/* B-Tree index on last_login_at for activity range queries */
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);

/* B-Tree index on user_roles(role_id) for accelerating role-based user filtering */
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

/* =============================================================================
 * Vaultix Authorization Service - Flyway Migration V8
 * Schema: Add SMS / Phone Multi-Factor Authentication Flag to Users
 * Database: PostgreSQL 18+ (using native uuidv7)
 * ============================================================================= */

/* -----------------------------------------------------------------------------
 * 1. Alter users table to add sms_mfa_enabled flag
 * ----------------------------------------------------------------------------- */
ALTER TABLE users ADD COLUMN IF NOT EXISTS sms_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;

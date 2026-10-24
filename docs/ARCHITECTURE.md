# Vaultix Authorization - Core Security Architecture

This document provides a comprehensive technical breakdown of the security subsystems, cryptographic primitives, distributed caching, and lifecycle management within the **Vaultix Authorization Service**.

---

## Architectural Data Flow

```
                               ┌──────────────────────────────────────────────────────────┐
                               │                   PostgreSQL (Auth DB)                   │
                               │  • users (UUIDv7, Argon2id passwords)                    │
                               │  • roles & permissions (Hierarchical RBAC)               │
                               │  • refresh_tokens (SHA-256 hash, ClientCtx, Generation)  │
                               │  • signing_keys (RSA-2048 encrypted by AES-256 GCM KEK)  │
                               └────────────────────────────┬─────────────────────────────┘
                                                            │
Client Request ──► Gateway ──► Controllers ──► Service Layer (Transactional)
                                                            │
                               ┌────────────────────────────┴─────────────────────────────┐
                               │                          Redis                           │
                               │  • JTI token blacklist (`auth:blacklist:*`)              │
                               │  • Disabled roles hash (`auth:role:disabled`)            │
                               │  • Disabled permissions hash (`auth:permission:disabled`)│
                               │  • Pub/Sub revocation broadcast channels                 │
                               └──────────────────────────────────────────────────────────┘
```

---

## 1. Dynamic Asymmetric Signing Keys (RSA-2048)
- Active signing keys are generated and stored in PostgreSQL (`signing_keys` table).
- Private keys are encrypted at rest using authenticated **AES-256 GCM** with a Key Encryption Key (`KEK`).
- Local in-memory caching with **Caffeine** and cluster-wide eviction across microservices via **Redis Pub/Sub** (`auth:signing-key:revocation`).
- Scheduled automatic key rotation via `SigningKeyScheduler`.

## 2. JWT Access Tokens
- Signed with active RSA-2048 private key via Nimbus JOSE.
- Claims: `iss`, `sub` (User UUID), `jti` (UUIDv7), `token_type: access`, `roles_permissions` map, `iat`, `exp` (15 min default).
- Subject UUID is validated early at the filter layer via `SecurityUtil.extractActorId(jwt)` during `CustomJwtAuthenticationConverter` processing.

## 3. Refresh Token Rotation & Session Tracking
- Stored as a **SHA-256 hash** in PostgreSQL (`refresh_tokens` table) to prevent plaintext exposure upon database breach.
- **Client Context Binding**: Every session persists client `ipAddress`, `deviceInfo` (up to 256 chars), and `locationInfo`.
- **Generation Tracking (`gen`) & Reuse Detection**: Tokens carry an incrementing generation counter. Presenting a revoked or previously rotated token instantly invalidates the session family.
- Transmitted as an **`HttpOnly`**, **`SameSite=Strict`** cookie restricted to `/api/v1/auth/public/refresh` via `AuthCookieHelper`.

## 4. Real-Time Distributed Revocation
- **Disabled Roles & Permissions**: When an admin disables a role or permission, the entity status is updated and persisted in Redis hashes (`auth:role:disabled`, `auth:permission:disabled`) with an explicit TTL matching token lifetime.
- **Transactional Synchronization**: Redis invalidation broadcast occurs strictly inside `TransactionSynchronization.afterCommit()` to ensure downstream instances only evict after database commit.
- **Token Blacklisting**: JTI blacklist in Redis (`auth:blacklist:<jti>`) rejects revoked tokens instantly before expiration.

## 5. Hierarchical RBAC & Privilege Protection
- **Role Hierarchy**: Roles maintain a numeric `level` (lower numeric value = higher privilege).
- **Role Governance**: Administrators cannot create, modify, enable, or disable roles with a privilege level equal to or higher than their own active role level (`level <= actorHighestLevel`). Permissions assigned to a role must already be possessed by the actor.
- **User Governance**: Administrators cannot provision or assign roles with a privilege level equal to or higher than their own (`level <= actorHighestLevel`). Administrators cannot edit or modify users whose highest role (active or disabled) is equal to or more privileged than the actor (`targetUserHighestLevel <= actorHighestLevel`).
- **Batch Error Aggregation**: Missing, disabled, and level-violating roles or permissions are collected and reported as complete sets at once rather than failing one by one.
- **Session Revocation on Privilege Change**: Modifying a user's roles automatically revokes all refresh token sessions in PostgreSQL and schedules JTI blacklisting in Redis after transaction commit via `TokenService.revokeAllUserTokens`.
- **Change Detection**: Role and user updates evaluate whether any attributes or roles actually changed. If identical, database updates, audit timestamp updates (`updated_at`, `updated_by`), and token revocations are skipped.

## 6. Centralized Error Handling & Spring 6.1+ Method Validation
- **`GlobalExceptionHandler`**: Inherits `BaseGlobalExceptionHandler` from `common`, returning standard `ApiResponse.error(...)` envelopes across all endpoints.
- **Native Method Validation**: Utilizes Spring MVC 6.1+ native `HandlerMethodValidationException` for request parameter constraints (e.g. cookie length limits) without requiring class-level `@Validated` proxies on controllers.
- **Security Leak Prevention**: Masks internal service exceptions (`InternalAuthenticationServiceException`) as generic `"Authentication failed"` to prevent leaking database or connection details to clients.

## 7. Event-Driven Notifications (RabbitMQ)
- Declares **`auth.exchange`** (`TopicExchange`) for cross-service asynchronous event dispatch.
- **Welcome Notification**: Dispatched upon user registration (`/public/register`) with routing key `auth.notification.welcome`.
- **Password Reset**: Dispatched when requesting password reset (`/public/password-reset/request`) with a cryptographically secure 6-digit OTP to routing key `auth.notification.password-reset`.
- **Password Changed**: Dispatched when an authenticated user updates their password (`/password/change`) with security alert details to routing key `auth.notification.password-changed`.
- **Email Verification**: Dispatched when an authenticated user requests verification (`/email/send-verification`) with a 6-digit OTP and 60-second Redis rate-limit cooldown to routing key `auth.notification.email-verification`.
- **Email Changed**: Dispatched upon confirming an email change (`/email/change/confirm`) with a 7-day secure revert token link sent to the old address to routing key `auth.notification.email-changed`.
- **Email Reverted**: Dispatched when an email address is reverted via secure token (`/public/email/revert`) notifying the account holder to routing key `auth.notification.email-reverted`.
- **MFA Enabled**: Dispatched when TOTP two-factor authentication is activated (`/mfa/totp/activate`) to routing key `auth.notification.mfa-enabled`.
- **MFA Disabled**: Dispatched when two-factor authentication is disabled (`/mfa/totp/disable`) to routing key `auth.notification.mfa-disabled`.
- **Emergency Recovery Code Used**: Dispatched when an emergency recovery code is burned to sign in (`/public/login/mfa`), alerting the account holder with remaining code count, IP, device, and timestamp to routing key `auth.notification.recovery-code-used`.
- **Emergency Recovery Codes Regenerated**: Dispatched when emergency recovery codes are regenerated (`/mfa/totp/recovery-codes/regenerate`), alerting the account holder that previous codes were invalidated and reporting the fresh code count to routing key `auth.notification.recovery-codes-regenerated`.
- Downstream notification services subscribe using the wildcard pattern **`auth.notification.*`** without coupling to internal authorization logic.

## 8. Platform-Wide Snake Case JSON (`SNAKE_CASE`)
- Enforces `spring.jackson.property-naming-strategy: SNAKE_CASE` across all DTOs and endpoints, eliminating manual `@JsonProperty` boilerplate while providing clean REST conventions for clients.

## 9. Distributed Scheduled Maintenance & ShedLock Coordination
Automated background tasks run on distributed staggered schedules using Spring `@Scheduled` and ShedLock (`@SchedulerLock`) to ensure single-instance execution across multi-node clusters:

| Scheduler | Cron Schedule | Task | Grace Period | Batch Size | Lock Duration (`min` / `max`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`SigningKeyScheduler`** | `0 0 2 * * ?` (02:00 AM) | Asymmetric RSA-2048 key rotation | &mdash; | &mdash; | `5m` / `15m` |
| **`SigningKeyScheduler`** | `0 10 2 * * ?` (02:10 AM) | Purge expired/retired RSA keys | `7d` | `100` | `5m` / `15m` |
| **`RefreshTokenScheduler`** | `0 20 2 * * ?` (02:20 AM) | Purge expired/revoked refresh sessions | `7d` | `500` | `5m` / `15m` |
| **`RoleScheduler`** | `0 30 2 * * ?` (02:30 AM) | Hard delete soft-deleted roles | `30d` | `100` | `5m` / `15m` |
| **`UserScheduler`** | `0 40 2 * * ?` (02:40 AM) | Hard delete soft-deleted users | `90d` | `100` | `5m` / `15m` |

- **Cascading Purges**: Hard deletion of soft-deleted users in PostgreSQL automatically cascades (`ON DELETE CASCADE`) to mapped `user_roles` and associated `refresh_tokens`.
- **Bounded Batch Processing**: Native SQL subquery deletion loops (`LIMIT :limit`) prevent transaction timeouts and lock contention on high-volume tables.

## 10. Multi-Factor Authentication (TOTP & Emergency Recovery Codes)
- **RFC 6238 TOTP Authenticator**: Generates 20-byte cryptographically secure secrets encoded in Base32. The private secret is encrypted at rest using authenticated **AES-256 GCM** with the platform Key Encryption Key (`KEK`). Enforces strict 30-second time-steps with a $\pm 1$ drift tolerance window (90-second validity) and replay protection via database tracking (`last_used_step`).
- **Single-Use Emergency Recovery Codes**: Generates 10 single-use `xxxxx-xxxxx` codes upon TOTP activation or on-demand regeneration (`/mfa/totp/recovery-codes/regenerate`). Plaintext codes are normalized and stored as **SHA-256 hashes** in PostgreSQL (`user_recovery_codes`). Using a recovery code permanently burns the entry and triggers an immediate security alert email (`auth.notification.recovery-code-used`) reporting the remaining code count, IP address, device info, and UTC timestamp.
- **Zero-Waste Factor Routing**: The `/public/login/mfa` verification endpoint routes using an explicit `factor` parameter (`"totp"`, `"recovery_code"`) or auto-detects based on code length (6 digits for TOTP vs 10 characters for recovery codes).

## 11. WebAuthn Passkeys (FIDO2 / W3C WebAuthn Passwordless Authentication)
- **Native Spring Security 7.x WebAuthn**: Implements W3C WebAuthn Level 3 passkey registration and authentication using `spring-security-webauthn`.
- **Passkey Persistence**: Credentials stored in PostgreSQL (`user_credentials` table) mapped to `UserPasskeyCredential` JPA entity with UUIDv7, updatable = false on immutable cryptographic elements, and cascade delete foreign keys linked to `users(id)`.
- **Stateless Redis Challenge Store**: `RedisPublicKeyCredentialCreationOptionsRepository` persists registration challenges in Redis with a 5-minute TTL (`auth:webauthn:challenge:*`) and dual-resolution via secure cookie (`VAULTIX_WEBAUTHN_CHALLENGE`) or authenticated user principal fallback.
- **Custom Auth Handlers**: `WebAuthnAuthenticationSuccessHandler` issues standard Vaultix JWT access tokens and secure refresh token cookies upon passkey assertion, while `WebAuthnAuthenticationFailureHandler` outputs standardized `ApiResponse.error(...)` 401 envelopes.
- **Passkey Lifecycle Management**: Authenticated REST API (`/mfa/passkeys`) allowing users to view registered passkeys (with authenticator transports and usage metadata), rename labels, and delete passkeys with automatic synchronization of `user.passkey_enabled`.

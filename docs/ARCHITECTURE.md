# Vaultix Authorization - Core Security Architecture

This document provides a comprehensive technical breakdown of the security subsystems, cryptographic primitives, distributed caching, and lifecycle management within the **Vaultix Authorization Service**.

---

## Architectural Data Flow

```
                               ┌──────────────────────────────────────────────────────────┐
                               │                   PostgreSQL (Auth DB)                   │
                               │  • users (UUIDv7, Argon2id passwords, SMS/TOTP flags)    │
                               │  • user_social_accounts (Google & GitHub provider links) │
                               │  • roles & permissions (Hierarchical RBAC)               │
                               │  • refresh_tokens (SHA-256 hash, ClientCtx, Generation)  │
                               │  • signing_keys (RSA-2048 encrypted by AES-256 GCM KEK)  │
                               │  • user_credentials (FIDO2 / WebAuthn passkey public keys│
                               └────────────────────────────┬─────────────────────────────┘
                                                            │
Client Request ──► Gateway ──► Controllers ──► Service Layer (Transactional)
                                                            │
                               ┌────────────────────────────┴─────────────────────────────┐
                               │                          Redis                           │
                               │  • JTI token blacklist (`auth:blacklist:*`)              │
                               │  • Disabled roles/permissions hashes                     │
                               │  • WebAuthn challenge stores (stateless session-free)    │
                               │  • OTP verification cooldowns (`auth:cooldown:*`)        │
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
- Downstream notification services subscribe using the wildcard pattern **`auth.notification.*`** without coupling to internal authorization logic.
- Supported routing keys:
  - `auth.notification.welcome`: Dispatched upon user registration (`/public/register`).
  - `auth.notification.password-reset`: Dispatched when requesting password reset (`/public/password-reset/request`) with a cryptographically secure 6-digit OTP.
  - `auth.notification.password-changed`: Dispatched when an authenticated user updates their password (`/password/change`).
  - `auth.notification.email-verification`: Dispatched when requesting email verification OTP with 60s Redis cooldown.
  - `auth.notification.email-changed`: Dispatched upon confirming an email change with a 7-day secure revert token link sent to the old address.
  - `auth.notification.email-reverted`: Dispatched when an email address is reverted via secure token (`/public/email/revert`).
  - `auth.notification.phone-verification`: Dispatched when requesting SMS phone verification OTP with 60s Redis cooldown.
  - `auth.notification.phone-changed`: Dispatched upon confirming a phone number update.
  - `auth.notification.mfa-enabled`: Dispatched when TOTP or SMS two-factor authentication is activated.
  - `auth.notification.mfa-disabled`: Dispatched when two-factor authentication is disabled.
  - `auth.notification.recovery-code-used`: Dispatched when an emergency recovery code is burned to sign in.
  - `auth.notification.recovery-codes-regenerated`: Dispatched when emergency recovery codes are regenerated.
  - `auth.notification.passkey-added`: Dispatched when a new WebAuthn passkey credential is registered.
  - `auth.notification.passkey-removed`: Dispatched when a WebAuthn passkey is deleted.
  - `auth.notification.social-account-linked`: Dispatched when a Google or GitHub account is linked to the user.
  - `auth.notification.social-account-unlinked`: Dispatched when a Google or GitHub account is unlinked.

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

- **Cascading Purges**: Hard deletion of soft-deleted users in PostgreSQL automatically cascades (`ON DELETE CASCADE`) to mapped `user_roles`, `refresh_tokens`, `user_credentials`, and `user_social_accounts`.
- **Bounded Batch Processing**: Native SQL subquery deletion loops (`LIMIT :limit`) prevent transaction timeouts and lock contention on high-volume tables.

## 10. Multi-Factor Authentication (TOTP & Emergency Recovery Codes)
- **RFC 6238 TOTP Authenticator**: Generates 20-byte cryptographically secure secrets encoded in Base32. The private secret is encrypted at rest using authenticated **AES-256 GCM** with the platform Key Encryption Key (`KEK`). Enforces strict 30-second time-steps with a $\pm 1$ drift tolerance window (90-second validity) and replay protection via database tracking (`last_used_step`).
- **Single-Use Emergency Recovery Codes**: Generates 10 single-use `xxxxx-xxxxx` codes upon TOTP or SMS MFA activation or on-demand regeneration (`/mfa/recovery-codes/regenerate`). Plaintext codes are normalized and stored as **SHA-256 hashes** in PostgreSQL (`user_recovery_codes`). Using a recovery code permanently burns the entry and triggers an immediate security alert email (`auth.notification.recovery-code-used`) reporting the remaining code count, IP address, device info, and UTC timestamp.
- **Zero-Waste Factor Routing**: The `/public/login/mfa` verification endpoint routes using an explicit `factor` parameter (`"totp"`, `"sms"`, `"recovery_code"`) or auto-detects based on code format (6 digits for TOTP/SMS vs 10 characters for recovery codes).

## 11. WebAuthn Passkeys (FIDO2 / W3C WebAuthn Passwordless Authentication)
- **Native Spring Security 7.x WebAuthn**: Implements W3C WebAuthn Level 3 passkey registration and authentication using `spring-security-webauthn`.
- **Passkey Persistence**: Credentials stored in PostgreSQL (`user_credentials` table) mapped to `UserPasskeyCredential` JPA entity with UUIDv7, updatable = false on immutable cryptographic elements, and cascade delete foreign keys linked to `users(id)`.
- **Stateless Distributed Redis Challenge Stores**:
  - **Registration Challenges**: `RedisPublicKeyCredentialCreationOptionsRepository` persists creation options in Redis with a 5-minute TTL (`auth:webauthn:challenge:*`) and dual-resolution via secure cookie (`VAULTIX_WEBAUTHN_CHALLENGE`) or authenticated user principal fallback.
  - **Authentication Challenges**: `RedisPublicKeyCredentialRequestOptionsRepository` persists authentication request options in Redis with a 5-minute TTL (`auth:webauthn:auth-challenge:*`) and dual-resolution via secure cookie (`VAULTIX_WEBAUTHN_AUTH_CHALLENGE`) or request header (`X-WebAuthn-Challenge`). Challenges are single-use and evicted immediately upon verification to prevent replay attacks.
  - **Zero-Session Architecture**: Wired into `PublicKeyCredentialRequestOptionsFilter` and post-processed onto `WebAuthnAuthenticationFilter`, completely eliminating container `HttpSession` and `JSESSIONID` cookie creation in a stateless microservice cluster.
- **Custom Auth Handlers**: `WebAuthnAuthenticationSuccessHandler` issues standard Vaultix JWT access tokens and secure refresh token cookies upon passkey assertion, while `WebAuthnAuthenticationFailureHandler` outputs standardized `ApiResponse.error(...)` 401 envelopes.
- **Passkey Lifecycle Management**: Authenticated REST API (`/mfa/passkeys`) allowing users to view registered passkeys (with authenticator transports and usage metadata), rename labels, and delete passkeys with automatic synchronization of `user.passkey_enabled`.

## 12. Social Identity Federation & Account Linking (Google OIDC & GitHub OAuth2)
- **Google OIDC ID Token Verification**: Uses Nimbus / Google JWK Set decoder to cryptographically verify Google ID tokens received from the client. Validates signature against Google's public certificates, validates audience (`aud == client_id`), and checks expiration.
- **GitHub OAuth2 Code Exchange**: Performs backend code-to-token exchange with GitHub API (`https://github.com/login/oauth/access_token`) using client secret, then fetches user profile (`/user`) and verified primary email (`/user/emails`).
- **User Auto-Provisioning & Linking**:
  - Unauthenticated sign-in: If the user does not exist, automatically creates an account with default role `ROLE_USER`, sets `email_verified = true`, maps the social account in `user_social_accounts`, and flags `has_social_accounts = true`. If an account with the matching email already exists, links the provider and signs in.
  - Authenticated linking: Allows users to link multiple external identity providers (`/social/google/link`, `/social/github/link`). Enforces uniqueness on `(provider, provider_user_id)` to prevent multi-account collisions.
- **Single-Auth Lockout Prevention Guard**:
  - When unlinking a social provider (`DELETE /social/{provider}`), the system checks if the user has an active password hash or another active social account. If no alternative authentication method exists, the request is rejected with `BadRequestException` to prevent the user from being locked out permanently.
- **Audit & Security Alerts**:
  - Publishes `auth.notification.social-account-linked` and `auth.notification.social-account-unlinked` to RabbitMQ with the connected provider name and email for immediate security auditing.

## 13. SMS-Based Multi-Factor Authentication
- **Verified Phone Binding**: SMS MFA requires that the user's phone number is verified (`phone_number_verified = true`). Attempting to set up SMS MFA without a verified phone throws `BadRequestException`.
- **Activation Ceremony**:
  1. User calls `/mfa/sms/setup` &rarr; Generates a cryptographically random 6-digit OTP stored in Redis with 5-minute TTL and sets a 60-second cooldown (`auth:cooldown:sms-mfa-setup:{userId}`). Dispatches `auth.notification.phone-verification` via RabbitMQ.
  2. User calls `/mfa/sms/enable` with the received OTP &rarr; Validates OTP, sets `sms_mfa_enabled = true` on the `users` table, provisions 10 emergency recovery codes (if not already existing), and dispatches `auth.notification.mfa-enabled`.
- **Login Challenge Dispatch**:
  - When a user with `sms_mfa_enabled` logs in with username/password, social provider, or email, `AuthResponse` returns `mfa_required = true` along with an encrypted `mfa_token`.
  - The client invokes `/public/login/mfa/sms/send-otp` with the `mfa_token` to send an SMS verification OTP to the user's registered phone number.
  - The user enters the OTP in the unified MFA challenge dialog, which sends it to `/public/login/mfa` with `factor: "sms"` to complete authentication and receive JWT tokens.
- **Disablement**: User calls `/mfa/sms/disable` &rarr; Sets `sms_mfa_enabled = false` and sends `auth.notification.mfa-disabled` security alert.

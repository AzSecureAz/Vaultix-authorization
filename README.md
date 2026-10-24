# Vaultix Authorization Service

The core Authentication & Authorization microservice for the **Vaultix** platform, providing OAuth2/OIDC-aligned JWT issuance, asymmetric key management (RSA-2048 with AES-256 GCM KEK encryption), refresh token rotation, real-time distributed cache invalidation, and granular RBAC authorization.

---

## Service Overview

| Attribute | Value |
| :--- | :--- |
| **Port** | `8082` (Context path: `/api/v1/auth`) |
| **Gateway Route** | `http://localhost:8085/api/v1/auth/**` &rarr; `lb://authorization` |
| **Framework** | Spring Boot 4.1.1 + Spring Security 7.1.1 + Nimbus JOSE + Virtual Threads (Java 27) |
| **Database** | PostgreSQL 18+ (`vaultix_auth_db`) with Flyway migrations |
| **Cache & Pub/Sub** | Redis 7+ (`auth:*` keyspace, real-time revocation broadcast) |

---

## Core Security Architecture

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

### 1. Dynamic Asymmetric Signing Keys (RSA-2048)
- Active signing keys are generated and stored in PostgreSQL (`signing_keys` table).
- Private keys are encrypted at rest using authenticated **AES-256 GCM** with a Key Encryption Key (`KEK`).
- Local in-memory caching with **Caffeine** and cluster-wide eviction across microservices via **Redis Pub/Sub** (`auth:signing-key:revocation`).
- Scheduled automatic key rotation via `SigningKeyScheduler`.

### 2. JWT Access Tokens
- Signed with active RSA-2048 private key via Nimbus JOSE.
- Claims: `iss`, `sub` (User UUID), `jti` (UUIDv7), `token_type: access`, `roles_permissions` map, `iat`, `exp` (15 min default).
- Subject UUID is validated early at the filter layer via `SecurityUtil.extractActorId(jwt)` during `CustomJwtAuthenticationConverter` processing.

### 3. Refresh Token Rotation & Session Tracking
- Stored as a **SHA-256 hash** in PostgreSQL (`refresh_tokens` table) to prevent plaintext exposure upon database breach.
- **Client Context Binding**: Every session persists client `ipAddress`, `deviceInfo` (up to 256 chars), and `locationInfo`.
- **Generation Tracking (`gen`) & Reuse Detection**: Tokens carry an incrementing generation counter. Presenting a revoked or previously rotated token instantly invalidates the session family.
- Transmitted as an **`HttpOnly`**, **`SameSite=Strict`** cookie restricted to `/api/v1/auth/public/refresh` via `AuthCookieHelper`.

### 4. Real-Time Distributed Revocation
- **Disabled Roles & Permissions**: When an admin disables a role or permission, the entity status is updated and persisted in Redis hashes (`auth:role:disabled`, `auth:permission:disabled`) with an explicit TTL matching token lifetime.
- **Transactional Synchronization**: Redis invalidation broadcast occurs strictly inside `TransactionSynchronization.afterCommit()` to ensure downstream instances only evict after database commit.
- **Token Blacklisting**: JTI blacklist in Redis (`auth:blacklist:<jti>`) rejects revoked tokens instantly before expiration.

### 5. Hierarchical RBAC & Privilege Protection
- **Role Hierarchy**: Roles maintain a numeric `level` (lower numeric value = higher privilege).
- **Role Governance**: Administrators cannot create, modify, enable, or disable roles with a privilege level equal to or higher than their own active role level (`level <= actorHighestLevel`). Permissions assigned to a role must already be possessed by the actor.
- **User Governance**: Administrators cannot provision or assign roles with a privilege level equal to or higher than their own (`level <= actorHighestLevel`). Administrators cannot edit or modify users whose highest role (active or disabled) is equal to or more privileged than the actor (`targetUserHighestLevel <= actorHighestLevel`).
- **Batch Error Aggregation**: Missing, disabled, and level-violating roles or permissions are collected and reported as complete sets at once rather than failing one by one.
- **Session Revocation on Privilege Change**: Modifying a user's roles automatically revokes all refresh token sessions in PostgreSQL and schedules JTI blacklisting in Redis after transaction commit via `TokenService.revokeAllUserTokens`.
- **Change Detection**: Role and user updates evaluate whether any attributes or roles actually changed. If identical, database updates, audit timestamp updates (`updated_at`, `updated_by`), and token revocations are skipped.

### 6. Centralized Error Handling & Spring 6.1+ Method Validation
- **`GlobalExceptionHandler`**: Inherits `BaseGlobalExceptionHandler` from `common`, returning standard `ApiResponse.error(...)` envelopes across all endpoints.
- **Native Method Validation**: Utilizes Spring MVC 6.1+ native `HandlerMethodValidationException` for request parameter constraints (e.g. cookie length limits) without requiring class-level `@Validated` proxies on controllers.
- **Security Leak Prevention**: Masks internal service exceptions (`InternalAuthenticationServiceException`) as generic `"Authentication failed"` to prevent leaking database or connection details to clients.

### 7. Event-Driven Notifications (RabbitMQ)
- Declares **`auth.exchange`** (`TopicExchange`) for cross-service asynchronous event dispatch.
- **Welcome Notification**: Dispatched upon user registration (`/public/register`) with routing key `auth.notification.welcome`.
- **Password Reset**: Dispatched when requesting password reset (`/public/password-reset/request`) with a cryptographically secure 6-digit OTP to routing key `auth.notification.password-reset`.
- **Password Changed**: Dispatched when an authenticated user updates their password (`/password/change`) with security alert details to routing key `auth.notification.password-changed`.
- **Email Verification**: Dispatched when an authenticated user requests verification (`/email/send-verification`) with a 6-digit OTP and 60-second Redis rate-limit cooldown to routing key `auth.notification.email-verification`.
- **Email Changed**: Dispatched upon confirming an email change (`/email/change/confirm`) with a 7-day secure revert token link sent to the old address to routing key `auth.notification.email-changed`.
- **Email Reverted**: Dispatched when an email address is reverted via secure token (`/public/email/revert`) notifying the account holder to routing key `auth.notification.email-reverted`.
- **MFA Enabled**: Dispatched when TOTP two-factor authentication is activated (`/mfa/totp/activate`) to routing key `auth.notification.mfa-enabled`.
- **MFA Disabled**: Dispatched when two-factor authentication is disabled (`/mfa/totp/disable`) to routing key `auth.notification.mfa-disabled`.
- **MFA Login OTP**: Dispatched when an email one-time code is requested during MFA login (`/public/login/mfa/send-email-otp`) to routing key `auth.notification.mfa-login-otp`.
- **Emergency Recovery Code Used**: Dispatched when an emergency recovery code is burned to sign in (`/public/login/mfa`), alerting the account holder with remaining code count, IP, device, and timestamp to routing key `auth.notification.recovery-code-used`.
- Downstream notification services subscribe using the wildcard pattern **`auth.notification.*`** without coupling to internal authorization logic.

### 8. Platform-Wide Snake Case JSON (`SNAKE_CASE`)
- Enforces `spring.jackson.property-naming-strategy: SNAKE_CASE` across all DTOs and endpoints, eliminating manual `@JsonProperty` boilerplate while providing clean REST conventions for clients.

### 9. Distributed Scheduled Maintenance & ShedLock Coordination
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

### 10. Multi-Factor Authentication (TOTP, Email OTP & Emergency Recovery Codes)
- **RFC 6238 TOTP Authenticator**: Generates 20-byte cryptographically secure secrets encoded in Base32. The private secret is encrypted at rest using authenticated **AES-256 GCM** with the platform Key Encryption Key (`KEK`). Enforces strict 30-second time-steps with a $\pm 1$ drift tolerance window (90-second validity) and replay protection via database tracking (`last_used_step`).
- **Single-Use Emergency Recovery Codes**: Generates 10 single-use `xxxxx-xxxxx` codes upon TOTP activation. Plaintext codes are normalized and stored as **SHA-256 hashes** in PostgreSQL (`user_recovery_codes`). Using a recovery code permanently burns the entry and triggers an immediate security alert email (`auth.notification.recovery-code-used`) reporting the remaining code count, IP address, device info, and UTC timestamp.
- **On-Demand Email OTP Fallback**: Ephemeral 6-digit OTP stored in Redis (`mfa-login:<user_id>`) with an active 60-second rate-limiting cooldown and dynamic PII masking (`MaskUtil`) on email and username across all public challenge responses.
- **Zero-Waste Factor Routing**: The `/public/login/mfa` verification endpoint routes using an explicit `factor` parameter (`"totp"`, `"email"`, `"recovery_code"`). Direct factor routing verifies email OTPs in Redis (<1ms) without executing unnecessary database lookups or AES-256/HMAC crypto, while maintaining seamless auto-detection when `factor` is omitted.

### 11. WebAuthn Passkeys (FIDO2 / W3C WebAuthn Passwordless Authentication)
- **Native Spring Security 7.x WebAuthn**: Implements W3C WebAuthn Level 3 passkey registration and authentication using `spring-security-webauthn`.
- **Passkey Persistence**: Credentials stored in PostgreSQL (`user_credentials` table) mapped to `UserPasskeyCredential` JPA entity with UUIDv7, updatable = false on immutable cryptographic elements, and cascade delete foreign keys linked to `users(id)`.
- **Stateless Redis Challenge Store**: `RedisPublicKeyCredentialCreationOptionsRepository` persists registration challenges in Redis with a 5-minute TTL (`auth:webauthn:challenge:*`) and dual-resolution via secure cookie (`VAULTIX_WEBAUTHN_CHALLENGE`) or authenticated user principal fallback.
- **Custom Auth Handlers**: `WebAuthnAuthenticationSuccessHandler` issues standard Vaultix JWT access tokens and secure refresh token cookies upon passkey assertion, while `WebAuthnAuthenticationFailureHandler` outputs standardized `ApiResponse.error(...)` 401 envelopes.
- **Passkey Lifecycle Management**: Authenticated REST API (`/mfa/passkeys`) allowing users to view registered passkeys (with authenticator transports and usage metadata), rename labels, and delete passkeys with automatic synchronization of `user.passkey_enabled`.

---

## API Endpoints (`/api/v1/auth`)

### 1. Public Authentication Endpoints (`/public`)

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/public/register` | Register a new user account & dispatch welcome email | No | No |
| `POST` | `/public/login` | Authenticate user, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST` | `/public/refresh` | Rotate refresh token and issue new access token | Cookie / Body | Yes |
| `POST` | `/public/password-reset/request`, `/public/password/reset/request` | Initiate password reset, generate OTP & publish RabbitMQ event | No | No |
| `POST` | `/public/password-reset/confirm`, `/public/password/reset/confirm` | Validate OTP, update password & invalidate active sessions | No | No |
| `POST` | `/public/login/mfa/send-email-otp`, `/public/login/mfa/send-otp`, `/public/login/mfa/email-otp` | Dispatch 6-digit one-time code to verified account email for secondary MFA login (60s cooldown) | No (MFA Token) | No |
| `POST` | `/public/login/mfa`, `/public/login/verify-mfa`, `/public/mfa/verify` | Complete login by verifying 6-digit TOTP, 6-digit Email OTP, or Emergency Recovery Code | No (MFA Token) | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST`, `GET` | `/public/email/revert`, `/public/email-revert` | Revert compromised account email back to previous address using 7-day token & revoke attacker sessions | Token / Query | No |
| `POST` | `/webauthn/authenticate/options` | Request WebAuthn publicKey credential request options (challenge, RP ID, user verification) | No | No |
| `POST` | `/login/webauthn` | Authenticate passkey credential assertion, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `GET` | `/.well-known/jwks.json` | Public JWK Set containing RSA-2048 verification keys | No | No |

### 2. Authenticated Profile & Session Endpoints

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/logout` | Revoke current session refresh token and clear cookie | Cookie / Body | No |
| `POST` | `/logout-all`, `/logout/all` | Revoke ALL active refresh tokens and blacklist current JWT | Bearer JWT | No |
| `PUT`, `PATCH`, `POST` | `/password`, `/password/change`, `/password-change` | Change authenticated user password, revoke active sessions & alert email | Bearer JWT | No |
| `PUT`, `PATCH`, `POST` | `/username`, `/username/change`, `/username-change` | Update authenticated user's unique username | Bearer JWT | No |
| `POST` | `/email/send-verification`, `/email/send/verification` | Send OTP verification code to authenticated user's email (with 60s cooldown) | Bearer JWT | No |
| `POST` | `/email/verify`, `/email-verify` | Validate OTP code and mark account email as verified (`email_verified = true`) | Bearer JWT | No |
| `POST` | `/phone/send-verification`, `/phone/send/verification` | Send OTP verification code via SMS to authenticated user's phone number (60s cooldown) | Bearer JWT | No |
| `POST` | `/phone/verify`, `/phone-verify` | Validate OTP code and mark account phone number as verified (`phone_number_verified = true`) | Bearer JWT | No |
| `POST`, `PUT` | `/email/change/request`, `/email/change`, `/email/request-change` | Initiate 2-step email change & send OTP to new email (60s cooldown) | Bearer JWT | No |
| `POST` | `/email/change/confirm`, `/email/confirm-change` | Validate OTP sent to new email, commit new email (`email_verified = true`) & revoke active sessions | Bearer JWT | No |
| `POST`, `PUT` | `/phone/change/request`, `/phone/change`, `/phone/request-change` | Initiate 2-step phone change & send OTP to new phone number (60s cooldown) | Bearer JWT | No |
| `POST` | `/phone/change/confirm`, `/phone/confirm-change` | Validate OTP sent to new phone number, commit new phone (`phone_number_verified = true`) & revoke active sessions | Bearer JWT | No |
| `POST` | `/mfa/totp/setup`, `/totp/setup`, `/totp/initiate` | Initiate TOTP 2FA setup, encrypt secret with KEK & return Base32 key with QR URI | Bearer JWT | No |
| `POST` | `/mfa/totp/activate`, `/totp/activate`, `/totp/verify` | Verify 6-digit TOTP code, enable MFA on user account & send security alert email | Bearer JWT | No |
| `POST` | `/mfa/totp/disable`, `/totp/disable` | Disable MFA, purge TOTP & recovery codes & send security alert email | Bearer JWT | No |
| `POST` | `/webauthn/register/options` | Request WebAuthn publicKey credential creation options for passkey registration | Bearer JWT | No |
| `POST` | `/webauthn/register` | Register new passkey credential (public key, authenticator transports, attestation) | Bearer JWT | No |
| `GET` | `/mfa/passkeys`, `/passkeys` | Retrieve all registered passkeys for authenticated user | Bearer JWT | No |
| `PATCH` | `/mfa/passkeys/{id}` | Update user-defined label for a passkey | Bearer JWT | No |
| `DELETE` | `/mfa/passkeys/{id}` | Delete passkey credential & auto-disable passkey flag if last passkey | Bearer JWT | No |
| `GET` | `/me`, `/profile` | Retrieve authenticated user profile with roles & permissions | Bearer JWT | No |


### 3. Admin User Management (`/admin/users`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/users` | Create user with assigned roles (password set via reset flow) | `hasAuthority('user:create')` |
| `GET` | `/admin/users` | Retrieve paginated list of users with roles | `hasAuthority('user:read')` |
| `GET` | `/admin/users/{identifier}` | Retrieve user by UUID, username, or email | `hasAuthority('user:read')` |
| `PUT`, `PATCH` | `/admin/users/{identifier}` | Update user roles (revokes active sessions on change) | `hasAuthority('user:update')` |
| `POST` | `/admin/users/{identifier}/disable` | Disable user and revoke all active sessions | `hasAuthority('user:update')` |
| `POST` | `/admin/users/{identifier}/enable` | Re-enable user and clear lockout state | `hasAuthority('user:update')` |
| `DELETE` | `/admin/users/{identifier}` | Soft-delete user and revoke active sessions | `hasAuthority('user:delete')` |
| `POST` | `/admin/users/{identifier}/restore` | Restore soft-deleted user (placed in DISABLED state) | `hasAuthority('user:restore')` |

### 4. Admin Role Management (`/admin/roles`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/roles` | Create a new role with level and permissions | `hasAuthority('role:create')` |
| `GET` | `/admin/roles` | Retrieve paginated list of roles with permissions | `hasAuthority('role:read')` |
| `GET` | `/admin/roles/{identifier}` | Retrieve role by UUID or role name | `hasAuthority('role:read')` |
| `PUT`, `PATCH` | `/admin/roles/{identifier}` | Update role description and assigned permissions | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/disable` | Disable role and broadcast revocation event | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/enable` | Re-enable previously disabled role | `hasAuthority('role:update')` |
| `DELETE` | `/admin/roles/{identifier}` | Soft-delete role and broadcast revocation event | `hasAuthority('role:delete')` |
| `POST` | `/admin/roles/{identifier}/restore` | Restore soft-deleted role (placed in DISABLED state) | `hasAuthority('role:restore')` |

### 5. Admin Permission Management (`/admin/permissions`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/permissions` | Retrieve paginated list of system permissions | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `GET` | `/admin/permissions/{identifier}` | Retrieve permission by UUID or name | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `POST` | `/admin/permissions/{identifier}/disable` | Disable permission and broadcast revocation event | `hasRole('ADMIN')` |

### 6. Admin Signing Key Management (`/admin/signing-keys`, `/admin/signing/keys`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/signing-keys` | Retrieve paginated history of signing keys | `hasAuthority('key:read')` |
| `GET` | `/admin/signing-keys/{kid}` | Retrieve signing key metadata by Key ID | `hasAuthority('key:read')` |
| `POST` | `/admin/signing-keys/rotate` | Manually rotate active RSA signing key | `hasAuthority('key:rotate')` |
| `POST` | `/admin/signing-keys/{kid}/revoke` | Revoke a compromised or retired signing key | `hasRole('ADMIN')` |

---

## Directory Structure

```
authorization/
├── pom.xml
├── README.md
├── .env.example
└── src/main/
    ├── java/com/vaultix/authorization/
    │   ├── AuthorizationApplication.java
    │   ├── bootstrap/
    │   │   └── AdminUserInitializer.java
    │   ├── config/
    │   │   ├── JwtDecoderConfig.java
    │   │   ├── RabbitConfig.java
    │   │   ├── RedisPubSubConfig.java
    │   │   ├── SchedulerConfig.java
    │   │   ├── SecurityBeansConfig.java
    │   │   ├── SecurityConfig.java
    │   │   └── properties/
    │   │       ├── AdminBootstrapProperties.java
    │   │       ├── AuthMessagingProperties.java
    │   │       ├── JwtProperties.java
    │   │       ├── KekProperties.java
    │   │       ├── LockoutProperties.java
    │   │       ├── OtpProperties.java
    │   │       ├── PasskeyProperties.java
    │   │       ├── RoleProperties.java
    │   │       └── UserProperties.java
    │   ├── controller/
    │   │   ├── AccountController.java
    │   │   ├── AuthController.java
    │   │   ├── JwksController.java
    │   │   ├── PasskeyController.java
    │   │   ├── TotpController.java
    │   │   ├── admin/
    │   │   │   ├── AdminPermissionController.java
    │   │   │   ├── AdminRoleController.java
    │   │   │   ├── AdminSigningKeyController.java
    │   │   │   └── AdminUserController.java
    │   │   └── pub/
    │   │       ├── EmailRevertController.java
    │   │       ├── PasswordResetController.java
    │   │       └── PublicAuthController.java
    │   ├── dto/
    │   │   ├── AuthResponse.java
    │   │   ├── ChangePasswordRequest.java
    │   │   ├── ChangeUsernameRequest.java
    │   │   ├── ConfirmEmailChangeRequest.java
    │   │   ├── ConfirmPhoneNumberChangeRequest.java
    │   │   ├── LoginRequest.java
    │   │   ├── PasswordResetConfirmRequest.java
    │   │   ├── PasswordResetRequest.java
    │   │   ├── RefreshTokenRequest.java
    │   │   ├── RegisterRequest.java
    │   │   ├── RequestEmailChangeRequest.java
    │   │   ├── RequestPhoneNumberChangeRequest.java
    │   │   ├── RevertEmailRequest.java
    │   │   ├── UserProfileDto.java
    │   │   ├── VerifyEmailRequest.java
    │   │   ├── VerifyPhoneNumberRequest.java
    │   │   ├── admin/
    │   │   │   ├── CreateRoleRequest.java
    │   │   │   ├── CreateUserRequest.java
    │   │   │   ├── PermissionResponse.java
    │   │   │   ├── RoleResponse.java
    │   │   │   ├── SigningKeyResponse.java
    │   │   │   ├── UpdateRoleRequest.java
    │   │   │   ├── UpdateUserRequest.java
    │   │   │   └── UserResponse.java
    │   │   └── mfa/
    │   │       ├── MfaLoginRequest.java
    │   │       ├── PasskeyResponse.java
    │   │       ├── SendMfaEmailOtpRequest.java
    │   │       ├── TotpActivationResponse.java
    │   │       ├── TotpSetupResponse.java
    │   │       ├── UpdatePasskeyRequest.java
    │   │       └── VerifyTotpRequest.java
    │   ├── entity/
    │   │   ├── Permission.java
    │   │   ├── RefreshToken.java
    │   │   ├── Role.java
    │   │   ├── SigningKey.java
    │   │   ├── User.java
    │   │   ├── UserPasskeyCredential.java
    │   │   ├── UserRecoveryCode.java
    │   │   ├── UserTotp.java
    │   │   └── enums/
    │   │       ├── KeyStatus.java
    │   │       ├── PermissionStatus.java
    │   │       ├── RoleStatus.java
    │   │       └── UserStatus.java
    │   ├── exception/
    │   │   └── GlobalExceptionHandler.java
    │   ├── repository/
    │   │   ├── PermissionRepository.java
    │   │   ├── RefreshTokenRepository.java
    │   │   ├── RoleRepository.java
    │   │   ├── SigningKeyRepository.java
    │   │   ├── UserPasskeyCredentialRepository.java
    │   │   ├── UserRepository.java
    │   │   ├── UserRecoveryCodeRepository.java
    │   │   └── UserTotpRepository.java
    │   ├── scheduler/
    │   │   ├── RefreshTokenScheduler.java
    │   │   ├── RoleScheduler.java
    │   │   ├── SigningKeyScheduler.java
    │   │   └── UserScheduler.java
    │   ├── security/
    │   │   ├── AuthCookieHelper.java
    │   │   ├── AuthSecurityExpressions.java
    │   │   ├── CustomUserDetails.java
    │   │   ├── CustomUserDetailsService.java
    │   │   └── webauthn/
    │   │       ├── JpaPublicKeyCredentialUserEntityRepository.java
    │   │       ├── JpaUserCredentialRepository.java
    │   │       ├── RedisPublicKeyCredentialCreationOptionsRepository.java
    │   │       ├── WebAuthnAuthenticationFailureHandler.java
    │   │       └── WebAuthnAuthenticationSuccessHandler.java
    │   ├── service/
    │   │   ├── AccountService.java
    │   │   ├── AuthService.java
    │   │   ├── OtpService.java
    │   │   ├── PasskeyService.java
    │   │   ├── PasswordResetService.java
    │   │   ├── PermissionService.java
    │   │   ├── RoleService.java
    │   │   ├── SigningKeyService.java
    │   │   ├── TokenService.java
    │   │   ├── TotpService.java
    │   │   ├── UserService.java
    │   │   └── impl/
    │   │       ├── AccountServiceImpl.java
    │   │       ├── AuthServiceImpl.java
    │   │       ├── OtpServiceImpl.java
    │   │       ├── PasskeyServiceImpl.java
    │   │       ├── PasswordResetServiceImpl.java
    │   │       ├── PermissionServiceImpl.java
    │   │       ├── RoleServiceImpl.java
    │   │       ├── SigningKeyServiceImpl.java
    │   │       ├── TokenServiceImpl.java
    │   │       ├── TotpServiceImpl.java
    │   │       └── UserServiceImpl.java
    │   └── validation/
    │       ├── StrongPassword.java
    │       ├── StrongPasswordValidator.java
    │       ├── ValidFullName.java
    │       ├── ValidFullNameValidator.java
    │       ├── ValidPhoneNumber.java
    │       ├── ValidPhoneNumberValidator.java
    │       ├── ValidRoleName.java
    │       ├── ValidRoleNameValidator.java
    │       ├── ValidUsername.java
    │       └── ValidUsernameValidator.java
    └── resources/
        ├── application.yaml
        └── db/migration/
            ├── V1__create_rbac_schema.sql
            ├── V2__create_users_schema.sql
            ├── V3__create_refresh_tokens_schema.sql
            ├── V4__create_signing_keys_schema.sql
            ├── V5__create_totp_schema.sql
            ├── V6__create_recovery_codes_schema.sql
            └── V7__create_passkeys_schema.sql
```

---

## Configuration Reference

Configurable via `src/main/resources/application.yaml` or environment variables:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8082` | HTTP server port |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/vaultix_auth_db` | PostgreSQL JDBC connection URL |
| `SPRING_DATASOURCE_USERNAME` | `auth_user` | PostgreSQL connection username |
| `SPRING_DATASOURCE_PASSWORD` | `auth_password` | PostgreSQL connection password |
| `VAULTIX_ADMIN_ENABLED` | `true` | Enables initial admin bootstrapping on startup |
| `VAULTIX_ADMIN_USERNAME` | `admin` | Bootstrap administrator username |
| `VAULTIX_ADMIN_EMAIL` | `admin@vaultix.com` | Bootstrap administrator email address |
| `VAULTIX_ADMIN_FULL_NAME` | `Vaultix Administrator` | Bootstrap administrator full name |
| `VAULTIX_SECURITY_KEK_MASTER_KEY` | `3xhw5B4DZicmirWLS4h3ZkA4pBFZwyKlG6cvEYvdf7I=` | Master Key Encryption Key (KEK) for AES-256 GCM encryption at rest |
| `VAULTIX_AUTH_LOCKOUT_MAX_FAILED_ATTEMPTS` | `5` | Maximum failed password attempts before account lockout |
| `VAULTIX_AUTH_LOCKOUT_DURATION` | `15m` | Account lockout duration |
| `VAULTIX_PASSKEY_RP_ID` | `localhost` | WebAuthn Relying Party ID |
| `VAULTIX_PASSKEY_RP_NAME` | `Vaultix` | WebAuthn Relying Party Name |
| `VAULTIX_PASSKEY_ALLOWED_ORIGINS` | `http://localhost:3000,http://localhost:5173,http://localhost:8080` | Allowed browser origins for passkey ceremonies |
| `SPRING_DATA_REDIS_HOST` | `localhost` | Redis server hostname |
| `SPRING_DATA_REDIS_PORT` | `6379` | Redis server port |
| `SPRING_DATA_REDIS_USERNAME` | `auth_user` | Redis ACL connection username |
| `SPRING_DATA_REDIS_PASSWORD` | `auth_password` | Redis ACL connection password |
| `SPRING_RABBITMQ_HOST` | `localhost` | RabbitMQ broker hostname |
| `SPRING_RABBITMQ_PORT` | `5672` | RabbitMQ broker port |
| `SPRING_RABBITMQ_USERNAME` | `auth_user` | RabbitMQ connection username |
| `SPRING_RABBITMQ_PASSWORD` | `auth_password` | RabbitMQ connection password |
| `SPRING_RABBITMQ_VIRTUAL_HOST` | `/` | RabbitMQ virtual host |
| `VAULTIX_JWT_ISSUER` | `https://auth.vaultix.com` | JWT issuer (`iss`) claim |
| `VAULTIX_JWT_ACCESS_TOKEN_EXPIRATION` | `5m` | JWT access token lifespan |
| `VAULTIX_JWT_REFRESH_TOKEN_EXPIRATION` | `7d` | Refresh token session lifespan |
| `VAULTIX_KEY_ROTATION_CRON` | `0 0 2 * * ?` | Cron expression for asymmetric RSA key rotation (daily at 02:00 AM) |
| `VAULTIX_KEY_CLEANUP_CRON` | `0 10 2 * * ?` | Cron expression for retired RSA key cleanup (daily at 02:10 AM) |
| `VAULTIX_KEY_CLEANUP_GRACE_PERIOD` | `7d` | Grace period before hard deleting retired RSA keys |
| `VAULTIX_KEY_CLEANUP_BATCH_SIZE` | `100` | Deletion batch size for key cleanup |
| `VAULTIX_REFRESH_TOKEN_CLEANUP_CRON` | `0 20 2 * * ?` | Cron expression for revoked refresh token cleanup (daily at 02:20 AM) |
| `VAULTIX_REFRESH_TOKEN_CLEANUP_GRACE_PERIOD` | `7d` | Grace period before hard deleting revoked refresh tokens |
| `VAULTIX_REFRESH_TOKEN_CLEANUP_BATCH_SIZE` | `500` | Deletion batch size for refresh token cleanup |
| `VAULTIX_ROLE_CLEANUP_CRON` | `0 30 2 * * ?` | Cron expression for soft-deleted roles cleanup (daily at 02:30 AM) |
| `VAULTIX_ROLE_CLEANUP_GRACE_PERIOD` | `30d` | Grace period before hard deleting soft-deleted roles |
| `VAULTIX_ROLE_CLEANUP_BATCH_SIZE` | `100` | Deletion batch size for role cleanup |
| `VAULTIX_USER_CLEANUP_CRON` | `0 40 2 * * ?` | Cron expression for soft-deleted users cleanup (daily at 02:40 AM) |
| `VAULTIX_USER_CLEANUP_GRACE_PERIOD` | `90d` | Grace period before hard deleting soft-deleted users |
| `VAULTIX_USER_CLEANUP_BATCH_SIZE` | `100` | Deletion batch size for user cleanup |
| `VAULTIX_OTP_LENGTH` | `6` | Length of generated OTP codes |
| `VAULTIX_OTP_DEFAULT_TTL` | `10m` | Default time-to-live for email and password reset OTPs |
| `VAULTIX_OTP_MAX_ATTEMPTS` | `5` | Maximum failed OTP attempts before invalidation |
| `VAULTIX_RABBITMQ_AUTH_EXCHANGE` | `auth.exchange` | RabbitMQ topic exchange for auth events |
| `VAULTIX_RABBITMQ_AUTH_PASSWORD_RESET_ROUTING_KEY` | `auth.notification.password-reset` | Routing key for password reset OTP events |
| `VAULTIX_RABBITMQ_AUTH_EMAIL_VERIFICATION_ROUTING_KEY` | `auth.notification.email-verification` | Routing key for email verification OTP events |
| `VAULTIX_RABBITMQ_AUTH_WELCOME_ROUTING_KEY` | `auth.notification.welcome` | Routing key for user welcome registration events |
| `VAULTIX_RABBITMQ_AUTH_PASSWORD_CHANGED_ROUTING_KEY` | `auth.notification.password-changed` | Routing key for password change security alerts |
| `VAULTIX_RABBITMQ_AUTH_EMAIL_CHANGED_ROUTING_KEY` | `auth.notification.email-changed` | Routing key for email change revert token events |
| `VAULTIX_RABBITMQ_AUTH_EMAIL_REVERTED_ROUTING_KEY` | `auth.notification.email-reverted` | Routing key for email revert confirmation events |
| `VAULTIX_RABBITMQ_AUTH_MFA_ENABLED_ROUTING_KEY` | `auth.notification.mfa-enabled` | Routing key for MFA activation security alerts |
| `VAULTIX_RABBITMQ_AUTH_MFA_DISABLED_ROUTING_KEY` | `auth.notification.mfa-disabled` | Routing key for MFA disablement security alerts |
| `VAULTIX_RABBITMQ_AUTH_MFA_LOGIN_OTP_ROUTING_KEY` | `auth.notification.mfa-login-otp` | Routing key for MFA secondary login OTP dispatch |
| `VAULTIX_RABBITMQ_AUTH_RECOVERY_CODE_USED_ROUTING_KEY` | `auth.notification.recovery-code-used` | Routing key for emergency recovery code security alerts |
| `EUREKA_CLIENT_SERVICE_URL_DEFAULTZONE` | `http://localhost:8761/eureka/` | Eureka Service Discovery registry URL |

---

## Local Development & Setup

### 1. Prerequisites
- **Infra running**: PostgreSQL & Redis via `docker compose up -d` in `infra/`.
- **Database & ACL initialized**: Execute `postgres/init-auth-db.sql` and `redis/init-auth-acl.txt` (see `infra/README.md`).
- **Eureka Server running**: On port `8761`.

### 2. Build & Run

```powershell
# Build application
.\mvnw.cmd clean package

# Run application
.\mvnw.cmd spring-boot:run
```

Once running, the service registers with Eureka as `AUTHORIZATION` and listens on [http://localhost:8082/api/v1/auth](http://localhost:8082/api/v1/auth).

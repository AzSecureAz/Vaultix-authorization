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
- Transmitted as an **`HttpOnly`**, **`SameSite=Strict`** cookie restricted to `/api/v1/auth/refresh` via `AuthCookieHelper`.

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
- **Welcome Notification**: Dispatched upon user registration (`/register`) with routing key `auth.notification.welcome`.
- **Password Reset**: Dispatched when requesting password reset (`/password-reset/request`) with a cryptographically secure 6-digit OTP to routing key `auth.notification.password-reset`.
- **Email Verification**: Dispatched when an authenticated user requests verification (`/email/send-verification`) with a 6-digit OTP and 60-second Redis rate-limit cooldown to routing key `auth.notification.email-verification`.
- Downstream notification services subscribe using the wildcard pattern **`auth.notification.*`** without coupling to internal authorization logic.

### 8. Platform-Wide Snake Case JSON (`SNAKE_CASE`)
- Enforces `spring.jackson.property-naming-strategy: SNAKE_CASE` across all DTOs and endpoints, eliminating manual `@JsonProperty` boilerplate while providing clean REST conventions for clients.

---

## API Endpoints (`/api/v1/auth`)

### 1. Authentication & Profile Endpoints

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/register` | Register a new user account & dispatch welcome email | No | No |
| `POST` | `/login` | Authenticate user, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST` | `/refresh` | Rotate refresh token and issue new access token | Cookie / Body | Yes |
| `POST` | `/logout` | Revoke current session refresh token and clear cookie | Cookie / Body | No |
| `POST` | `/logout-all` | Revoke ALL active refresh tokens and blacklist current JWT | Bearer JWT | No |
| `POST` | `/password-reset/request` | Initiate password reset, generate OTP & publish RabbitMQ event | No | No |
| `POST` | `/password-reset/confirm` | Validate OTP, update password & invalidate active sessions | No | No |
| `POST` | `/email/send-verification` | Send OTP verification code to authenticated user's email (with 60s cooldown) | Bearer JWT | No |
| `POST` | `/email/verify` | Validate OTP code and mark account email as verified (`email_verified = true`) | Bearer JWT | No |
| `GET` | `/me`, `/profile` | Retrieve authenticated user profile with roles & permissions | Bearer JWT | No |
| `GET` | `/.well-known/jwks.json` | Public JWK Set containing RSA-2048 verification keys | No | No |


### 2. Admin User Management (`/admin/users`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/users` | Create user with assigned roles (password set via reset flow) | `hasAuthority('user:create')` |
| `GET` | `/admin/users` | Retrieve paginated list of users with roles | `hasAuthority('user:read')` |
| `GET` | `/admin/users/{identifier}` | Retrieve user by UUID, username, or email | `hasAuthority('user:read')` |
| `PUT` | `/admin/users/{identifier}` | Update user roles (revokes active sessions on change) | `hasAuthority('user:update')` |
| `POST` | `/admin/users/{identifier}/disable` | Disable user and revoke all active sessions | `hasAuthority('user:update')` |
| `POST` | `/admin/users/{identifier}/enable` | Re-enable user and clear lockout state | `hasAuthority('user:update')` |
| `DELETE` | `/admin/users/{identifier}` | Soft-delete user and revoke active sessions | `hasAuthority('user:delete')` |
| `POST` | `/admin/users/{identifier}/restore` | Restore soft-deleted user (placed in DISABLED state) | `hasAuthority('user:restore')` |

### 3. Admin Role Management (`/admin/roles`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/roles` | Create a new role with level and permissions | `hasAuthority('role:create')` |
| `GET` | `/admin/roles` | Retrieve paginated list of roles with permissions | `hasAuthority('role:read')` |
| `GET` | `/admin/roles/{identifier}` | Retrieve role by UUID or role name | `hasAuthority('role:read')` |
| `PUT` | `/admin/roles/{identifier}` | Update role description and assigned permissions | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/disable` | Disable role and broadcast revocation event | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/enable` | Re-enable previously disabled role | `hasAuthority('role:update')` |
| `DELETE` | `/admin/roles/{identifier}` | Soft-delete role and broadcast revocation event | `hasAuthority('role:delete')` |
| `POST` | `/admin/roles/{identifier}/restore` | Restore soft-deleted role (placed in DISABLED state) | `hasAuthority('role:restore')` |

### 4. Admin Permission Management (`/admin/permissions`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/permissions` | Retrieve paginated list of system permissions | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `GET` | `/admin/permissions/{identifier}` | Retrieve permission by UUID or name | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `POST` | `/admin/permissions/{identifier}/disable` | Disable permission and broadcast revocation event | `hasRole('ADMIN')` |

### 5. Admin Signing Key Management (`/admin/signing-keys`)

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
    │   │       └── RoleProperties.java
    │   ├── controller/
    │   │   ├── AuthController.java
    │   │   ├── JwksController.java
    │   │   └── admin/
    │   │       ├── AdminPermissionController.java
    │   │       ├── AdminRoleController.java
    │   │       ├── AdminSigningKeyController.java
    │   │       └── AdminUserController.java
    │   ├── dto/
    │   │   ├── AuthResponse.java
    │   │   ├── LoginRequest.java
    │   │   ├── PasswordResetConfirmRequest.java
    │   │   ├── PasswordResetRequest.java
    │   │   ├── RefreshTokenRequest.java
    │   │   ├── RegisterRequest.java
    │   │   ├── UserProfileDto.java
    │   │   ├── VerifyEmailRequest.java
    │   │   └── admin/
    │   │       ├── CreateRoleRequest.java
    │   │       ├── CreateUserRequest.java
    │   │       ├── PermissionResponse.java
    │   │       ├── RoleResponse.java
    │   │       ├── SigningKeyResponse.java
    │   │       ├── UpdateRoleRequest.java
    │   │       ├── UpdateUserRequest.java
    │   │       └── UserResponse.java
    │   ├── entity/
    │   │   ├── Permission.java
    │   │   ├── RefreshToken.java
    │   │   ├── Role.java
    │   │   ├── SigningKey.java
    │   │   ├── User.java
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
    │   │   └── UserRepository.java
    │   ├── scheduler/
    │   │   ├── RefreshTokenScheduler.java
    │   │   └── SigningKeyScheduler.java
    │   ├── security/
    │   │   ├── AuthCookieHelper.java
    │   │   ├── AuthSecurityExpressions.java
    │   │   ├── CustomUserDetails.java
    │   │   └── CustomUserDetailsService.java
    │   ├── service/
    │   │   ├── AuthService.java
    │   │   ├── OtpService.java
    │   │   ├── PermissionService.java
    │   │   ├── RoleService.java
    │   │   ├── SigningKeyService.java
    │   │   ├── TokenService.java
    │   │   ├── UserService.java
    │   │   └── impl/
    │   │       ├── AuthServiceImpl.java
    │   │       ├── OtpServiceImpl.java
    │   │       ├── PermissionServiceImpl.java
    │   │       ├── RoleServiceImpl.java
    │   │       ├── SigningKeyServiceImpl.java
    │   │       ├── TokenServiceImpl.java
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
            ├── V1__init_auth_schema.sql
            └── V2__create_signing_keys_schema.sql
```

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

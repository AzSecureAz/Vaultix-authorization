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
- Roles maintain a numeric `level` (lower numeric value = higher privilege).
- Administrators cannot create, modify, enable, or disable roles with a privilege level equal to or higher than their own active role level.

---

## API Endpoints (`/api/v1/auth`)

### 1. Authentication & Profile Endpoints

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/register` | Register a new user account | No | No |
| `POST` | `/login` | Authenticate user, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST` | `/refresh` | Rotate refresh token and issue new access token | Cookie / Body | Yes |
| `POST` | `/logout` | Revoke refresh token and wipe session cookie | Cookie / Body | No |
| `GET` | `/me` | Retrieve authenticated user profile with roles & permissions | Bearer JWT | No |
| `GET` | `/.well-known/jwks.json` | Public JWK Set containing RSA-2048 verification keys | No | No |

### 2. Admin User Management (`/admin/users`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/users` | Retrieve paginated list of users with roles | `hasAuthority('user:read')` |
| `GET` | `/admin/users/{identifier}` | Retrieve user by UUID, username, or email | `hasAuthority('user:read')` |

### 3. Admin Role Management (`/admin/roles`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `POST` | `/admin/roles` | Create a new role with level and permissions | `hasAuthority('role:create')` |
| `GET` | `/admin/roles` | Retrieve paginated list of roles with permissions | `hasAuthority('role:read')` |
| `GET` | `/admin/roles/{identifier}` | Retrieve role by UUID or role name | `hasAuthority('role:read')` |
| `PUT` | `/admin/roles/{identifier}` | Update role description and assigned permissions | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/disable` | Disable role and broadcast revocation event | `hasAuthority('role:update')` |
| `POST` | `/admin/roles/{identifier}/enable` | Re-enable previously disabled role | `hasAuthority('role:update')` |

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
└── src/main/
    ├── java/com/vaultix/authorization/
    │   ├── AuthorizationApplication.java
    │   ├── bootstrap/
    │   │   └── AdminUserInitializer.java
    │   ├── config/
    │   │   ├── JwtDecoderConfig.java
    │   │   ├── RedisPubSubConfig.java
    │   │   ├── SchedulerConfig.java
    │   │   ├── SecurityBeansConfig.java
    │   │   ├── SecurityConfig.java
    │   │   └── properties/
    │   │       ├── JwtProperties.java
    │   │       ├── KekProperties.java
    │   │       └── LockoutProperties.java
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
    │   │   ├── RefreshTokenRequest.java
    │   │   ├── RegisterRequest.java
    │   │   ├── UserProfileDto.java
    │   │   └── admin/
    │   │       ├── CreateRoleRequest.java
    │   │       ├── PermissionResponse.java
    │   │       ├── RoleResponse.java
    │   │       ├── SigningKeyResponse.java
    │   │       ├── UpdateRoleRequest.java
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
    │   ├── repository/
    │   │   ├── PermissionRepository.java
    │   │   ├── RefreshTokenRepository.java
    │   │   ├── RoleRepository.java
    │   │   ├── SigningKeyRepository.java
    │   │   └── UserRepository.java
    │   ├── scheduler/
    │   │   └── SigningKeyScheduler.java
    │   ├── security/
    │   │   ├── AuthCookieHelper.java
    │   │   ├── AuthSecurityExpressions.java
    │   │   ├── CustomUserDetails.java
    │   │   └── CustomUserDetailsService.java
    │   ├── service/
    │   │   ├── AuthService.java
    │   │   ├── PermissionService.java
    │   │   ├── RoleService.java
    │   │   ├── SigningKeyService.java
    │   │   ├── TokenService.java
    │   │   ├── UserService.java
    │   │   └── impl/
    │   │       ├── AuthServiceImpl.java
    │   │       ├── PermissionServiceImpl.java
    │   │       ├── RoleServiceImpl.java
    │   │       ├── SigningKeyServiceImpl.java
    │   │       ├── TokenServiceImpl.java
    │   │       └── UserServiceImpl.java
    │   └── validation/
    │       ├── StrongPassword.java
    │       └── ValidUsername.java
    └── resources/
        ├── application.yaml
        └── db/migration/
            └── V1__init_auth_schema.sql
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

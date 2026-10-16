# Vaultix Authorization Service

The core Authentication & Authorization microservice for the **Vaultix** platform, providing OAuth2/OIDC-aligned JWT issuance, asymmetric key management (RSA-2048 with AES-256 GCM KEK encryption), refresh token rotation, and RBAC authorization.

---

## Service Overview

| Attribute | Value |
| :--- | :--- |
| **Port** | `8082` (Context path: `/api/v1/auth`) |
| **Gateway Route** | `http://localhost:8085/api/v1/auth/**` &rarr; `lb://authorization` |
| **Framework** | Spring Boot 4.1.1 + Spring Security 7 + Nimbus JOSE + Virtual Threads (Java 27) |
| **Database** | PostgreSQL 16+ (`vaultix_auth_db`) with Flyway migrations |
| **Cache & Pub/Sub** | Redis 7+ (`auth:*` keyspace, key invalidation events) |

---

## Core Security Architecture

```
                               ┌──────────────────────────────────────────────┐
                               │             PostgreSQL (Auth DB)             │
                               │  • users (UUIDv7, Argon2id passwords)        │
                               │  • roles & permissions (RBAC)                │
                               │  • refresh_tokens (SHA-256 hash, ClientCtx)  │
                               │  • signing_keys (RSA-2048 encrypted by KEK)  │
                               └──────────────────────┬───────────────────────┘
                                                      │
Client Request ──► Gateway ──► AuthController ──► AuthService / TokenService
                                                      │
                               ┌──────────────────────┴───────────────────────┐
                               │                    Redis                     │
                               │  • JTI blacklist (fast token revocation)     │
                               │  • Pub/Sub key rotation event broadcast      │
                               └──────────────────────────────────────────────┘
```

### 1. Dynamic Asymmetric Signing Keys (RSA-2048)
- Active signing keys are generated and stored in PostgreSQL (`signing_keys` table).
- Private keys are encrypted at rest using authenticated **AES-256 GCM** with a Key Encryption Key (`KEK`).
- In-memory key caching with **Caffeine** and distributed eviction across microservice instances using **Redis Pub/Sub**.

### 2. JWT Access Tokens
- Signed with active RSA-2048 private key.
- Minimal claims: `iss`, `sub` (User ID), `username`, `roles`, `permissions`, `jti`, `token_type: access`, `exp` (15 min default).

### 3. Refresh Token Rotation & Session Tracking
- Stored as a **SHA-256 hash** in PostgreSQL (`refresh_tokens` table) to prevent plaintext exposure upon database breach.
- **Client Context Binding**: Every session persists client `ipAddress`, `deviceInfo` (up to 256 chars), and `locationInfo`.
- **Generation Tracking (`gen`) & Reuse Detection**: Tokens carry a generation counter. If a revoked or previously rotated token is presented, the session is invalidated.
- Transmitted as an **`HttpOnly`**, **`SameSite=Strict`** cookie restricted to the `/api/v1/auth/refresh` path via `AuthCookieHelper`.

### 4. Role-Based & Permission-Based Access Control (RBAC)
- Flyway schema migration (`V1__init_auth_schema.sql`) enforces UUIDv7 primary keys.
- Automatic seeding via `AdminUserInitializer` on boot (`SUPER_ADMIN`, `ADMIN`, `USER`).

---

## API Endpoints (`/api/v1/auth`)

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/register` | Register a new user account | No | No |
| `POST` | `/login` | Authenticate user, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST` | `/refresh` | Rotate refresh token and issue new access token | Cookie / Body | Yes |
| `POST` | `/logout` | Revoke refresh token and wipe session cookie | Cookie / Body | No |
| `GET` | `/me` | Retrieve authenticated user profile with roles & permissions | Bearer JWT | No |
| `GET` | `/.well-known/jwks.json` | Public JWK Set containing RSA-2048 verification keys | No | No |

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
    │   │   ├── SecurityBeansConfig.java
    │   │   ├── SecurityConfig.java
    │   │   └── properties/
    │   ├── controller/
    │   │   ├── AuthController.java
    │   │   └── JwksController.java
    │   ├── dto/
    │   │   ├── AuthResponse.java
    │   │   ├── LoginRequest.java
    │   │   ├── RefreshTokenRequest.java
    │   │   ├── RegisterRequest.java
    │   │   └── UserProfileDto.java
    │   ├── entity/
    │   │   ├── Permission.java
    │   │   ├── RefreshToken.java
    │   │   ├── Role.java
    │   │   ├── SigningKey.java
    │   │   └── User.java
    │   ├── repository/
    │   ├── security/
    │   │   ├── AuthCookieHelper.java
    │   │   ├── CustomUserDetails.java
    │   │   └── CustomUserDetailsService.java
    │   ├── service/
    │   │   ├── AuthService.java
    │   │   ├── SigningKeyService.java
    │   │   └── TokenService.java
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


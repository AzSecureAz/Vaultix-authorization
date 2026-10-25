# Vaultix Authorization Service

The core Authentication & Authorization microservice for the **Vaultix** platform, providing OAuth2/OIDC identity federation (Google & GitHub), WebAuthn Level 3 passkeys, TOTP & SMS multi-factor authentication, asymmetric key management (RSA-2048 with AES-256 GCM KEK encryption), refresh token rotation, real-time distributed cache invalidation, and granular RBAC authorization.

---

## Service Overview

| Attribute | Value |
| :--- | :--- |
| **Port** | `8082` (Context path: `/api/v1/auth`) |
| **Gateway Route** | `http://localhost:8085/api/v1/auth/**` &rarr; `lb://authorization` |
| **Framework** | Spring Boot 4.1.1 + Spring Security 7.1.1 + Nimbus JOSE + Virtual Threads (Java 27) |
| **Database** | PostgreSQL 18+ (`vaultix_auth_db`) with Flyway migrations (`V1` &rarr; `V9`) |
| **Cache & Pub/Sub** | Redis 7+ (`auth:*` keyspace, real-time revocation broadcast) |
| **Messaging** | RabbitMQ (`auth.exchange`, topic routing for async notification events) |

---

## Documentation Index

Detailed technical specifications, security designs, and endpoint documentation are maintained in the [`docs/`](docs/) directory:

| Document | Description |
| :--- | :--- |
| 📖 [**Core Security Architecture**](docs/ARCHITECTURE.md) | In-depth breakdown of the 13 security subsystems: dynamic RSA-2048 key rotation, AES-256 GCM KEK encryption, refresh token rotation, Redis Pub/Sub revocation, hierarchical RBAC governance, ShedLock maintenance, TOTP, WebAuthn Passkeys, Social Identity Federation (Google OIDC / GitHub OAuth2), and SMS MFA. |
| 📡 [**REST API Reference**](docs/API.md) | Complete specification of all `/api/v1/auth` endpoints, including Public auth (login, register, OAuth2/OIDC, passkeys), Authenticated Profile, MFA (TOTP, SMS, Recovery Codes), Social Linking, and Admin APIs. |

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

## Directory Structure

```
authorization/
├── pom.xml
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   └── API.md
└── src/main/
    ├── java/com/vaultix/authorization/
    │   ├── config/ (JwtDecoderConfig, RabbitConfig, RedisPubSubConfig, SecurityConfig, properties/)
    │   ├── controller/
    │   │   ├── AccountController.java (profile, password, username, email/phone verification)
    │   │   ├── AuthController.java (session logout, logout-all)
    │   │   ├── JwksController.java (public JWKS endpoint)
    │   │   ├── MfaRecoveryCodeController.java (recovery codes count & regeneration)
    │   │   ├── PasskeyController.java (WebAuthn passkey management)
    │   │   ├── SmsMfaController.java (SMS MFA setup, activation, disablement)
    │   │   ├── SocialAccountController.java (social linking & unlinking)
    │   │   ├── TotpController.java (TOTP setup, activation, disablement)
    │   │   ├── admin/ (AdminUserController, AdminRoleController, AdminPermissionController, AdminSigningKeyController)
    │   │   └── pub/ (PublicAuthController, GoogleAuthController, GitHubAuthController, PasswordResetController, EmailRevertController)
    │   ├── dto/ (AuthResponse, LoginRequest, oauth2/, mfa/, admin/)
    │   ├── entity/ (User, Role, Permission, RefreshToken, SigningKey, UserSocialAccount, UserPasskeyCredential, UserTotp, UserRecoveryCode)
    │   ├── repository/ (UserRepository, UserSocialAccountRepository, RefreshTokenRepository, SigningKeyRepository, ...)
    │   ├── scheduler/ (SigningKeyScheduler, RefreshTokenScheduler, RoleScheduler, UserScheduler)
    │   ├── security/ (AuthCookieHelper, CustomUserDetails, webauthn/)
    │   └── service/ (AuthService, GoogleAuthService, GitHubAuthService, SocialAccountService, SmsMfaService, TotpService, TokenService, ...)
    └── resources/
        ├── application.yaml
        └── db/migration/
            ├── V1__create_rbac_schema.sql ... V7__create_passkeys_schema.sql
            ├── V8__add_sms_mfa_to_users.sql
            └── V9__create_social_accounts_schema.sql
```

---

## Configuration Reference

Key settings configurable via `application.yaml` or environment variables:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `PORT` | `8082` | HTTP server port |
| `SPRING_DATASOURCE_URL` | `jdbc:postgresql://localhost:5432/vaultix_auth_db` | PostgreSQL connection URL |
| `SPRING_DATA_REDIS_HOST` | `localhost` | Redis server hostname |
| `SPRING_RABBITMQ_HOST` | `localhost` | RabbitMQ broker hostname |
| `VAULTIX_SECURITY_KEK_MASTER_KEY` | `3xhw5...` | 256-bit KEK for encrypting private keys & TOTP secrets at rest |
| `VAULTIX_JWT_ISSUER` | `https://auth.vaultix.com` | JWT issuer (`iss`) claim |
| `VAULTIX_JWT_ACCESS_TOKEN_EXPIRATION` | `5m` | Access token lifespan |
| `VAULTIX_JWT_REFRESH_TOKEN_EXPIRATION` | `7d` | Refresh token lifespan |
| `VAULTIX_PASSKEY_RP_ID` | `localhost` | WebAuthn Relying Party ID |
| `VAULTIX_PASSKEY_ALLOWED_ORIGINS` | `http://localhost:3000,...` | Allowed origins for WebAuthn passkey ceremonies |
| `VAULTIX_FRONTEND_BASE_URL` | `http://localhost:3000` | Frontend application base URL for redirects and alerts |
| `VAULTIX_GOOGLE_CLIENT_ID` | &mdash; | Google OAuth2 / OIDC Client ID |
| `VAULTIX_GITHUB_CLIENT_ID` | &mdash; | GitHub OAuth2 App Client ID |
| `VAULTIX_GITHUB_CLIENT_SECRET` | &mdash; | GitHub OAuth2 App Client Secret |
| `VAULTIX_GITHUB_REDIRECT_URI` | &mdash; | GitHub OAuth2 callback URL |
| `VAULTIX_RABBITMQ_AUTH_EXCHANGE` | `auth.exchange` | RabbitMQ topic exchange for auth events |

*For complete list of RabbitMQ routing keys and cleanup schedules, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).*

---

## Local Development & Setup

### 1. Prerequisites
- **Infra running**: PostgreSQL, Redis & RabbitMQ via `docker compose up -d` in `infra/`.
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

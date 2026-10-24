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

## Documentation Index

Detailed technical specifications, security designs, and endpoint documentation are maintained in the [`docs/`](docs/) directory:

| Document | Description |
| :--- | :--- |
| 📖 [**Core Security Architecture**](docs/ARCHITECTURE.md) | In-depth breakdown of the 11 security subsystems: dynamic RSA-2048 key rotation, AES-256 GCM KEK encryption, refresh token rotation, real-time Redis Pub/Sub revocation, hierarchical RBAC governance, ShedLock distributed maintenance, TOTP, and WebAuthn Level 3 passkeys. |
| 📡 [**REST API Reference**](docs/API.md) | Complete specification of all `/api/v1/auth` endpoints, including Public auth, Authenticated Profile & Session management, Admin User management, Admin Roles, Permissions, and Signing Key rotation APIs. |

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

## Directory Structure

```
authorization/
├── pom.xml
├── README.md
├── .env.example
├── docs/
│   ├── ARCHITECTURE.md
│   └── API.md
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
| `VAULTIX_RABBITMQ_AUTH_RECOVERY_CODE_USED_ROUTING_KEY` | `auth.notification.recovery-code-used` | Routing key for emergency recovery code security alerts |
| `VAULTIX_RABBITMQ_AUTH_RECOVERY_CODES_REGENERATED_ROUTING_KEY` | `auth.notification.recovery-codes-regenerated` | Routing key for emergency recovery codes regeneration alerts |
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

# Vaultix Authorization - REST API Reference

Complete endpoint reference for the **Vaultix Authorization Service**.

- **Base Context Path**: `/api/v1/auth`
- **Gateway Forwarding**: `http://localhost:8085/api/v1/auth/**` &rarr; `lb://authorization`
- **Response Format**: All endpoints return standard [`ApiResponse<T>`](file:///c:/Users/vimal/Documents/Projects/Vaultix/common/src/main/java/com/vaultix/common/dto/ApiResponse.java) JSON wrappers with `SNAKE_CASE` property formatting.

---

## 1. Public Authentication Endpoints (`/public`)

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

---

## 2. Authenticated Profile & Session Endpoints

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
| `GET` | `/mfa/totp/recovery-codes`, `/totp/recovery-codes`, `/mfa/totp/recovery-codes/count`, `/totp/recovery-codes/count` | Retrieve remaining count of unused emergency recovery codes | Bearer JWT | No |
| `POST` | `/mfa/totp/recovery-codes/regenerate`, `/mfa/totp/recovery-codes`, `/totp/recovery-codes/regenerate`, `/totp/recovery-codes` | Invalidate existing recovery codes and generate 10 fresh emergency recovery codes | Bearer JWT | No |
| `POST` | `/webauthn/register/options` | Request WebAuthn publicKey credential creation options for passkey registration | Bearer JWT | No |
| `POST` | `/webauthn/register` | Register new passkey credential (public key, authenticator transports, attestation) | Bearer JWT | No |
| `GET` | `/mfa/passkeys`, `/passkeys` | Retrieve all registered passkeys for authenticated user | Bearer JWT | No |
| `PATCH` | `/mfa/passkeys/{id}` | Update user-defined label for a passkey | Bearer JWT | No |
| `DELETE` | `/mfa/passkeys/{id}` | Delete passkey credential & auto-disable passkey flag if last passkey | Bearer JWT | No |
| `GET` | `/me`, `/profile` | Retrieve authenticated user profile with roles & permissions | Bearer JWT | No |

---

## 3. Admin User Management (`/admin/users`)

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

---

## 4. Admin Role Management (`/admin/roles`)

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

---

## 5. Admin Permission Management (`/admin/permissions`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/permissions` | Retrieve paginated list of system permissions | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `GET` | `/admin/permissions/{identifier}` | Retrieve permission by UUID or name | `hasRole('ADMIN') or hasAuthority('permission:read')` |
| `POST` | `/admin/permissions/{identifier}/disable` | Disable permission and broadcast revocation event | `hasRole('ADMIN')` |

---

## 6. Admin Signing Key Management (`/admin/signing-keys`, `/admin/signing/keys`)

| Method | Endpoint | Description | PreAuthorize Expression |
| :--- | :--- | :--- | :--- |
| `GET` | `/admin/signing-keys` | Retrieve paginated history of signing keys | `hasAuthority('key:read')` |
| `GET` | `/admin/signing-keys/{kid}` | Retrieve signing key metadata by Key ID | `hasAuthority('key:read')` |
| `POST` | `/admin/signing-keys/rotate` | Manually rotate active RSA signing key | `hasAuthority('key:rotate')` |
| `POST` | `/admin/signing-keys/{kid}/revoke` | Revoke a compromised or retired signing key | `hasRole('ADMIN')` |

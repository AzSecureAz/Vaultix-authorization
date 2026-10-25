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
| `POST` | `/public/login` | Authenticate with username/password, issue access token & set refresh cookie | No | Yes (`X-Client-IP`, `X-Device-*`) |
| `POST` | `/public/login/google`, `/public/oauth2/google` | Authenticate using Google OIDC ID token, auto-provision user & issue tokens | No | Yes |
| `POST` | `/public/login/github`, `/public/oauth2/github` | Authenticate using GitHub OAuth2 authorization code, auto-provision & issue tokens | No | Yes |
| `POST` | `/public/login/mfa`, `/public/login/verify-mfa`, `/public/mfa/verify` | Complete login by verifying TOTP code, Emergency Recovery Code, or SMS OTP | No (MFA Token) | Yes |
| `POST` | `/public/login/mfa/sms/send-otp`, `/public/login/mfa/sms/send` | Request SMS verification code dispatch to registered phone during MFA login | No (MFA Token) | No |
| `POST` | `/public/refresh` | Rotate refresh token and issue new access token | Cookie / Body | Yes |
| `POST` | `/public/password-reset/request`, `/public/password/reset/request` | Initiate password reset, generate OTP & publish RabbitMQ event | No | No |
| `POST` | `/public/password-reset/confirm`, `/public/password/reset/confirm` | Validate reset OTP and apply new password (revokes active sessions) | No | No |
| `POST`, `GET` | `/public/email/revert`, `/public/email-revert` | Revert compromised account email back to previous address using 7-day token & revoke attacker sessions | Token / Query | No |
| `POST` | `/webauthn/authenticate/options` | Request WebAuthn publicKey credential request options (challenge, RP ID, user verification) | No | No |
| `POST` | `/login/webauthn` | Authenticate passkey credential assertion, issue access token & set refresh cookie | No | Yes |
| `GET` | `/.well-known/jwks.json` | Public JWK Set containing RSA-2048 verification keys | No | No |

---

## 2. Authenticated Profile & Session Endpoints

### 2.1 User Profile & Account Settings

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/me`, `/profile` | Retrieve authenticated user profile with roles, permissions, and MFA status | Bearer JWT | No |
| `PUT`, `PATCH`, `POST` | `/password`, `/password/change`, `/password-change` | Change password, revoke active sessions & alert email | Bearer JWT | No |
| `PUT`, `PATCH`, `POST` | `/username`, `/username/change`, `/username-change` | Update authenticated user's unique username | Bearer JWT | No |
| `POST` | `/email/send-verification`, `/email/send/verification` | Send OTP verification code to authenticated user's email (60s cooldown) | Bearer JWT | No |
| `POST` | `/email/verify`, `/email-verify` | Validate OTP code and mark account email as verified (`email_verified = true`) | Bearer JWT | No |
| `POST`, `PUT` | `/email/change/request`, `/email/change`, `/email/request-change` | Initiate 2-step email change & send OTP to new email (60s cooldown) | Bearer JWT | No |
| `POST` | `/email/change/confirm`, `/email/confirm-change` | Validate OTP sent to new email, commit new email & revoke active sessions | Bearer JWT | No |
| `POST` | `/phone/send-verification`, `/phone/send/verification` | Send OTP verification code via SMS to registered phone number (60s cooldown) | Bearer JWT | No |
| `POST` | `/phone/verify`, `/phone-verify` | Validate OTP code and mark phone number as verified (`phone_number_verified = true`) | Bearer JWT | No |
| `POST`, `PUT` | `/phone/change/request`, `/phone/change`, `/phone/request-change` | Initiate 2-step phone change & send OTP to new phone number (60s cooldown) | Bearer JWT | No |
| `POST` | `/phone/change/confirm`, `/phone/confirm-change` | Validate OTP sent to new phone number, commit new phone & revoke active sessions | Bearer JWT | No |

### 2.2 Multi-Factor Authentication (MFA) & Passkeys

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/mfa/totp/setup`, `/totp/setup`, `/totp/initiate` | Initiate TOTP 2FA setup, encrypt secret with KEK & return Base32 key with QR URI | Bearer JWT | No |
| `POST` | `/mfa/totp/activate`, `/totp/activate`, `/totp/verify` | Verify 6-digit TOTP code, enable MFA on user account, generate 10 recovery codes & alert email | Bearer JWT | No |
| `POST` | `/mfa/totp/disable`, `/totp/disable` | Disable TOTP MFA, purge secret & recovery codes & send security alert email | Bearer JWT | No |
| `POST` | `/mfa/sms/setup`, `/mfa/sms/send-setup-otp`, `/mfa/sms/initiate` | Send 6-digit OTP to user's registered phone number for SMS MFA activation (60s cooldown) | Bearer JWT | No |
| `POST` | `/mfa/sms/enable`, `/mfa/sms/activate`, `/mfa/sms/verify` | Verify SMS OTP, enable SMS MFA (`sms_mfa_enabled = true`), issue recovery codes & alert email | Bearer JWT | No |
| `POST` | `/mfa/sms/disable` | Disable SMS MFA & send security alert email | Bearer JWT | No |
| `GET` | `/mfa/recovery-codes`, `/mfa/totp/recovery-codes`, `/recovery-codes/count` | Retrieve remaining count of unused emergency recovery codes | Bearer JWT | No |
| `POST` | `/mfa/recovery-codes`, `/mfa/recovery-codes/regenerate`, `/mfa/totp/recovery-codes/regenerate` | Invalidate existing recovery codes and generate 10 fresh emergency recovery codes | Bearer JWT | No |
| `POST` | `/webauthn/register/options` | Request WebAuthn publicKey credential creation options for passkey registration | Bearer JWT | No |
| `POST` | `/webauthn/register` | Register new passkey credential (public key, authenticator transports, attestation) | Bearer JWT | No |
| `GET` | `/mfa/passkeys`, `/passkeys` | Retrieve all registered passkeys for authenticated user | Bearer JWT | No |
| `PATCH` | `/mfa/passkeys/{id}` | Update user-defined label/nickname for a registered passkey | Bearer JWT | No |
| `DELETE` | `/mfa/passkeys/{id}` | Delete passkey credential & auto-disable passkey flag if last credential removed | Bearer JWT | No |

### 2.3 Connected Social Accounts (`/social`)

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/social` | Retrieve all linked social accounts (Google, GitHub) with profile metadata | Bearer JWT | No |
| `POST` | `/social/google/link`, `/social/google` | Link Google account to current user account via Google OIDC ID token | Bearer JWT | No |
| `POST` | `/social/github/link`, `/social/github` | Link GitHub account to current user account via OAuth2 authorization code | Bearer JWT | No |
| `DELETE` | `/social/{provider}`, `/social/{provider}/unlink` | Unlink social provider account (prevented if account has no password or other login methods) | Bearer JWT | No |

### 2.4 Session Management & Logout

| Method | Endpoint | Description | Auth Required | Client Context Tracked |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/logout` | Revoke current session refresh token and clear cookie | Cookie / Body | No |
| `POST` | `/logout-all`, `/logout/all` | Revoke ALL active refresh tokens for the user and blacklist current JWT in Redis | Bearer JWT | No |

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

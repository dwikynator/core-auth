# Authentication Flow

> **Audience:** Frontend engineers, backend service integrators, and anyone consuming the `core-auth` API.
> This guide traces every step of the authentication lifecycle from a **client's perspective** — what you send, what you receive, and what you do with it next.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Registration](#2-registration)
3. [Login — Standard (No MFA)](#3-login--standard-no-mfa)
4. [Login — With MFA Challenge](#4-login--with-mfa-challenge)
5. [Using the Access Token](#5-using-the-access-token)
6. [Token Refresh](#6-token-refresh)
7. [Logout](#7-logout)
8. [Password Reset Flow](#8-password-reset-flow)
9. [Error Reference](#9-error-reference)
10. [Flow Cheat Sheet](#10-flow-cheat-sheet)

---

## 1. Overview

`core-auth` issues a **short-lived JWT access token** and a **long-lived opaque refresh token** upon successful authentication. The two tokens serve distinct roles:

| Token | Format | Lifetime | Stored where |
|---|---|---|---|
| `access_token` | Signed JWT (RS256) | 15 minutes | Memory / `Authorization` header |
| `refresh_token` | Opaque random string | 30 days | HttpOnly cookie or secure storage |

The lifecycle for a typical session looks like this:

```
Register ──► Login ──► [MFA Challenge?] ──► Get Token Pair
                                                   │
                                    ┌──────────────┘
                                    │
                            Use Access Token ──► Refresh when expired
                                    │
                                 Logout ──► Token pair revoked
```

All requests require a `client_id` field. This is your **tenant identifier** — it determines which scopes are returned and which security policies are enforced. For local development, any non-empty string works (e.g. `"test-app"`).

---

## 2. Registration

Registration creates a new user account. It does **not** return tokens — the user must log in separately after confirming their email.

### Request

```
POST /v1/auth/register
```

```json
{
  "client_id": "my-app",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

You may also register with a `username` or `phone` instead of (or in addition to) `email`. At least one identifier is required.

**Password policy:** 8–128 characters, must contain at least one uppercase letter, one lowercase letter, and one digit.

### Successful Response (`200 OK`)

```json
{
  "user": {
    "user_id": "40bf857f-d513-402a-a92c-f6fa9b422a55",
    "email": "alice@example.com",
    "role": "user",
    "scopes": ["openid", "profile"],
    "email_verified": false,
    "mfa_enabled": false
  }
}
```

### What happens internally

```
Client                      core-auth
  │                              │
  │── POST /v1/auth/register ───►│
  │                              │ 1. Validate identifier format
  │                              │ 2. Validate password policy
  │                              │ 3. Hash password (Argon2id)
  │                              │ 4. Persist user (status: "unverified")
  │                              │ 5. Send email verification OTP (async)
  │                              │ 6. Emit audit event
  │◄── 200 OK {user} ───────────│
```

> [!NOTE]
> `email_verified` will be `false` until the user confirms the OTP sent to their inbox.
> If the email send fails, registration **still succeeds** — the user can request a new OTP later.

> [!IMPORTANT]
> A newly registered account has status `"unverified"`. Login will be **rejected** until the email is verified. Prompt users to check their inbox immediately after registration.

### Common Errors

| Error | Cause |
|---|---|
| `INVALID_IDENTIFIER` | No email, username, or phone was provided |
| `INVALID_IDENTIFIER_FORMAT` | Email failed normalisation, username has invalid characters, phone is malformed |
| `PASSWORD_POLICY_VIOLATION` | Password does not meet complexity requirements |
| `USER_ALREADY_EXISTS` | An account with this email / username / phone already exists |

---

## 3. Login — Standard (No MFA)

### Request

```
POST /v1/auth/login
```

```json
{
  "client_id": "my-app",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

You may substitute `email` with `username` or `phone`.

### Successful Response (`200 OK`)

```json
{
  "login_success": {
    "user": {
      "user_id": "40bf857f-d513-402a-a92c-f6fa9b422a55",
      "email": "alice@example.com",
      "role": "user",
      "scopes": ["openid", "profile"],
      "email_verified": true,
      "mfa_enabled": false
    },
    "tokens": {
      "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refresh_token": "a1b2c3d4e5f6...",
      "expires_in": 900
    }
  }
}
```

`expires_in` is in seconds. Start a refresh timer at `expires_in - 60` to silently renew before expiry.

### Sequence Diagram

```
Client                          core-auth
  │                                  │
  │── POST /v1/auth/login ──────────►│
  │                                  │ 1. Check IP rate limit (Redis)
  │                                  │ 2. Look up user by identifier
  │                                  │ 3. Check account lockout (Redis)
  │                                  │ 4. Check account status
  │                                  │    (suspended / deleted / unverified)
  │                                  │ 5. Verify password (Argon2id, constant-time)
  │                                  │ 6. Check tenant IP policy (allowlist / denylist)
  │                                  │ 7. Suspicious login detection
  │                                  │ 8. Record login attempt
  │                                  │ 9. MFA enrolled? → See Section 4
  │                                  │ 10. Create session + sign token pair
  │                                  │ 11. Emit audit event (login)
  │◄── 200 OK {login_success} ──────│
```

> [!NOTE]
> If the user is not found, the service deliberately maps this to `INVALID_CREDENTIALS` — the same error returned for a wrong password. This prevents **user enumeration** attacks.

### Common Errors

| Error | Cause |
|---|---|
| `INVALID_CREDENTIALS` | Wrong password, or no user found for the identifier |
| `ACCOUNT_NOT_VERIFIED` | Email address has not been verified yet |
| `ACCOUNT_SUSPENDED` | Account suspended by an admin |
| `ACCOUNT_LOCKED` | Too many failed attempts — temporary lockout is active |
| `TOO_MANY_REQUESTS` | IP-level rate limit exceeded |
| `IP_NOT_ALLOWED` | Client IP is denied by the tenant's IP policy |

---

## 4. Login — With MFA Challenge

When a user has MFA enrolled (or the system detects a suspicious login from an unknown IP and `SUSPICIOUS_LOGIN_ACTION=challenge_mfa`), the login response is different — no tokens are issued yet. Instead, you receive a short-lived `mfa_session_token`.

### Step 1 — Login returns `mfa_required`

Same request as in Section 3. When MFA is required, the response shape changes:

```json
{
  "mfa_required": {
    "mfa_session_token": "mfa_sess_abc123...",
    "mfa_type": "totp"
  }
}
```

The `mfa_session_token` is a **single-use, short-lived token** (stored in Redis). It proves that the password check was passed. Store it in memory only — never persist it.

> [!IMPORTANT]
> The MFA session token is consumed the moment you submit the challenge, **regardless of whether the TOTP code is correct**. If the code is wrong, the user must restart the full login flow from Step 1.

### Step 2 — Submit the TOTP code

```
POST /v1/mfa/challenge
```

```json
{
  "mfa_session_token": "mfa_sess_abc123...",
  "code": "123456"
}
```

### Successful Response (`200 OK`)

```json
{
  "user": {
    "user_id": "40bf857f-d513-402a-a92c-f6fa9b422a55",
    "email": "alice@example.com",
    "mfa_enabled": true
  },
  "tokens": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "a1b2c3d4e5f6...",
    "expires_in": 900
  }
}
```

### Sequence Diagram

```
Client                               core-auth
  │                                       │
  │── POST /v1/auth/login ───────────────►│
  │                                       │ (password verified ✓)
  │                                       │ MFA enrolled? YES
  │                                       │ → Create MFA session (Redis, TTL ~5 min)
  │◄── 200 OK {mfa_required} ────────────│
  │                                       │
  │  [User opens authenticator app]       │
  │                                       │
  │── POST /v1/mfa/challenge ────────────►│
  │   { mfa_session_token, code }         │ 1. Consume MFA session (single-use)
  │                                       │ 2. Decrypt TOTP secret (AES-256-GCM)
  │                                       │ 3. Validate TOTP code
  │                                       │ 4. Create session + sign token pair
  │                                       │ 5. Emit audit event (mfa_challenged)
  │◄── 200 OK {user, tokens} ────────────│
```

### Common Errors

| Error | Cause |
|---|---|
| `INVALID_MFA_SESSION` | `mfa_session_token` is expired, not found, or already consumed |
| `MFA_INVALID_CODE` | TOTP code is wrong (session is consumed — restart login) |

---

## 5. Using the Access Token

Pass the access token as a `Bearer` token in the `Authorization` header on every protected request:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Example:**

```bash
curl -s http://localhost:8080/v1/user/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

The access token is a **JWT signed with RS256**. Consumers can verify it offline using the service's public key — no network round-trip required.

### Token Claims

| Claim | Description |
|---|---|
| `sub` | User ID (UUID) |
| `role` | User role (e.g. `"user"`, `"admin"`) |
| `scopes` | List of OAuth scopes granted to this client |
| `iss` | Issuer — matches the `JWT_ISSUER` config value |
| `exp` | Unix timestamp when the token expires |
| `jti` | Unique token ID (used for revocation blacklist) |

> [!IMPORTANT]
> Access tokens expire in **15 minutes**. Do not store them in `localStorage`. Keep them in memory (JavaScript) or a secure, short-lived cookie. When they expire, use the refresh token to get a new pair — see Section 6.

---

## 6. Token Refresh

When the access token expires, use the refresh token to silently obtain a new token pair **without prompting the user to log in again**.

### Request

```
POST /v1/auth/refresh
```

```json
{
  "client_id": "my-app",
  "refresh_token": "a1b2c3d4e5f6..."
}
```

### Successful Response (`200 OK`)

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "g7h8i9j0k1l2...",
  "expires_in": 900
}
```

> [!IMPORTANT]
> **Refresh tokens rotate on every use.** The old `refresh_token` is invalidated immediately after a successful refresh — you **must** replace it with the new one returned. Failing to do so will force the user to log in again.

### Sequence Diagram

```
Client                          core-auth
  │                                  │
  │── POST /v1/auth/refresh ────────►│
  │   { refresh_token }              │ 1. Hash the refresh token
  │                                  │ 2. Find session by hash
  │                                  │ 3. Verify session not revoked / expired
  │                                  │ 4. Generate new token pair
  │                                  │ 5. Rotate refresh token hash in DB (atomic)
  │                                  │ 6. Old token is now invalid
  │◄── 200 OK {token_pair} ─────────│
```

### Common Errors

| Error | Cause |
|---|---|
| `SESSION_NOT_FOUND` | Refresh token is invalid, expired, or already rotated |

---

## 7. Logout

Logout revokes the current session. The refresh token becomes immediately invalid. The access token remains technically valid until its natural expiry (`expires_in`), but it will be added to a **JTI blacklist** checked on every request.

### Request

```
POST /v1/auth/logout
```

Requires an authenticated request (valid `Authorization: Bearer` header).

```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

### Successful Response (`200 OK`)

```json
{}
```

### Sequence Diagram

```
Client                          core-auth
  │                                  │
  │── POST /v1/auth/logout ─────────►│
  │   Authorization: Bearer <token>  │ 1. Validate access token (JWT)
  │   { refresh_token }              │ 2. Revoke session (mark revoked_at = NOW)
  │                                  │ 3. Blacklist access token JTI (Redis, until exp)
  │                                  │ 4. Emit audit event (logout)
  │◄── 200 OK {} ───────────────────│
```

> [!TIP]
> After logout, clear the access token from memory and the refresh token from storage immediately. Redirect to your login screen.

---

## 8. Password Reset Flow

The password reset flow is a three-step process: request a reset email → user clicks link → submit the new password.

### Step 1 — Request a reset email

```
POST /v1/auth/forgot-password
```

```json
{
  "email": "alice@example.com"
}
```

**Always returns `200 OK`** — even if no account exists for that email. This prevents **email enumeration**.

### Step 2 — User clicks the link in their email

The email contains a link such as:
```
https://your-app.com/reset-password?token=<reset_token>
```

The frontend extracts `token` from the query string and presents a "new password" form.

### Step 3 — Submit the new password

```
POST /v1/auth/reset-password
```

```json
{
  "token": "<reset_token_from_email>",
  "new_password": "NewSecurePass456!"
}
```

### Successful Response (`200 OK`)

```json
{}
```

> [!IMPORTANT]
> A successful password reset **immediately revokes all existing sessions** across all devices. Users will need to log in again on every device. This is intentional — if the password was compromised, active attacker sessions are also invalidated.

### Common Errors

| Error | Cause |
|---|---|
| `INVALID_TOKEN` | Token is missing or malformed |
| `TOKEN_NOT_FOUND` | Token doesn't exist — possibly already used or expired |
| `TOKEN_EXPIRED` | Reset tokens have a fixed TTL; user must request a new one |
| `TOKEN_ALREADY_USED` | The one-time token was already consumed |
| `PASSWORD_POLICY_VIOLATION` | New password doesn't meet complexity requirements |

---

## 9. Error Reference

All errors follow the `google.rpc.Status` format wrapped in the HTTP response body. The `details` array will include an `ErrorInfo` object with a `reason` field and metadata.

**Error response shape:**

```json
{
  "code": 3,
  "message": "human-readable description",
  "details": [
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "INVALID_CREDENTIALS",
      "domain": "core-auth",
      "metadata": {}
    }
  ]
}
```

### gRPC → HTTP status mapping

| gRPC Code | HTTP Status | Typical reason codes |
|---|---|---|
| `INVALID_ARGUMENT` (3) | 400 | `INVALID_IDENTIFIER`, `INVALID_IDENTIFIER_FORMAT`, `PASSWORD_POLICY_VIOLATION` |
| `UNAUTHENTICATED` (16) | 401 | `INVALID_CREDENTIALS`, `INVALID_TOKEN`, `TOKEN_EXPIRED` |
| `PERMISSION_DENIED` (7) | 403 | `ACCOUNT_SUSPENDED`, `ACCOUNT_LOCKED`, `IP_NOT_ALLOWED` |
| `NOT_FOUND` (5) | 404 | `USER_NOT_FOUND`, `SESSION_NOT_FOUND` |
| `ALREADY_EXISTS` (6) | 409 | `USER_ALREADY_EXISTS`, `MFA_ALREADY_ENROLLED` |
| `RESOURCE_EXHAUSTED` (8) | 429 | `TOO_MANY_REQUESTS` |
| `INTERNAL` (13) | 500 | Internal server errors |

> [!TIP]
> Use the `reason` field in `ErrorInfo` — not the human-readable `message` — to drive your UI logic. Messages may change; reason codes are stable.

---

## 10. Flow Cheat Sheet

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AUTHENTICATION FLOW OVERVIEW                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  New User                                                              │
│  ─────────                                                             │
│  POST /v1/auth/register  →  user (no tokens)                          │
│  [verify email via OTP]                                                │
│  POST /v1/auth/login     →  tokens  ─────────────────────┐            │
│                                                           │            │
│  Returning User (no MFA)                                  │            │
│  ───────────────────────                                  │            │
│  POST /v1/auth/login     →  login_success.tokens ────────┤            │
│                                                           │            │
│  Returning User (MFA enrolled)                            │            │
│  ─────────────────────────────                            ▼            │
│  POST /v1/auth/login     →  mfa_required         Use access_token      │
│  POST /v1/mfa/challenge  →  tokens ─────────►    in Authorization      │
│                                                   header               │
│  Token Expired                                                         │
│  ─────────────                                                         │
│  POST /v1/auth/refresh   →  new token pair  (old refresh invalidated)  │
│                                                                        │
│  End of Session                                                        │
│  ──────────────                                                        │
│  POST /v1/auth/logout    →  {} (session revoked, JTI blacklisted)     │
│                                                                        │
│  Forgot Password                                                       │
│  ───────────────                                                       │
│  POST /v1/auth/forgot-password  →  {} (email sent, always 200)        │
│  POST /v1/auth/reset-password   →  {} (all sessions revoked)          │
│                                                                        │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Related Guides

| Guide | What it covers |
|---|---|
| [`docs/guides/mfa.md`](./mfa.md) | TOTP enrollment, recovery code flow, disabling MFA |
| [`docs/guides/session-management.md`](./session-management.md) | Multi-device sessions, listing and revoking sessions |
| [`docs/guides/frontend-integration.md`](./frontend-integration.md) | Cookie vs. bearer, CSRF, recommended storage patterns |
| [`docs/error-catalog.md`](../error-catalog.md) | Every error reason code with gRPC status + HTTP equivalent |
| [`docs/security/token-model.md`](../security/token-model.md) | JWT claims, signing algorithm, rotation policy |
| [`docs/guides/grpc-integration.md`](./grpc-integration.md) | gRPC client setup, auth metadata, structured error handling |

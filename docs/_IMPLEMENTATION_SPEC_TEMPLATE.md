# Core-Auth Implementation Specification

This document provides step-by-step pseudo-code, explicit database schemas, and cryptographic requirements to reproduce the `core-auth` system in any programming language. It is designed to act as a strict blueprint for technical implementation.

---

## 0. System & Cryptography Setup

This section covers every piece of infrastructure and cryptographic primitive that must be configured **before** any feature can be implemented. Every bullet below maps directly to something used in the codebase.

---

### 0.1 Infrastructure Dependencies

The following services must be running and reachable:

| Dependency | Purpose |
|---|---|
| **PostgreSQL** | Persistent storage for all user, session, MFA, tenant, and audit data. |
| **Redis** | Ephemeral storage for rate limiting counters, MFA sessions, OAuth state tokens, OTPs, and refresh token lookups. |
| **Email Provider (Resend)** | Transactional email delivery for OTPs, magic links, and password resets. |
| **Google OAuth 2.0** (optional) | Social login provider. Required only if OAuth features are enabled. |
| **WhatsApp Business API** (optional) | Used only for the WhatsApp verification flow. |

---

### 0.2 Environment Variables

All configuration is injected at runtime via environment variables. None are optional unless marked.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GRPC_PORT` | No | `50051` | Port the gRPC server listens on. |
| `HTTP_PORT` | No | `8080` | Port the REST/HTTP gateway listens on. |
| `DATABASE_URL` | **Yes** | — | Full Postgres connection string (e.g. `postgres://user:pass@host/db?sslmode=disable`). |
| `REDIS_HOST` | **Yes** | — | Redis host (e.g. `localhost`). |
| `REDIS_PORT` | **Yes** | `6379` | Redis port. |
| `REDIS_PASSWORD` | No | — | Redis password. |
| `RSA_PRIVATE_KEY_PATH` | **Yes** | — | Filesystem path to the PEM-encoded RSA private key file (PKCS#8 format). |
| `JWT_ISSUER` | **Yes** | — | The `iss` claim embedded in all JWTs (e.g., `https://auth.example.com`). |
| `RESEND_API_KEY` | **Yes** | — | API key for the Resend email service. |
| `RESEND_FROM` | No | `onboarding@resend.dev` | The `From` address used for all outbound emails. |
| `FRONTEND_URL` | No | `http://localhost:3000` | Used when constructing magic link and password reset URLs in emails. |
| `BASE_URL` | No | `http://localhost:8080` | Public base URL of this service (used in JWKS and OAuth callback URLs). |
| `MFA_ENCRYPTION_KEY` | **Yes** | — | A **32-byte, hex-encoded** AES-256 key used to encrypt TOTP secrets at rest. |
| `WHATSAPP_BUSINESS_PHONE` | No | `+6281234567890` | Sender phone number for the WhatsApp verification flow. |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth 2.0 client ID. |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth 2.0 client secret. |
| `RATE_LIMIT_MAX_FAILED_PER_IP` | No | `30` | Max failed login attempts from one IP before an IP-level block is applied. |
| `RATE_LIMIT_IP_WINDOW` | No | `15m` | Sliding window duration for the per-IP counter. |
| `RATE_LIMIT_MAX_FAILED_PER_ACCOUNT` | No | `10` | Max failed attempts on one account before the account is locked. |
| `RATE_LIMIT_ACCOUNT_LOCKOUT` | No | `15m` | How long an account stays locked after reaching the threshold. |
| `SECURE_COOKIE` | No | `true` | Sets the `Secure` flag on HTTP cookies. Set to `false` only in local dev. |
| `SUSPICIOUS_LOGIN_ENABLED` | No | `true` | Whether to detect and act on logins from new/unknown locations. |
| `SUSPICIOUS_LOGIN_WINDOW` | No | `2160h` (90 days) | How far back to look for "known" login patterns. |
| `SUSPICIOUS_LOGIN_ACTION` | No | `audit_only` | Action on suspicious login: `"audit_only"` or `"challenge_mfa"`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | *(empty)* | OpenTelemetry collector endpoint. Leave empty to disable tracing entirely. |

---

### 0.3 RSA Key Pair Generation (for JWT Signing)

JWTs are signed using **RS256** (RSA + SHA-256 asymmetric signing). You need a private key to sign tokens and a public key (exposed via JWKS) so external services can verify them.

**Steps:**
```text
1. Generate a 4096-bit RSA private key in PKCS#8 format:
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out private.pem

2. (Optional) Derive the public key for inspection or manual JWKS construction:
   openssl rsa -in private.pem -pubout -out public.pem

3. Set RSA_PRIVATE_KEY_PATH=/path/to/private.pem in your environment.
```

**Key ID (`kid`) derivation:**
- The service automatically derives the `kid` header value from the public key.
- Algorithm: `SHA-256(DER-encoded public key)`, take the first 8 bytes, encode as base64url.
- This means the `kid` changes automatically when you rotate the key file — no manual JWKS updates needed.

---

### 0.4 AES-256-GCM Key Generation (for TOTP Secret Encryption)

TOTP secrets stored in the database are encrypted at rest using **AES-256-GCM** (authenticated encryption). This requires a 32-byte key.

**Steps:**
```text
1. Generate 32 cryptographically random bytes:
   openssl rand -hex 32
   → outputs a 64-character hex string

2. Set MFA_ENCRYPTION_KEY=<that 64-char hex string> in your environment.
```

**Encryption scheme:**
- Mode: **AES-256-GCM** (provides both confidentiality and integrity).
- Nonce: 12 bytes, generated fresh for every encryption operation via `crypto/rand`.
- Storage format: `base64(nonce + ciphertext)` — the nonce is prepended to the ciphertext.
- There is **no key versioning**: rotating the key requires re-encrypting all stored TOTP secrets.

---

### 0.5 Password Hashing (Argon2id)

All user passwords are hashed using **Argon2id** (the memory-hard, side-channel resistant variant of Argon2) before being stored. Passwords are never stored in plain text.

**Parameters (OWASP minimum recommendation):**
| Parameter | Value | Notes |
|---|---|---|
| Algorithm | `argon2id` | Required variant — not `argon2i` or `argon2d`. |
| Memory (`m`) | `65536` KiB (64 MiB) | Increase to 128 MiB for higher security if latency allows. |
| Iterations (`t`) | `1` | Increase to `3` if you can tolerate ~150ms per hash. |
| Parallelism (`p`) | `4` | Match to available CPU cores. |
| Key length | `32` bytes | Derived key length. |
| Salt length | `16` bytes | Randomly generated per hash using `crypto/rand`. |

**Storage format (PHC string):**
```text
$argon2id$v=19$m=65536,t=1,p=4$<base64(salt)>$<base64(hash)>
```
The parameters are stored inside the hash string itself, so old password hashes remain verifiable even after tuning parameters for new hashes.

**Password comparison:**
- Must use **constant-time comparison** (e.g., `crypto/subtle.ConstantTimeCompare`) to prevent timing attacks. Never use a regular string equality check (`==`).

---

### 0.6 JWT Access Token Design

| Claim | Field | Description |
|---|---|---|
| `sub` | `user.id` | The authenticated user's UUID. |
| `iss` | `JWT_ISSUER` env var | Who issued the token. |
| `iat` | Current timestamp | Issued-at time (Unix seconds). |
| `exp` | `iat + TTL` | Expiry time. |
| `jti` | 16 random bytes → 32-char hex | Unique token ID. Used as a Redis blacklist key on logout. |
| `role` | User's role | Custom claim for authorization. |
| `scope` | `["openid", ...]` | Custom claim listing granted OAuth scopes. |

**Signing:** RS256. The `kid` header is always included to allow JWKS-based key rotation by consumers.

---

### 0.7 Refresh Token Design

Refresh tokens are **not JWTs**. They are opaque, high-entropy random strings.

```text
1. Generate 32 crypto-random bytes via crypto/rand.
2. Hex-encode → 64-character string. This is the raw refresh token returned to the client.
3. SHA-256 hash the raw token.
4. Store the SHA-256 hash in the `sessions` table (never store the raw token).
5. On refresh: receive raw token from client → hash it → look it up in the DB by hash.
```
This approach means a database breach does not expose valid refresh tokens.

---

### 0.8 Secure Token Generation Primitives

All random tokens in the system (OTPs, password reset links, OAuth state, magic links) are generated using **cryptographically secure randomness** (`crypto/rand`), never `math/rand`.

| Token Type | Generation Method | Storage |
|---|---|---|
| OTP (6-digit) | Rejection sampling via `crypto/rand.Int` over `big.Int` to avoid modulo bias | SHA-256 hash stored in Redis with TTL |
| Password Reset Token | 32 `crypto/rand` bytes → hex-encoded 64-char string | SHA-256 hash stored in `users` table with expiry timestamp |
| Magic Link Token | 32 `crypto/rand` bytes → hex-encoded 64-char string | SHA-256 hash stored in DB or Redis with TTL |
| OAuth State Token | 32 `crypto/rand` bytes → hex-encoded 64-char string | Stored in Redis with short TTL (~10 min) |
| Refresh Token | 32 `crypto/rand` bytes → hex-encoded 64-char string | SHA-256 hash stored in `sessions` table |
| JWT `jti` | 16 `crypto/rand` bytes → hex-encoded 32-char string | Stored in Redis blacklist on logout |

---

### 0.9 Observability Wiring

Both Postgres and Redis connections must be instrumented **at the connection level** so all database queries and cache operations automatically emit child spans under the active request trace.

- **Postgres**: Attach an OpenTelemetry tracer to the connection pool config (`otelpgx` tracer). Every query produces a `pgx.query` span with the SQL as `db.statement`.
- **Redis**: Instrument the Redis client after construction (`redisotel.InstrumentTracing`). Every command (GET, SET, EXPIRE, etc.) produces a child span.
- **gRPC**: Observability middleware (metrics + tracing interceptors) must wrap the server at startup — not inside individual handlers.
- **Disabling Tracing**: If `OTEL_EXPORTER_OTLP_ENDPOINT` is empty, use a no-op `TracerProvider` so all instrumentation calls are safe no-ops without any code changes.

---

## 1. Authentication (`auth` domain)

### Feature: Register
**Description:** Creates a new user account with an email and password, securely hashing the password before storing it.

#### 1. Database Requirements
*(Placeholder: Describe table schema, e.g., `users` table fields and types)*

#### 2. Request / Response Contract
*(Placeholder: Define the JSON request/response structures)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Step-by-step pseudo code to validate input, hash with Argon2, and store user
```

### Feature: Login
**Description:** Verifies user credentials mathematically against the stored hash, applies security policies, and issues tokens.

#### 1. Database Requirements
*(Placeholder: Define required fields from `users` and `sessions` tables)*

#### 2. Request / Response Contract
*(Placeholder: Define JSON payload and token response)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Step-by-step pseudo code for checking tenant IP rules, validating password via Argon2, clearing rate limits, and signing the JWT tokens
```

### Feature: ForgotPassword
**Description:** Initiates a password reset flow by generating a secure reset token and dispatching a recovery email.

#### 1. Database Requirements
*(Placeholder: Define any temporary tables or Redis keys used to store the reset token)*

#### 2. Request / Response Contract
*(Placeholder: Define JSON payload)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Step-by-step pseudo code for token generation and email dispatch
```

### Feature: ResetPassword
**Description:** Consumes the reset token and updates the user's password securely.

#### 1. Database Requirements
*(Placeholder: Define `users` table updates)*

#### 2. Request / Response Contract
*(Placeholder: Define JSON payload)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Step-by-step pseudo code for token validation, Argon2 hashing the new password, and saving
```

---

## 2. Session Management (`session` domain)

### Feature: RefreshToken
**Description:** Exchanges a valid refresh token for a new pair of access and refresh tokens, handling token rotation.

#### 1. Database Requirements
*(Placeholder: Schema for `sessions` table)*

#### 2. Request / Response Contract
*(Placeholder: Expected Refresh Token payload)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Token validation logic, old session invalidation, and new token issuance
```

### Feature: ListSessions
**Description:** Retrieves a list of all active sessions for the authenticated user.

#### 1. Database Requirements
*(Placeholder: Query definition for `sessions` table or Redis)*

#### 2. Request / Response Contract
*(Placeholder)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Fetch logic
```

### Feature: RevokeSession
**Description:** Terminates a specific target session by its ID.

#### 1. Database Requirements
*(Placeholder)*

#### 2. Request / Response Contract
*(Placeholder)*

#### 3. Implementation Pseudo-code
```text
// Placeholder: Deletion or invalidation logic
```

### Feature: RevokeAllSessions
**Description:** Terminates all active sessions for the user globally.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

### Feature: Logout
**Description:** Invalidates the currently active session used to make the request.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

---

## 3. Multi-Factor Authentication (`mfa` domain)

### Feature: SetupTOTP
**Description:** Begins TOTP setup by generating a cryptographic secret and provisioning a QR code.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

### Feature: ConfirmTOTP
**Description:** Finalizes TOTP setup by verifying the first generated token.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

### Feature: ChallengeMFA
**Description:** Validates a TOTP code during the login flow to complete authentication.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

### Feature: DisableMFA
**Description:** Securely removes the TOTP secret and disables the MFA requirement.

*(Placeholder: Requirements, Contracts, and Pseudo-code)*

---

## 4. Social Login / OAuth (`oauth` domain)

*(Placeholder for the following endpoints: `GetOAuthURL`, `OAuthCallback`, `LinkProvider`, `UnlinkProvider`. Each should define Database Requirements, Request Contracts, and Pseudo-code.)*

---

## 5. User Profile (`user` domain)

*(Placeholder for the following endpoints: `GetMe`, `ChangePassword`. Each should define Database Requirements, Request Contracts, and Pseudo-code.)*

---

## 6. Administration (`admin` domain)

*(Placeholder for the following endpoints: `SuspendUser`, `UnsuspendUser`, `DeleteUser`. Each should define Database Requirements, Request Contracts, and Pseudo-code.)*

---

## 7. Passwordless & Verification (`verification` domain)

*(Placeholder for the following endpoints: `SendOTP`, `VerifyOTP`, `SendMagicLink`, `VerifyMagicLink`, `GetWhatsAppVerificationLink`. Each should define Database Requirements, Request Contracts, and Pseudo-code.)*

---

## 8. Cross-Cutting Security Interfaces

*(Placeholder: Describe pseudo-code mechanisms or middleware steps that apply to all flows)*

### Feature: Rate Limiting & Brute Force Protection
*(Placeholder: Describe the generic Redis logic for counting failed attempts and locking accounts)*

### Feature: Tenant Isolation & IP Controls
*(Placeholder: Describe the middleware logic to intercept the IP and validate against allow/denylist)*

### Feature: Audit Logging
*(Placeholder: Describe the asynchronous worker or event-bus logic used to emit and save audit logs)*

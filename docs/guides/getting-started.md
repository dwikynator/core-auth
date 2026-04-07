# Getting Started with core-auth

> **Audience:** Backend engineers, frontend teams, and any service that needs to integrate with `core-auth`.
> This guide gets you from zero to your first successful authenticated API call.

---

## Table of Contents

1. [What is core-auth?](#1-what-is-core-auth)
2. [Prerequisites](#2-prerequisites)
3. [Spinning Up the Service](#3-spinning-up-the-service)
   - [3.1 Clone & Dependencies](#31-clone--dependencies)
   - [3.2 Start Infrastructure](#32-start-infrastructure)
   - [3.3 Environment Variables](#33-environment-variables)
   - [3.4 Generate RSA Key Pair](#34-generate-rsa-key-pair)
   - [3.5 Run Database Migrations](#35-run-database-migrations)
   - [3.6 Start the Server](#36-start-the-server)
4. [Environment Variables Reference](#4-environment-variables-reference)
5. [Verifying the Service is Up](#5-verifying-the-service-is-up)
6. [Your First API Call](#6-your-first-api-call)
   - [6.1 Register a User (HTTP)](#61-register-a-user-http)
   - [6.2 Login (HTTP)](#62-login-http)
   - [6.3 Authenticated Request](#63-authenticated-request)
7. [Connecting via gRPC](#7-connecting-via-grpc)
8. [Next Steps](#8-next-steps)

---

## 1. What is core-auth?

`core-auth` is a self-hosted, multi-tenant authentication service. It exposes **both gRPC and HTTP** on separate ports — gRPC is the primary transport; the HTTP/REST API is provided via [`grpc-gateway`](https://github.com/grpc-ecosystem/grpc-gateway) and is the easiest way to start integrating.

Key capabilities at a glance:

| Feature | Summary |
|---|---|
| Registration & Login | Email / username / phone + password |
| MFA | TOTP-based (authenticator apps) |
| Token model | Short-lived JWT access token + opaque refresh token |
| Session management | Multi-device, revocable sessions |
| Social login | OAuth2 (Google) |
| Multi-tenancy | Tenant isolation via `client_id`, per-tenant IP policy |
| Security | Argon2id hashing, rate limiting, brute-force lockout, audit logging |

---

## 2. Prerequisites

Make sure the following are installed and available on your `$PATH` before continuing:

| Tool | Minimum version | Purpose |
|---|---|---|
| **Go** | 1.22+ | Running / building the service |
| **Docker** & Docker Compose | Latest stable | PostgreSQL and Redis |
| **[goose](https://github.com/pressly/goose)** | v3+ | Running database migrations |
| **openssl** or **ssh-keygen** | Any | Generating the RSA key pair for JWT signing |
| `make` | Any | Convenience wrapper around common commands |

> [!TIP]
> Install goose with: `go install github.com/pressly/goose/v3/cmd/goose@latest`

Optional (for live-reload during development):

| Tool | Purpose |
|---|---|
| **[air](https://github.com/air-verse/air)** | Hot-reload on file changes (`make dev`) |

---

## 3. Spinning Up the Service

### 3.1 Clone & Dependencies

```bash
git clone https://github.com/dwikynator/core-auth.git
cd core-auth
go mod download
```

### 3.2 Start Infrastructure

The service requires **PostgreSQL 16** and **Redis 7**. A `docker-compose.yaml` is included at the repo root:

```bash
make docker-up
# or: docker compose up -d
```

This starts:

| Container | Image | Port mapping | Credentials |
|---|---|---|---|
| `core-auth-postgres` | `postgres:16-alpine` | `5432:5432` | `core_auth / core_auth` |
| `core-auth-redis` | `redis:7-alpine` | `6380:6379` (host:container) | none |

> [!NOTE]
> Redis is exposed on host port **6380** (not 6379) to avoid conflicts with a locally running Redis instance.

### 3.3 Environment Variables

Copy the example file and fill in the required values:

```bash
cp .env.example .env
```

Open `.env` and set every value marked **required** in the [reference table below](#4-environment-variables-reference). For a local dev setup, only the following need changing from the defaults:

- `RESEND_API_KEY` — get a free key at [resend.com](https://resend.com)
- `MFA_ENCRYPTION_KEY` — generate a 32-byte hex string (see below)
- `RSA_PRIVATE_KEY_PATH` — path to the generated RSA key (see next step)

Generate the `MFA_ENCRYPTION_KEY`:
```bash
openssl rand -hex 32
```

### 3.4 Generate RSA Key Pair

`core-auth` uses **RS256** to sign JWTs. You need to generate an RSA key pair once and point the config at it:

```bash
# Create the keys directory (already in .gitignore)
mkdir -p keys

# Generate a 4096-bit RSA private key
openssl genrsa -out keys/private.pem 4096

# (Optional) Extract the public key for verification by consumers
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

Set `RSA_PRIVATE_KEY_PATH=keys/private.pem` in your `.env`.

> [!CAUTION]
> **Never commit `keys/private.pem` to version control.** It is already listed in `.gitignore`. Treat this file like a production secret.

### 3.5 Run Database Migrations

With the database running and `.env` loaded:

```bash
make migrate-up
```

This applies all migrations from the `migrations/` directory in order. You can check the current state at any time with:

```bash
make migrate-status
```

<details>
<summary>Migrations applied</summary>

| # | File | Description |
|---|---|---|
| 001 | `create_users.sql` | Core user identity table |
| 002 | `create_user_providers.sql` | OAuth provider links |
| 003 | `create_verification_tokens.sql` | OTP and magic link tokens |
| 004 | `create_sessions.sql` | Refresh token sessions |
| 005 | `create_tenant_configs.sql` | Per-tenant configuration |
| 006 | `add_tenant_scopes.sql` | OAuth scope definitions per tenant |
| 007 | `create_mfa_credentials.sql` | Encrypted TOTP secrets |
| 008 | `create_login_attempts.sql` | Rate-limiting tracking table |
| 009 | `tenant_ip_policy.sql` | IP allowlist / denylist rules |

</details>

### 3.6 Start the Server

**Production-like (single run):**
```bash
make run
# or: go run ./cmd/server
```

**Development (with hot-reload, requires `air`):**
```bash
make dev
```

When the server starts successfully you will see log output indicating both ports are ready:

```
gRPC server listening on :50051
HTTP gateway listening on :8080
```

---

## 4. Environment Variables Reference

All configuration is read from environment variables (or a `.env` file at the repo root). The service validates required values on startup and will refuse to start if any are missing.

### Server

| Variable | Default | Required | Description |
|---|---|---|---|
| `GRPC_PORT` | `50051` | No | Port for the gRPC server |
| `HTTP_PORT` | `8080` | No | Port for the HTTP/REST gateway |

### Database

| Variable | Default | Required | Description |
|---|---|---|---|
| `DATABASE_URL` | — | **Yes** | PostgreSQL connection string. Example: `postgres://core_auth:core_auth@localhost:5432/core_auth?sslmode=disable` |

### Cache / Session Store

| Variable | Default | Required | Description |
|---|---|---|---|
| `REDIS_HOST` | — | **Yes** | Redis host. Example: `localhost` |
| `REDIS_PORT` | `6379` | **Yes** | Redis port. Example: `6380` |
| `REDIS_PASSWORD` | — | No | Redis password. Optional in development. |

### JWT & Token Signing

| Variable | Default | Required | Description |
|---|---|---|---|
| `RSA_PRIVATE_KEY_PATH` | — | **Yes** | Path to the PEM-encoded RSA private key used to sign access tokens (RS256). |
| `JWT_ISSUER` | — | **Yes** | The `iss` claim embedded in every access token. Must match what consumers validate against. Example: `core-auth` |

### Email (Resend)

| Variable | Default | Required | Description |
|---|---|---|---|
| `RESEND_API_KEY` | — | **Yes** | API key from [resend.com](https://resend.com) for sending verification and password reset emails. |
| `RESEND_FROM` | `onboarding@resend.dev` | No | Sender address. Use your own verified domain in production. |
| `FRONTEND_URL` | `http://localhost:3000` | No | Base URL of your frontend, used when constructing links in emails (e.g. password reset links). |
| `BASE_URL` | `http://localhost:8080` | No | Public base URL of this service, used for constructing OAuth callback URLs. |

### MFA

| Variable | Default | Required | Description |
|---|---|---|---|
| `MFA_ENCRYPTION_KEY` | — | **Yes** | 32-byte hex-encoded AES-256 key used to encrypt TOTP secrets at rest. Generate with `openssl rand -hex 32`. |
| `WHATSAPP_BUSINESS_PHONE` | `+6281234567890` | No | WhatsApp Business number used for WhatsApp-based OTP delivery. |

### OAuth2 — Google

| Variable | Default | Required | Description |
|---|---|---|---|
| `GOOGLE_CLIENT_ID` | — | No | Google OAuth2 client ID. Required only if you enable Google social login. |
| `GOOGLE_CLIENT_SECRET` | — | No | Google OAuth2 client secret. Required only if you enable Google social login. |

### Rate Limiting & Account Lockout

| Variable | Default | Required | Description |
|---|---|---|---|
| `RATE_LIMIT_MAX_FAILED_PER_IP` | `30` | No | Max failed login attempts from a single IP within the window before that IP is blocked. |
| `RATE_LIMIT_IP_WINDOW` | `15m` | No | Sliding window duration for the per-IP counter. Accepts Go duration strings (`15m`, `1h`, etc.). |
| `RATE_LIMIT_MAX_FAILED_PER_ACCOUNT` | `10` | No | Max failed login attempts for a single account before it is temporarily locked. |
| `RATE_LIMIT_ACCOUNT_LOCKOUT` | `15m` | No | How long an account stays locked after hitting the threshold. |

### Security

| Variable | Default | Required | Description |
|---|---|---|---|
| `SECURE_COOKIE` | `true` | No | Set to `false` only in local HTTP development. In production this must always be `true`. |
| `SUSPICIOUS_LOGIN_ENABLED` | `true` | No | Enable detection of logins from previously unseen IPs / user-agents. |
| `SUSPICIOUS_LOGIN_WINDOW` | `2160h` (90 days) | No | How far back login history is checked to determine if a login looks suspicious. |
| `SUSPICIOUS_LOGIN_ACTION` | `audit_only` | No | What to do when a suspicious login is detected. Options: `audit_only` or `challenge_mfa`. |

### Observability

| Variable | Default | Required | Description |
|---|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | *(empty)* | No | OTLP endpoint for distributed tracing (e.g. `http://localhost:4317`). Leave empty to disable tracing (a no-op provider is used). |

---

## 5. Verifying the Service is Up

**HTTP health check** — the HTTP gateway is reachable if you can hit any endpoint:

```bash
curl -s http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

You should receive a structured error response (not a connection refused), which confirms the server is up:

```json
{
  "code": 3,
  "message": "at least one identifier (email, username, or phone) is required",
  "details": [...]
}
```

**Swagger / OpenAPI UI** — a self-hosted Swagger UI is served at:

```
http://localhost:8080/swagger/
```

**Prometheus metrics** — available at:

```
http://localhost:8080/metrics
```

---

## 6. Your First API Call

All examples below use the HTTP gateway (`localhost:8080`). Equivalent gRPC examples are in [Section 7](#7-connecting-via-grpc).

> [!NOTE]
> Every request requires a `client_id`. This is your **tenant identifier** — it determines which scopes are returned and which IP policy is enforced. For local development, any non-empty string works (e.g., `"test-app"`); in production, tenant records must be provisioned in the database.

### 6.1 Register a User (HTTP)

```bash
curl -s -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "test-app",
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }' | jq .
```

**Successful response (`200 OK`):**

```json
{
  "user": {
    "user_id": "40bf857f-d513-402a-a92c-f6fa9b422a55",
    "email": "alice@example.com",
    "username": "",
    "phone": "",
    "role": "user",
    "scopes": ["openid", "profile"],
    "email_verified": false,
    "phone_verified": false,
    "mfa_enabled": false
  },
  "tokens": null
}
```

> [!NOTE]
> `tokens` is `null` after registration. The user must log in separately to receive a token pair. A verification email is sent asynchronously — the user's `email_verified` status will be `false` until they confirm the OTP.

**Password policy:** Passwords must be 8–128 characters and contain at least one uppercase letter, one lowercase letter, and one digit.

### 6.2 Login (HTTP)

```bash
curl -s -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "test-app",
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }' | jq .
```

**Successful response (`200 OK`):**

```json
{
  "login_success": {
    "user": {
      "user_id": "40bf857f-d513-402a-a92c-f6fa9b422a55",
      "email": "alice@example.com",
      "role": "user",
      "scopes": ["openid", "profile"],
      "email_verified": false,
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

> [!IMPORTANT]
> If the account has MFA enabled, the response shape will be different — the `login_success` key will instead be `mfa_required`, containing a short-lived `mfa_session_token`. See [`docs/guides/mfa.md`](./mfa.md) for the full MFA challenge flow.

Store the `access_token` (valid for `expires_in` seconds) and `refresh_token` (for token rotation) securely. Never store them in `localStorage` if you can avoid it — see [`docs/guides/frontend-integration.md`](./frontend-integration.md) for recommended storage patterns.

### 6.3 Authenticated Request

Pass the access token as a `Bearer` token in the `Authorization` header:

```bash
ACCESS_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -s http://localhost:8080/v1/user/me \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
```

---

## 7. Connecting via gRPC

The gRPC server listens on port `50051` by default. The proto definitions live in [`proto/auth/v1/`](../../proto/auth/v1/).

**Import path:**
```
github.com/dwikynator/core-auth/gen/auth/v1
```

**Quick connection check with `grpcurl`:**

```bash
# Install: brew install grpcurl / go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List available services
grpcurl -plaintext localhost:50051 list

# Describe the AuthService
grpcurl -plaintext localhost:50051 describe auth.v1.AuthService

# Make a register call
grpcurl -plaintext -d '{
  "client_id": "test-app",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}' localhost:50051 auth.v1.AuthService/Register
```

**Authentication metadata:** All protected RPCs require the access token passed as gRPC metadata:

```
authorization: Bearer <access_token>
```

> For a full guide on error handling from `google.rpc.Status` + `ErrorInfo`, see [`docs/guides/grpc-integration.md`](./grpc-integration.md).

---

## 8. Next Steps

Now that the service is running and you've made your first API call, here's what to read next (in priority order):

| Guide | What it covers |
|---|---|
| [`docs/guides/authentication-flow.md`](./authentication-flow.md) | End-to-end flow: register → login → refresh → logout, with sequence diagrams oriented at a client consumer |
| [`docs/guides/frontend-integration.md`](./frontend-integration.md) | Cookie vs. bearer token, CSRF handling, MFA challenge UX, recommended token storage |
| [`docs/error-catalog.md`](../error-catalog.md) | Every error code the service can return — grouped by domain with gRPC status + HTTP equivalent |
| [`docs/security/token-model.md`](../security/token-model.md) | Access vs. refresh token lifecycle, rotation policy, signing algorithm |
| [`docs/guides/mfa.md`](./mfa.md) | TOTP enrollment, challenge, and recovery from a client's perspective |
| [`docs/guides/grpc-integration.md`](./grpc-integration.md) | Proto import path, auth interceptors, structured error handling |
| [`docs/ops/configuration.md`](../ops/configuration.md) | Full environment variable reference for production deployments |

### Useful Make Targets

```bash
make run           # Start the server (single run)
make dev           # Start with hot-reload (requires air)
make migrate-up    # Apply pending database migrations
make migrate-status # Show current migration state
make migrate-down  # Roll back one migration
make docker-up     # Start PostgreSQL + Redis containers
make docker-down   # Stop containers
make db-shell      # Open a psql shell inside the Postgres container
make redis-shell   # Open a redis-cli shell inside the Redis container
make proto         # Regenerate code from .proto files
make test          # Run all tests
```

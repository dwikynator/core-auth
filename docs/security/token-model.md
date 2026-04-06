# Token Model

This document describes how `core-auth` issues, validates, rotates, and revokes tokens. It covers the access token (JWT) and refresh token (opaque) design, the signing algorithm, claim structure, default lifetimes, per-tenant overrides, and the security rationale behind each decision.

---

## Overview: Hybrid Token Strategy

`core-auth` uses a **hybrid token model**:

| Token | Type | Storage (server-side) | Storage (client-side) | Lifetime |
|---|---|---|---|---|
| **Access token** | Signed JWT (RS256) | Nothing (stateless) + JTI blacklist on logout | Bearer header / `HttpOnly` cookie | 15 min (default) |
| **Refresh token** | Opaque random bytes | SHA-256 hash in Postgres `sessions` table | `HttpOnly` cookie / secure storage | 30 days (default) |

**Why two separate tokens?**

- The access token is **stateless**: any service with the public key can verify it without a round-trip to the database or cache. Short lifetime limits the blast radius if a token is leaked.
- The refresh token is **stateful**: it is validated against a persisted session record, enabling true revocation. It is never put in a JWT to prevent claims tampering.

---

## Access Token

### Signing Algorithm: RS256

Access tokens are signed using **RS256** (RSA PKCS#1 v1.5 with SHA-256). The private key is loaded from disk at startup (`RSA_PRIVATE_KEY_PATH`). The public key is exposed via `/.well-known/jwks.json` so any consumer can verify tokens independently.

**Why RS256 over HS256?**
- HS256 requires sharing a symmetric secret with every verifier. RS256 lets the database, downstream microservices, or third-party systems verify tokens using only the public key — no secret exposure.
- Key rotation is transparent: the `kid` header in each JWT matches the JWKS entry; consumers update their cached key on `kid` mismatch.

### Key ID (`kid`)

The `kid` is derived deterministically from the public key:

```
kid = base64url(sha256(DER(public_key))[:8])  // 11-character truncated fingerprint
```

This means:
- `kid` changes automatically when the key file is rotated.
- There is no manual `kid` management — the fingerprint is the source of truth.
- The same `kid` appears in both the JWT header and the JWKS response.

### JWT Claims Structure

Every access token contains the following claims:

```json
{
  "jti": "a3f8c2d1e4b5...",     // 32-char hex — 16 random bytes, unique per token
  "sub": "018e1a2b-...",        // User UUID
  "iss": "https://auth.example.com",  // Configured via JWT_ISSUER env var
  "iat": 1711929600,            // Issued-at (Unix seconds)
  "exp": 1711930500,            // Expiry (iat + access TTL)
  "role": "user",               // User's role ("user" | "admin" | ...)
  "scope": ["openid", "profile", "email"]  // Tenant-specific or system default scopes
}
```

| Claim | Go field | Notes |
|---|---|---|
| `jti` | `Claims.ID` | 16 random bytes → 32-char hex. Used as the blacklist key on logout. |
| `sub` | `Claims.Subject` | User UUID. Primary identity claim. |
| `iss` | `Claims.Issuer` | Must match `JWT_ISSUER` env var on all validators. |
| `iat` | `Claims.IssuedAt` | Standard; set to `time.Now()` at signing time. |
| `exp` | `Claims.ExpiresAt` | `iat + access_ttl`. Default: 15 minutes. |
| `role` | `Claims.Role` | Custom claim. Injected by the token issuer. |
| `scope` | `Claims.Scopes` | Custom claim. OpenID Connect-compatible scope list. |

The JWT header also carries `"alg": "RS256"` and `"kid": "<derived fingerprint>"`.

### Validation Steps

On every authenticated request, the token validator performs:

1. **Parse & verify signature** using the RSA public key (only `RS256` is accepted).
2. **Validate standard claims**: `exp` must be in the future; `iss` must match the configured issuer.
3. **JTI blacklist check** via Redis: `EXISTS blacklist:jti:<jti>`. If found → token is revoked → `401`.

Step 3 is **fail-closed**: if Redis is unavailable, the request is rejected. A brief Redis outage produces a `503`; letting a revoked token slip through would be a security incident.

---

## Refresh Token

### Generation

The refresh token is **opaque** — it carries no claims and cannot be decoded. It is generated as:

```
refresh_token = hex(rand_bytes(32))   // 64-char hex string, 256 bits of entropy
```

The raw token is sent to the client **once** and never stored on the server. Instead, the server stores its SHA-256 hash:

```
refresh_token_hash = hex(sha256(refresh_token))
```

**Why hash it?**
The refresh token is equivalent to a password for continued access. Storing a hash means a database breach cannot be used to issue new tokens directly — an attacker would need to invert SHA-256, which is computationally infeasible for a 256-bit random value.

### Session Record

Every refresh token is tied to a **session** row in Postgres:

```sql
CREATE TABLE sessions (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id          VARCHAR(255) NOT NULL DEFAULT '',
    refresh_token_hash TEXT NOT NULL,
    ip_address         INET,
    user_agent         TEXT NOT NULL DEFAULT '',
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,      -- NULL = active; set = revoked
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

The lookup path (`/v1/auth/refresh`) uses a **unique partial index** on `(refresh_token_hash) WHERE revoked_at IS NULL` — the hot path hits this index on every token refresh call.

### Token Rotation

Every call to `/v1/auth/refresh` performs **single-use rotation**:

1. Incoming refresh token → SHA-256 hash.
2. Lookup active session by hash.
3. Generate new token pair (new access token + new refresh token).
4. `UPDATE sessions SET refresh_token_hash = <new_hash>, last_used_at = NOW()` — atomically in a single query.
5. Return the new token pair to the client.
6. **Old refresh token is immediately invalid.** Any subsequent use of the old token will produce `ErrSessionNotFound`.

**Reuse detection**: If the old token is presented after rotation (i.e., `sessions` returns no row for that hash because it was already rotated), the system returns `ErrTokenReuseDetected`. This indicates the token was either replayed by an attacker or the client sent a stale token. The recommended production response is to revoke all sessions for the affected user.

### Refresh Token Expiry

On rotation, `expires_at` is extended:

```sql
expires_at = NOW() + INTERVAL '30 days'
```

This means **active users never get logged out** — each refresh extends the session window. A user who stops refreshing for more than 30 days will find their session expired.

---

## Token Lifetimes

Default lifetimes (defined in `internal/session/domain.go`):

| Token | Default TTL | Config source |
|---|---|---|
| Access token | **15 minutes** | `DefaultAccessTokenTTL` |
| Refresh token | **30 days** | `DefaultRefreshTokenTTL` |

### Per-Tenant Overrides

Lifetimes and scopes are **per-tenant configurable** via the `tenant_configs` table. The session usecase resolves them at token issuance time:

```
1. Look up TenantConfig by client_id
2. If found: use tc.AccessTokenTTL, tc.RefreshTokenTTL, tc.DefaultScopes
3. If not found (ErrTenantNotFound): fall back to system defaults
```

This allows, for example, a high-security B2B tenant to enforce 5-minute access tokens, while a consumer app defaults to 15 minutes.

---

## Revocation

`core-auth` uses two complementary revocation mechanisms:

### 1. Access Token Blacklist (Redis)

On **logout**, the current access token's `jti` is added to the Redis blacklist:

```
Key:   blacklist:jti:<jti>
Value: "1"
TTL:   remaining lifetime of the token (time.Until(exp))
```

Properties:
- **Bounded memory**: the list never grows unboundedly — each entry auto-expires when the token would have expired anyway.
- **O(1) check**: every authenticated request runs `EXISTS blacklist:jti:<jti>` in Redis.
- **No stale entries**: once a token is naturally expired, the blacklist entry is also gone.

### 2. Session Revocation (Postgres)

The `sessions` table supports targeted revocation:

| Operation | Mechanism |
|---|---|
| Logout | Set `revoked_at = NOW()` for the session matching the refresh token hash |
| Revoke single session | `UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2` |
| Revoke all sessions | `UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL` |
| Revoke all except current | Same query with `AND id != $2` exclusion |

Session revocation prevents **future refresh token use**. It does not invalidate already-issued access tokens (those expire naturally within their TTL, or are caught by the JTI blacklist if logout was called).

> **Design note**: The combination of short access token TTL (15 min) + JTI blacklist + session revocation means a revoked user is fully locked out within 15 minutes at most, with immediate effect if they call logout.

---

## JWKS Endpoint

The public key is exposed as a JSON Web Key Set at:

```
GET /.well-known/jwks.json
```

Response shape:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "<derived fingerprint>",
      "n":   "<base64url RSA modulus>",
      "e":   "<base64url RSA exponent>"
    }
  ]
}
```

Consumers should:
1. Cache the JWKS response (it changes only on key rotation).
2. Re-fetch if the JWT's `kid` is not found in the cached set.
3. Never bypass `kid` matching — this prevents accepting tokens signed by an older or compromised key.

---

## Security Properties Summary

| Property | Implementation |
|---|---|
| **Token integrity** | RS256 signature — forgery requires the private key |
| **Revocation (logout)** | JTI blacklist in Redis, TTL-bounded |
| **Revocation (session)** | `revoked_at` in Postgres sessions table |
| **Refresh token secrecy** | SHA-256 hash stored, raw token sent to client once |
| **Replay detection** | Hash rotation on every refresh; old hash immediately invalid |
| **Theft detection** | `ErrTokenReuseDetected` on stale-token use after rotation |
| **Fail-closed** | Redis error → 503 (not 401 bypass) |
| **Bounded blacklist** | Redis TTL matches token expiry — no unbounded growth |
| **Multi-tenant isolation** | Per-tenant TTL and scopes via `TenantConfig` |
| **Key rotation** | `kid` is auto-derived from public key fingerprint |

---

## Related

- [`docs/security/rate-limiting.md`](rate-limiting.md) — brute-force protection for login
- [`docs/guides/authentication-flow.md`](../guides/authentication-flow.md) — end-to-end login and refresh flow from the client perspective
- [`docs/guides/session-management.md`](../guides/session-management.md) — multi-device session behaviour and revocation APIs
- [`docs/adr/004-jwt-token-strategy.md`](../adr/004-jwt-token-strategy.md) — architectural decision record for this hybrid model

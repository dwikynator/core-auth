# Frontend Integration Guide

> **Audience:** Frontend engineers integrating a web or mobile application with `core-auth`.
> This guide is opinionated and practical — it tells you *how* to implement each screen and *why* certain security choices matter.

---

## Table of Contents

1. [Token Model at a Glance](#1-token-model-at-a-glance)
2. [Storage Strategy: Where to Put Your Tokens](#2-storage-strategy-where-to-put-your-tokens)
   - [2.1 The Recommended Pattern](#21-the-recommended-pattern)
   - [2.2 Why Not `localStorage`?](#22-why-not-localstorage)
   - [2.3 Cookie vs. Bearer: Deciding the Right Approach](#23-cookie-vs-bearer-deciding-the-right-approach)
3. [CSRF Protection](#3-csrf-protection)
   - [3.1 What the Risk Is](#31-what-the-risk-is)
   - [3.2 Double-Submit Cookie Pattern](#32-double-submit-cookie-pattern)
4. [Screen-by-Screen Implementation Guide](#4-screen-by-screen-implementation-guide)
   - [4.1 Registration Screen](#41-registration-screen)
   - [4.2 Email Verification Screen](#42-email-verification-screen)
   - [4.3 Login Screen](#43-login-screen)
   - [4.4 MFA Challenge Screen](#44-mfa-challenge-screen)
   - [4.5 Authenticated Pages & Route Guards](#45-authenticated-pages--route-guards)
   - [4.6 Forgot Password Screen](#46-forgot-password-screen)
   - [4.7 Reset Password Screen](#47-reset-password-screen)
   - [4.8 Logout](#48-logout)
5. [Token Refresh: Silent Renewal](#5-token-refresh-silent-renewal)
   - [5.1 Timer-Based Refresh](#51-timer-based-refresh)
   - [5.2 Interceptor-Based Refresh (Recommended)](#52-interceptor-based-refresh-recommended)
   - [5.3 Tab Coordination](#53-tab-coordination)
6. [Handling API Errors](#6-handling-api-errors)
7. [MFA Enrollment Flow](#7-mfa-enrollment-flow)
8. [OAuth / Social Login](#8-oauth--social-login)
9. [Security Checklist](#9-security-checklist)
10. [Quick Reference](#10-quick-reference)

---

## 1. Token Model at a Glance

`core-auth` issues two tokens after a successful authentication:

| Token | Format | Lifetime | Purpose |
|---|---|---|---|
| `access_token` | Signed JWT (RS256) | **15 minutes** (`expires_in: 900`) | Sent on every protected API request via `Authorization: Bearer` |
| `refresh_token` | Opaque random string | **30 days** (stored in the `sessions` table) | Used once to rotate the token pair silently |

Key constraints your frontend must respect:

- **Access tokens rotate every 15 minutes.** Don't cache them past their `exp` claim.
- **Refresh tokens rotate on every use.** After a successful `/v1/auth/refresh`, you **must** replace the stored refresh token with the new one. The old token is immediately invalidated.
- **Refresh tokens are single-use.** If you attempt to use an already-rotated refresh token, the session is treated as compromised — the user will be logged out.

---

## 2. Storage Strategy: Where to Put Your Tokens

### 2.1 The Recommended Pattern

| Token | Where to store | Rationale |
|---|---|---|
| `access_token` | **In-memory** (JavaScript variable / React state / Vuex store) | Short-lived; lost on page refresh is fine — the refresh token will renew it |
| `refresh_token` | **`HttpOnly`, `Secure`, `SameSite=Strict` cookie** | Inaccessible to JavaScript; immune to XSS |

```
Browser                                   core-auth
   │                                           │
   │── POST /v1/auth/login ──────────────────►│
   │◄── { access_token, refresh_token } ──────│
   │                                           │
   │  Store access_token in memory             │
   │  Set-Cookie: refresh_token (HttpOnly)     │
   │                                           │
   │── GET /v1/protected ────────────────────►│
   │   Authorization: Bearer <access_token>    │
   │◄── 200 OK ────────────────────────────────│
```

> [!NOTE]
> To use the HttpOnly cookie pattern, your **backend-for-frontend (BFF)** or server-side route must handle the `Set-Cookie` response header. If you're calling `core-auth` directly from the browser (SPA without a BFF), use the bearer token approach described in [Section 2.3](#23-cookie-vs-bearer-deciding-the-right-approach).

### 2.2 Why Not `localStorage`?

`localStorage` is accessible to **any JavaScript running on your page** — including third-party scripts, browser extensions injected into your page, and any code from an XSS vulnerability. A stolen refresh token can be used to generate new access tokens indefinitely until the session is revoked.

```
// ❌ Never do this
localStorage.setItem('refresh_token', tokens.refresh_token);

// ✅ Keep the access token in memory
let accessToken = tokens.access_token;

// ✅ Let your server set the refresh token as an HttpOnly cookie
// (handled server-side via Set-Cookie header)
```

`sessionStorage` is marginally better (cleared on tab close) but is still script-accessible and fails across tabs.

### 2.3 Cookie vs. Bearer: Deciding the Right Approach

| Scenario | Recommended approach |
|---|---|
| SPA + same-origin BFF (Next.js, Nuxt, SvelteKit) | HttpOnly cookie for refresh token; in-memory access token |
| SPA calling `core-auth` directly (CORS) | In-memory access token; refresh token in `sessionStorage` as a fallback (accept the trade-off) OR use `SameSite=None; Secure` cookies if CORS is configured |
| Native mobile app | Secure OS keychain/keystore for refresh token; memory for access token |
| Server-to-server | Bearer token in `Authorization` header; store credentials in secrets manager |

> [!IMPORTANT]
> If you must store the refresh token in `sessionStorage` or `localStorage` (e.g., simple SPA with no BFF), ensure your CSP is strict, all third-party scripts are audited, and you understand the XSS risk. This is the less-secure option.

---

## 3. CSRF Protection

### 3.1 What the Risk Is

Cross-Site Request Forgery (CSRF) is only a concern when you use **cookies** for authentication. If a malicious site can trick the browser into sending a state-changing request (e.g., POST to `/v1/auth/logout`), and the cookie is attached automatically, damage is done.

If you're using only bearer tokens in `Authorization` headers, **CSRF is not a concern** — other sites cannot set that header.

### 3.2 Double-Submit Cookie Pattern

When using cookies, protect state-changing requests with a CSRF token:

**Step 1 — Generate a CSRF token on login** (server-side / BFF):

```
// On your BFF server, after receiving tokens from core-auth:
const csrfToken = crypto.randomBytes(32).toString('hex');
res.cookie('csrf_token', csrfToken, {
  httpOnly: false,  // Must be readable by JS so it can be sent in the header
  secure: true,
  sameSite: 'Strict'
});
```

**Step 2 — Read and attach on every mutating request** (client-side):

```javascript
// Read the CSRF token from the non-HttpOnly cookie
function getCsrfToken() {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith('csrf_token='))
    ?.split('=')[1];
}

// Attach it as a header on every POST / PUT / DELETE
async function apiRequest(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': getCsrfToken(),
      'Authorization': `Bearer ${getAccessToken()}`,
      ...options.headers,
    },
    credentials: 'include', // send the HttpOnly cookie
  });
}
```

**Step 3 — Validate on the server** (BFF layer):

Your BFF validates that the `X-CSRF-Token` header matches the `csrf_token` cookie value before proxying the request to `core-auth`.

> [!TIP]
> If you're using `SameSite=Strict` cookies, CSRF protection is largely handled for you on modern browsers because cross-site requests won't include the cookie at all. The double-submit pattern is belt-and-suspenders defence for older browser compatibility.

---

## 4. Screen-by-Screen Implementation Guide

### 4.1 Registration Screen

**Fields:** Email (required), Password (required). Optionally: Username, Phone.

**API Call:**

```
POST /v1/auth/register
{
  "client_id": "your-app",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

**Password policy to enforce client-side (before submitting):**
- 8–128 characters
- At minimum: 1 uppercase letter, 1 lowercase letter, 1 digit

Enforce this in the UI with a live strength indicator — don't rely solely on server-side validation.

**Success response:**

```json
{
  "user": {
    "user_id": "...",
    "email": "alice@example.com",
    "email_verified": false,
    "mfa_enabled": false
  }
}
```

**What to do on success:**
1. **Do not** attempt to log the user in automatically — tokens are not returned on registration.
2. Show a **"Check your email"** banner: *"We've sent a 6-digit verification code to alice@example.com."*
3. Redirect to the [Email Verification Screen](#42-email-verification-screen).

**Error handling:**

| `error.code` | UX action |
|---|---|
| `USER_ALREADY_EXISTS` | "An account with this email already exists. [Sign in instead?]" |
| `PASSWORD_POLICY_VIOLATION` | Highlight the password field with the server's message |
| `INVALID_IDENTIFIER_FORMAT` | Highlight the invalid field (email format, phone format, etc.) |

### 4.2 Email Verification Screen

After registration, the user receives a 6-digit OTP at their email.

**API Call:**

```
POST /v1/auth/verify-email
{
  "email": "alice@example.com",
  "code": "123456"
}
```

**What to do on success:**
1. Show a "Email verified!" confirmation.
2. Redirect to the login screen with a pre-filled email and a success toast: *"Your email has been verified. Please log in."*

**Resend logic:**

```
POST /v1/auth/resend-verification
{
  "email": "alice@example.com"
}
```

Implement a **60-second cooldown** on the resend button client-side to reduce spam and rate limit hits. This is in addition to the server-side rate limiting.

> [!IMPORTANT]
> **Do not** silently log the user in after email verification — the service does not issue tokens at this step. Always route the user through the login flow.

### 4.3 Login Screen

**Fields:** Email (or Username / Phone), Password.

**API Call:**

```
POST /v1/auth/login
{
  "client_id": "your-app",
  "email": "alice@example.com",
  "password": "SecurePass123!"
}
```

**The response can be one of two shapes** — always check which key is present:

```javascript
const data = await res.json();

if (data.login_success) {
  // Standard login — store tokens and redirect
  handleLoginSuccess(data.login_success.tokens, data.login_success.user);
} else if (data.mfa_required) {
  // MFA enrolled — redirect to MFA challenge screen
  handleMFARequired(data.mfa_required.mfa_session_token, data.mfa_required.mfa_type);
}
```

**Storing the access token (in-memory):**

```javascript
// auth.js — singleton module
let _accessToken = null;
let _accessTokenExpiry = null;

export function setTokens({ access_token, refresh_token, expires_in }) {
  _accessToken = access_token;
  _accessTokenExpiry = Date.now() + expires_in * 1000;
  // refresh_token is handled server-side (HttpOnly cookie)
  // or stored in sessionStorage as a fallback
}

export function getAccessToken() {
  return _accessToken;
}

export function isAccessTokenExpired() {
  return !_accessToken || Date.now() >= _accessTokenExpiry;
}

export function clearTokens() {
  _accessToken = null;
  _accessTokenExpiry = null;
}
```

**Error handling:**

| `error.code` | UX action |
|---|---|
| `INVALID_CREDENTIALS` | "Incorrect email or password." (do not distinguish between the two) |
| `ACCOUNT_NOT_VERIFIED` | "Please verify your email first. [Resend verification →]" |
| `ACCOUNT_LOCKED` | "Too many failed attempts. Please try again in 15 minutes." |
| `ACCOUNT_SUSPENDED` | "Your account has been suspended. Please contact support." |
| `TOO_MANY_REQUESTS` | Show a lockout timer countdown; disable the submit button |
| `IP_NOT_ALLOWED` | "Access is restricted from your current location." |

> [!CAUTION]
> Never reveal whether the lockout is triggered by IP or account to the user — this prevents attackers from fingerprinting the rate limiting strategy.

### 4.4 MFA Challenge Screen

This screen appears when `login` returns `mfa_required`. You must hold the `mfa_session_token` **in memory only** — never persist it.

```javascript
// Store temporarily in memory navigation state
// e.g., React Router state, Vuex, or module-level variable
let pendingMFASession = {
  token: data.mfa_required.mfa_session_token,
  type: data.mfa_required.mfa_type, // "totp"
};
```

**Screen design:**
- A single 6-digit code input (auto-focus, numeric keyboard on mobile)
- A cancel/back link that clears `pendingMFASession` and redirects to login
- No "remember this device" option unless you implement it separately

**API Call:**

```
POST /v1/mfa/challenge
{
  "mfa_session_token": "<token from login response>",
  "code": "123456"
}
```

**Success response:**

```json
{
  "user": { ... },
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": 900
  }
}
```

**What to do on success:**
1. Clear `pendingMFASession` from memory.
2. Call `setTokens(data.tokens)`.
3. Redirect to the authenticated home/dashboard.

**Critical error handling:**

| `error.code` | UX action |
|---|---|
| `MFA_INVALID_CODE` | **"Incorrect code. Please restart the sign-in process."** — Clear `pendingMFASession` and redirect back to the login screen. The MFA session is consumed, even on failure. |
| `INVALID_MFA_SESSION` | Same as above — the session has expired or been consumed. |

```javascript
async function submitMFAChallenge(code) {
  const res = await fetch('/v1/mfa/challenge', {
    method: 'POST',
    body: JSON.stringify({
      mfa_session_token: pendingMFASession.token,
      code,
    }),
  });

  if (!res.ok) {
    const err = await res.json();
    const code = err.error?.code;

    if (code === 'MFA_INVALID_CODE' || code === 'INVALID_MFA_SESSION') {
      pendingMFASession = null;
      // Redirect to login with error message
      router.push('/login?error=mfa_failed');
      return;
    }
  }

  const data = await res.json();
  setTokens(data.tokens);
  router.push('/dashboard');
}
```

> [!WARNING]
> Unlike most form submissions, the MFA session token is **single-use regardless of outcome**. A wrong code invalidates the session. Always redirect to the login screen on any error from `/v1/mfa/challenge`.

### 4.5 Authenticated Pages & Route Guards

Protect your routes by checking for a valid access token. If the access token is expired but the refresh token exists, attempt a silent refresh before redirecting to login.

```javascript
// route-guard.js
async function requireAuth(next) {
  if (!isAccessTokenExpired()) {
    return next(); // token is still valid
  }

  // Try silent refresh
  const refreshed = await silentRefresh();
  if (refreshed) {
    return next();
  }

  // Refresh failed — redirect to login
  return next('/login?reason=session_expired');
}
```

**On page load / app init**, always check if the access token needs refresh:

```javascript
// app-init.js
async function initAuth() {
  // Access token is gone (page refresh) — try to renew from refresh token
  if (isAccessTokenExpired()) {
    await silentRefresh(); // see Section 5
  }
}
```

### 4.6 Forgot Password Screen

**Field:** Email address.

**API Call:**

```
POST /v1/auth/forgot-password
{
  "email": "alice@example.com"
}
```

**Always returns `200 OK`** — even if no account exists for that email. This is intentional.

**UX pattern:** After submission, always show the same message regardless of whether an account was found:

> *"If an account exists for that email, you'll receive a reset link shortly. Check your spam folder if you don't see it within a few minutes."*

This prevents **email enumeration** — attackers probing whether an email is registered.

**Do not:**
- Change the message based on whether the account was found
- Allow the user to retry immediately — implement a cooldown

### 4.7 Reset Password Screen

The user lands here via a link in the reset email. The URL will contain the reset token:

```
https://your-app.com/reset-password?token=<reset_token>
```

**Extract the token from the URL and hold it in memory:**

```javascript
const token = new URLSearchParams(window.location.search).get('token');
if (!token) {
  // Redirect to forgot-password with an error
  router.push('/forgot-password?error=invalid_link');
}
```

**Fields:** New password, Confirm new password.

**API Call:**

```
POST /v1/auth/reset-password
{
  "token": "<token from URL>",
  "new_password": "NewSecurePass456!"
}
```

**What to do on success:**

1. Show a confirmation: *"Your password has been reset. All active sessions have been signed out."*
2. Clear any stored tokens from memory (in-memory access token, sessionStorage refresh token).
3. Redirect to the login screen.

> [!IMPORTANT]
> A successful password reset **revokes all existing sessions** across all devices. This is intentional — if the password was compromised, attacker sessions are also terminated. Make this clear in the UI.

**Error handling:**

| `error.code` | UX action |
|---|---|
| `TOKEN_NOT_FOUND` | "This reset link is invalid or has already been used. [Request a new one →]" |
| `TOKEN_EXPIRED` | "This reset link has expired. [Request a new one →]" |
| `TOKEN_ALREADY_USED` | "This reset link has already been used. [Request a new one →]" |
| `PASSWORD_POLICY_VIOLATION` | Highlight the password field with the server's error message |

### 4.8 Logout

**API Call:**

```
POST /v1/auth/logout
Authorization: Bearer <access_token>

{
  "refresh_token": "<refresh_token>"
}
```

> [!NOTE]
> If you're using HttpOnly cookies, the refresh token is sent automatically as a cookie. Your BFF should extract it from the cookie and forward it in the JSON body (or the server-side proxied request).

**What to do on success — and also on failure:**

```javascript
async function logout() {
  try {
    await apiRequest('/v1/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: getRefreshToken() }),
    });
  } catch (e) {
    // Best-effort logout — even if the request fails, clear client-side state
    console.warn('Logout request failed, clearing local state anyway', e);
  } finally {
    clearTokens();
    clearRefreshTokenCookie(); // if using cookies
    router.push('/login');
  }
}
```

Always clear client-side tokens in the `finally` block. A network error should never leave the user in a stuck authenticated state.

---

## 5. Token Refresh: Silent Renewal

### 5.1 Timer-Based Refresh

Start a refresh timer when you first receive the token pair. Refresh 60 seconds before expiry to give the request time to complete.

```javascript
let refreshTimer = null;

function scheduleRefresh(expiresIn) {
  clearTimeout(refreshTimer);
  const refreshIn = (expiresIn - 60) * 1000; // refresh 60s before expiry
  refreshTimer = setTimeout(silentRefresh, Math.max(refreshIn, 0));
}

async function silentRefresh() {
  const refreshToken = getRefreshToken(); // from cookie or sessionStorage
  if (!refreshToken) {
    clearTokens();
    return false;
  }

  try {
    const res = await fetch('/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // sends the HttpOnly cookie if applicable
      body: JSON.stringify({
        client_id: 'your-app',
        refresh_token: refreshToken,
      }),
    });

    if (!res.ok) {
      // Refresh failed — session expired or compromised
      clearTokens();
      router.push('/login?reason=session_expired');
      return false;
    }

    const tokens = await res.json();
    setTokens(tokens); // updates in-memory access token + stores new refresh token
    scheduleRefresh(tokens.expires_in);
    return true;
  } catch (e) {
    // Network error — don't log out, will retry on next request
    return false;
  }
}
```

### 5.2 Interceptor-Based Refresh (Recommended)

A **request interceptor** is more robust than a timer alone — it handles edge cases like the browser tab being put to sleep, or the timer firing while offline.

```javascript
// api.js — wraps fetch with automatic token refresh on 401
async function apiFetch(url, options = {}) {
  // Proactively refresh if the access token is expired
  if (isAccessTokenExpired()) {
    const refreshed = await silentRefresh();
    if (!refreshed) {
      return Promise.reject(new Error('Session expired'));
    }
  }

  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${getAccessToken()}`,
      ...options.headers,
    },
    credentials: 'include',
  });

  // Handle 401 — token may have been invalidated server-side (blacklisted JTI)
  if (res.status === 401) {
    const refreshed = await silentRefresh();
    if (!refreshed) {
      return Promise.reject(new Error('Session expired'));
    }
    // Retry the original request once
    return fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getAccessToken()}`,
        ...options.headers,
      },
      credentials: 'include',
    });
  }

  return res;
}
```

> [!CAUTION]
> **Prevent refresh storms.** If multiple requests fail simultaneously (e.g., on page load), they will all try to refresh at once. Use a promise-based mutex to ensure only one refresh runs at a time, and queue subsequent callers to wait for it:
>
> ```javascript
> let refreshPromise = null;
>
> async function silentRefresh() {
>   if (refreshPromise) return refreshPromise; // reuse in-flight refresh
>   refreshPromise = doRefresh().finally(() => {
>     refreshPromise = null;
>   });
>   return refreshPromise;
> }
> ```

### 5.3 Tab Coordination

When the user has multiple browser tabs open, each tab will schedule its own refresh timer. This leads to multiple concurrent refresh requests — each consuming the rotating refresh token before the others can use it.

**Solution — use the `BroadcastChannel` API:**

```javascript
const authChannel = new BroadcastChannel('auth');

// After a successful refresh, broadcast the new access token to all tabs
authChannel.postMessage({
  type: 'TOKEN_REFRESHED',
  accessToken: newAccessToken,
  expiresIn: tokens.expires_in,
});

// In every tab, listen and update local in-memory token
authChannel.addEventListener('message', (event) => {
  if (event.data.type === 'TOKEN_REFRESHED') {
    _accessToken = event.data.accessToken;
    _accessTokenExpiry = Date.now() + event.data.expiresIn * 1000;
    scheduleRefresh(event.data.expiresIn);
  }
  if (event.data.type === 'LOGGED_OUT') {
    clearTokens();
    router.push('/login');
  }
});
```

With this pattern, only the fastest tab wins the refresh race, and all other tabs receive the updated access token without triggering additional refreshes.

---

## 6. Handling API Errors

All errors from `core-auth` follow this shape:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "invalid credentials"
  }
}
```

`error.code` is a stable, machine-readable string (the `ErrorReason` enum value). `error.message` is a human-readable description that **may change** — do not use it to drive UI logic.

**Always key your error handling on `error.code`:**

```javascript
async function parseError(res) {
  const body = await res.json();
  const code = body?.error?.code ?? 'UNKNOWN';
  const message = body?.error?.message ?? 'An unexpected error occurred';
  return { code, message, statusCode: res.status };
}

// Usage
const res = await fetch('/v1/auth/login', { method: 'POST', ... });
if (!res.ok) {
  const { code } = await parseError(res);
  switch (code) {
    case 'INVALID_CREDENTIALS':
      setError('Incorrect email or password.');
      break;
    case 'ACCOUNT_LOCKED':
      setError('Account temporarily locked. Try again later.');
      break;
    // ...
  }
}
```

### HTTP status → `error.code` mapping

| HTTP Status | Common `error.code` values |
|---|---|
| `400` | `INVALID_IDENTIFIER`, `INVALID_IDENTIFIER_FORMAT`, `PASSWORD_POLICY_VIOLATION` |
| `401` | `INVALID_CREDENTIALS`, `INVALID_TOKEN`, `TOKEN_EXPIRED`, `TOKEN_ALREADY_USED`, `MFA_INVALID_CODE`, `INVALID_MFA_SESSION` |
| `403` | `ACCOUNT_SUSPENDED`, `ACCOUNT_LOCKED`, `IP_NOT_ALLOWED`, `SESSION_NOT_OWNED` |
| `404` | `USER_NOT_FOUND`, `SESSION_NOT_FOUND`, `TOKEN_NOT_FOUND` |
| `409` | `USER_ALREADY_EXISTS`, `MFA_ALREADY_ENROLLED` |
| `412` | `ACCOUNT_NOT_VERIFIED`, `MFA_NOT_ENROLLED`, `MFA_REQUIRED` |
| `429` | `TOO_MANY_REQUESTS` |
| `500` | `INTERNAL_ERROR` |

### Global 401 handler

Any `401` response on a protected endpoint means the access token is invalid or blacklisted (e.g., after logout on another device). Handle it globally:

```javascript
// In your interceptor:
if (res.status === 401 && !isRefreshRequest(url)) {
  const refreshed = await silentRefresh();
  if (!refreshed) {
    // Session is truly gone — route to login
    broadcast({ type: 'LOGGED_OUT' });
    router.push('/login?reason=session_expired');
  }
}
```

---

## 7. MFA Enrollment Flow

This flow is for authenticated users enabling MFA on their account (typically in account settings).

### Step 1 — Request TOTP Setup

```
POST /v1/mfa/setup/totp
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_uri": "otpauth://totp/core-auth:alice@example.com?secret=..."
}
```

**Screen:** Show a QR code rendered from `qr_uri` (use a library like `qrcode`) alongside the manual entry `secret` for users who can't scan. 

```javascript
// Example using qrcode npm package
import QRCode from 'qrcode';
const qrDataUrl = await QRCode.toDataURL(data.qr_uri);
```

### Step 2 — Confirm Enrollment

After the user scans the QR code in their authenticator app and enters the first 6-digit code:

```
POST /v1/mfa/setup/totp/confirm
Authorization: Bearer <access_token>

{
  "totp_code": "123456"
}
```

**On success:** Update the user's profile state to reflect `mfa_enabled: true`. Show recovery code instructions if your app supports them.

**Error handling:**

| `reason` | UX action |
|---|---|
| `MFA_INVALID_CODE` | "Incorrect code. Make sure your device clock is accurate and try again." |
| `MFA_ALREADY_ENROLLED` | "MFA is already enabled on your account." |

### Step 3 — Disabling MFA

MFA disable requires **password re-confirmation**:

```
DELETE /v1/mfa
Authorization: Bearer <access_token>

{
  "password": "current-password"
}
```

Always present a confirmation dialog before this action. Update your local user state to `mfa_enabled: false` on success.

---

## 8. OAuth / Social Login

When OAuth (e.g., Google) is configured, the login flow is redirect-based.

### Initiate OAuth

```
GET /v1/auth/oauth/google?client_id=your-app&redirect_uri=https://your-app.com/oauth/callback
```

Redirect the user to this URL. Do not open it in an iframe — it must be a full navigation.

### Handle the Callback

After the OAuth provider redirects back, `core-auth` processes the authorization code and redirects to your `redirect_uri` with tokens:

```
https://your-app.com/oauth/callback?access_token=...&refresh_token=...&expires_in=900
```

> [!IMPORTANT]
> Extract tokens from the URL query parameters **immediately** and clear them from the URL using `history.replaceState` or equivalent — tokens in the URL bar are visible in browser history, server logs, and referrer headers.

```javascript
// oauth-callback.js
const params = new URLSearchParams(window.location.search);
const tokens = {
  access_token: params.get('access_token'),
  refresh_token: params.get('refresh_token'),
  expires_in: parseInt(params.get('expires_in'), 10),
};

// Clear tokens from URL immediately
window.history.replaceState({}, document.title, window.location.pathname);

setTokens(tokens);
scheduleRefresh(tokens.expires_in);
router.push('/dashboard');
```

---

## 9. Security Checklist

Use this checklist before deploying your integration to production:

### Token Storage
- [ ] Access token is **only stored in memory** (never `localStorage`, never a persistent cookie)
- [ ] Refresh token is in an **`HttpOnly`, `Secure`, `SameSite=Strict`** cookie (or OS keychain for native)
- [ ] No tokens appear in the URL bar (OAuth callback tokens cleared immediately)
- [ ] No tokens are logged to the browser console

### Network & Transport
- [ ] All API traffic goes over **HTTPS** in production
- [ ] `SECURE_COOKIE=true` is set on the `core-auth` server in production
- [ ] CORS is restricted to your known origins only

### CSRF
- [ ] If using cookies, you've implemented the **double-submit pattern** (or rely on `SameSite=Strict`)
- [ ] Mutating requests (POST, PUT, DELETE) include the CSRF header

### Error Handling
- [ ] Error UX uses the `reason` enum, not the `message` string
- [ ] `INVALID_CREDENTIALS` does not distinguish "wrong password" from "user not found"
- [ ] `ACCOUNT_LOCKED` shows a lockout timer, not a retry button
- [ ] Forgot password always shows the same success message regardless of email existence

### Session Lifecycle
- [ ] Token refresh uses a **single-flight mutex** (no parallel refresh storms)
- [ ] Multiple tabs coordinate via `BroadcastChannel` (or a service worker)
- [ ] Logout clears tokens even if the API call fails
- [ ] `SESSION_NOT_FOUND` (refresh failure) routes to the login screen immediately

### MFA
- [ ] `mfa_session_token` is held **in memory only**
- [ ] Any error from `/v1/mfa/challenge` redirects to login (session is consumed)
- [ ] MFA disable requires password confirmation

### Content Security Policy
- [ ] CSP disallows inline scripts (`script-src 'self'`)
- [ ] CSP restricts `connect-src` to your known API origins

---

## 10. Quick Reference

### Endpoints

| Action | Method | Path |
|---|---|---|
| Register | `POST` | `/v1/auth/register` |
| Login | `POST` | `/v1/auth/login` |
| MFA Challenge | `POST` | `/v1/mfa/challenge` |
| Refresh Token | `POST` | `/v1/auth/refresh` |
| Logout | `POST` | `/v1/auth/logout` |
| Forgot Password | `POST` | `/v1/auth/forgot-password` |
| Reset Password | `POST` | `/v1/auth/reset-password` |
| Verify Email | `POST` | `/v1/auth/verify-email` |
| Resend Verification | `POST` | `/v1/auth/resend-verification` |
| MFA Setup (TOTP) | `POST` | `/v1/mfa/setup/totp` |
| MFA Confirm | `POST` | `/v1/mfa/setup/totp/confirm` |
| MFA Disable | `DELETE` | `/v1/mfa` |
| OAuth Google | `GET` | `/v1/auth/oauth/google` |

### Token Lifecycle Cheat Sheet

```
Login ──────────────────────────────────────────────────────────────────────────►
  │                                                                               │
  │ Response contains:                                                            │
  │   access_token  (JWT, 15 min)  ──store in memory──────────────────────────►  │
  │   refresh_token (opaque, 30d)  ──store in HttpOnly cookie──────────────────► │
  │                                                                               │
  │ Every API request:                                                            │
  │   Authorization: Bearer <access_token>                                        │
  │                                                                               │
  │ At 14 min (or on 401):                                                        │
  │   POST /v1/auth/refresh → NEW access_token + NEW refresh_token                │
  │   Replace BOTH tokens. Old refresh_token is now dead.                         │
  │                                                                               │
Logout ─────────────────────────────────────────────────────────────────────────►
  │                                                                               │
  │   POST /v1/auth/logout  (session revoked, JTI blacklisted)                   │
  │   Clear access_token from memory                                              │
  │   Clear refresh_token cookie (or sessionStorage)                              │
```

### Related Guides

| Guide | What it covers |
|---|---|
| [`docs/guides/authentication-flow.md`](./authentication-flow.md) | End-to-end flow with sequence diagrams — read this first |
| [`docs/guides/mfa.md`](./mfa.md) | TOTP enrollment, recovery codes, MFA disable from a client perspective |
| [`docs/guides/session-management.md`](./session-management.md) | Multi-device sessions, listing and revoking sessions |
| [`docs/error-catalog.md`](../error-catalog.md) | Every error `reason` code with gRPC status + HTTP equivalent |
| [`docs/security/token-model.md`](../security/token-model.md) | JWT claims, signing algorithm, rotation policy, lifetime rationale |
| [`docs/guides/grpc-integration.md`](./grpc-integration.md) | Connecting as a gRPC client instead of HTTP |

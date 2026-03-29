package errors

import (
	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/minato/merr"
)

var (
	// ── Shared ──────────────────────────────────────────────────────────────────
	ErrInternal = merr.Internal("INTERNAL_ERROR", "internal error")

	// ── Identity & Account ──────────────────────────────────────────────────────
	ErrUserNotFound       = merr.NotFound(authv1.ErrorReason_USER_NOT_FOUND.String(), "no user matches the given identifier")
	ErrUserAlreadyExists  = merr.Conflict(authv1.ErrorReason_USER_ALREADY_EXISTS.String(), "user already exists")
	ErrAccountNotVerified = merr.PreconditionFailed(authv1.ErrorReason_ACCOUNT_NOT_VERIFIED.String(), "account is not verified")
	ErrAccountSuspended   = merr.Forbidden(authv1.ErrorReason_ACCOUNT_SUSPENDED.String(), "account is suspended")
	ErrAccountDeleted     = merr.Forbidden(authv1.ErrorReason_ACCOUNT_DELETED.String(), "account has been deleted")
	ErrAccountLocked      = merr.Forbidden(authv1.ErrorReason_ACCOUNT_LOCKED.String(), "account is temporarily locked")

	// ── Credentials & Tokens ────────────────────────────────────────────────────
	ErrInvalidCredentials = merr.Unauthorized(authv1.ErrorReason_INVALID_CREDENTIALS.String(), "invalid credentials")
	ErrInvalidToken       = merr.Unauthorized(authv1.ErrorReason_INVALID_TOKEN.String(), "invalid token")
	ErrTokenExpired       = merr.Unauthorized(authv1.ErrorReason_TOKEN_EXPIRED.String(), "token has expired")
	ErrTokenAlreadyUsed   = merr.Unauthorized(authv1.ErrorReason_TOKEN_ALREADY_USED.String(), "token has already been used")
	ErrTokenReuseDetected = merr.Unauthorized(authv1.ErrorReason_TOKEN_REUSE_DETECTED.String(), "refresh token reuse detected; all sessions revoked")
	ErrTokenRevoked       = merr.Unauthorized(authv1.ErrorReason_TOKEN_REVOKED.String(), "token has been revoked")

	// ── Input Validation ────────────────────────────────────────────────────────
	ErrPasswordPolicyViolation = merr.BadRequest(authv1.ErrorReason_PASSWORD_POLICY_VIOLATION.String(), "password does not meet complexity requirements")
	ErrInvalidIdentifierFormat = merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "invalid identifier format")
	ErrInvalidIdentifier       = merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER.String(), "invalid identifier")

	// ── MFA ─────────────────────────────────────────────────────────────────────
	ErrMFAAlreadyEnrolled = merr.PreconditionFailed(authv1.ErrorReason_MFA_ALREADY_ENROLLED.String(), "MFA is already enrolled")
	ErrMFANotEnrolled     = merr.PreconditionFailed(authv1.ErrorReason_MFA_NOT_ENROLLED.String(), "MFA is not enrolled")
	ErrMFAInvalidCode     = merr.Unauthorized(authv1.ErrorReason_MFA_INVALID_CODE.String(), "the TOTP code is incorrect")
	ErrMFASessionExpired  = merr.Unauthorized(authv1.ErrorReason_MFA_SESSION_EXPIRED.String(), "MFA challenge session has expired")
	ErrInvalidMFASession  = merr.Unauthorized(authv1.ErrorReason_INVALID_MFA_SESSION.String(), "invalid MFA session")
	ErrMFARequired        = merr.PreconditionFailed(authv1.ErrorReason_MFA_REQUIRED.String(), "MFA is required")

	// ── Verification ────────────────────────────────────────────────────────────
	ErrInvalidOTP      = merr.Unauthorized(authv1.ErrorReason_INVALID_OTP.String(), "the OTP code is incorrect")
	ErrOTPExpired      = merr.Unauthorized(authv1.ErrorReason_OTP_EXPIRED.String(), "the OTP code has expired")
	ErrAlreadyVerified = merr.PreconditionFailed(authv1.ErrorReason_ALREADY_VERIFIED.String(), "already verified")
	ErrPhoneNotSet     = merr.PreconditionFailed(authv1.ErrorReason_PHONE_NOT_SET.String(), "phone number is not set")
	ErrTokenNotFound   = merr.NotFound(authv1.ErrorReason_TOKEN_NOT_FOUND.String(), "token not found")

	// ── Session ──────────────────────────────────────────────────────────────────
	ErrSessionNotFound = merr.NotFound(authv1.ErrorReason_SESSION_NOT_FOUND.String(), "session not found")
	ErrSessionNotOwned = merr.Forbidden(authv1.ErrorReason_SESSION_NOT_OWNED.String(), "session belongs to a different user")

	// ── OAuth2 ───────────────────────────────────────────────────────────────────
	ErrUnsupportedProvider        = merr.BadRequest(authv1.ErrorReason_UNSUPPORTED_PROVIDER.String(), "provider is not supported")
	ErrOAuthCodeInvalid           = merr.Unauthorized(authv1.ErrorReason_OAUTH_CODE_INVALID.String(), "invalid or expired OAuth code")
	ErrOAuthStateMismatch         = merr.BadRequest(authv1.ErrorReason_OAUTH_STATE_MISMATCH.String(), "OAuth state mismatch")
	ErrProviderAlreadyLinked      = merr.PreconditionFailed(authv1.ErrorReason_PROVIDER_ALREADY_LINKED.String(), "provider is already linked to an account")
	ErrProviderNotLinked          = merr.NotFound(authv1.ErrorReason_PROVIDER_NOT_LINKED.String(), "no linked provider found")
	ErrCannotUnlinkLastCredential = merr.PreconditionFailed(authv1.ErrorReason_CANNOT_UNLINK_LAST_CREDENTIAL.String(), "cannot unlink the last login credential")
	ErrLinkSessionExpired         = merr.Unauthorized(authv1.ErrorReason_LINK_SESSION_EXPIRED.String(), "link session is invalid or expired")
	ErrNoPassword                 = merr.PreconditionFailed(authv1.ErrorReason_NO_PASSWORD_SET.String(), "no password set")
	ErrAccountLinkRequired        = merr.PreconditionFailed(authv1.ErrorReason_ACCOUNT_LINK_REQUIRED.String(), "provider email matches an existing account; linking required")

	// ── Tenant ───────────────────────────────────────────────────────────────────
	ErrTenantNotFound = merr.NotFound(authv1.ErrorReason_TENANT_NOT_FOUND.String(), "tenant not found")

	// ── Network & Rate Limiting ──────────────────────────────────────────────────
	ErrTooManyRequests = merr.TooManyRequests(authv1.ErrorReason_TOO_MANY_REQUESTS.String(), "rate limit exceeded")
	ErrIPNotAllowed    = merr.Forbidden(authv1.ErrorReason_IP_NOT_ALLOWED.String(), "request IP is not allowed")
)

package ratelimit

import (
	"context"
	"time"
)

// LoginAttempt records a single login attempt event.
type LoginAttempt struct {
	UserID      string
	IPAddress   string
	AttemptedAt time.Time
	Success     bool
}

// LoginAttemptsRepository is the persistence contract for login attempt tracking.
// Implementations live in internal/ratelimit/repository/.
type LoginAttemptsRepository interface {
	// Record inserts a new login attempt row.
	Record(ctx context.Context, attempt *LoginAttempt) error

	// CountFailed returns the number of failed attempts for a given user
	// within the provided lookback window. Used to enforce account lockout.
	CountFailed(ctx context.Context, userID string, since time.Time) (int, error)

	// CountFailedByIP returns the number of failed attempts from a given IP
	// address within the lookback window. Used for IP-level rate limiting.
	CountFailedByIP(ctx context.Context, ip string, since time.Time) (int, error)

	// IsKnownIP returns true if the given IP has been associated with at least
	// one successful login by this user within the lookback window.
	// Used by suspicious login detection to determine whether to flag or challenge.
	IsKnownIP(ctx context.Context, userID string, ip string, since time.Time) (bool, error)
}

// RateLimiter is the primary use-case interface consumed by the auth domain.
// It is defined here (consumer-owned) to avoid import cycles.
type RateLimitUseCase interface {
	// CheckAndRecord inspects the current rate state, records the attempt,
	// and returns an error if the rate limit or lockout threshold is exceeded.
	//
	// Call this BEFORE validating credentials so that even invalid-identifier
	// requests consume a rate limit slot (prevents enumeration via timing).
	CheckIPLimit(ctx context.Context, ip string) error

	// RecordAttempt persists the outcome of a login attempt so that lockout
	// thresholds can be evaluated on the next call.
	RecordAttempt(ctx context.Context, attempt *LoginAttempt) error

	// CheckAccountLockout returns an error if the user account is locked due
	// to too many recent failed attempts.
	CheckAccountLockout(ctx context.Context, userID string) error

	// CheckSuspiciousLogin inspects whether the login IP is new for this user.
	// Returns a SuspiciousLoginResult describing what action the caller should take.
	// Always returns a zero-value result (both fields false) if detection is disabled,
	// the IP is empty, or a DB error occurs (fail-open).
	CheckSuspiciousLogin(ctx context.Context, userID string, ip string) (SuspiciousLoginResult, error)
}

// Config holds tunable thresholds for rate limiting and lockout.
// Values are read from the environment via config.go.
type Config struct {
	// MaxFailedAttemptsPerIP is the maximum number of failed login attempts
	// from a single IP before a 429 is returned.
	MaxFailedAttemptsPerIP int

	// IPWindowDuration is the sliding window over which IP attempts are counted.
	IPWindowDuration time.Duration

	// MaxFailedAttemptsPerAccount is the number of consecutive failures before
	// an account is locked.
	MaxFailedAttemptsPerAccount int

	// AccountLockoutDuration is the sliding window for the account lockout check.
	AccountLockoutDuration time.Duration

	// SuspiciousLoginConfig holds the knobs for the detection policy.
	SuspiciousLogin SuspiciousLoginConfig
}

// DefaultConfig returns safe, sensible production defaults.
func DefaultConfig() Config {
	return Config{
		MaxFailedAttemptsPerIP:      30,
		IPWindowDuration:            15 * time.Minute,
		MaxFailedAttemptsPerAccount: 10,
		AccountLockoutDuration:      15 * time.Minute,
	}
}

// SuspiciousLoginAction controls what happens when a login from a new IP is detected.
type SuspiciousLoginAction string

const (
	// SuspiciousLoginAuditOnly logs the event and lets the login proceed.
	SuspiciousLoginAuditOnly SuspiciousLoginAction = "audit_only"

	// SuspiciousLoginChallengeMFA requires the user to complete a TOTP challenge
	// before tokens are issued. Only applies when MFA is enrolled.
	SuspiciousLoginChallengeMFA SuspiciousLoginAction = "challenge_mfa"
)

// SuspiciousLoginResult carries the outcome of a CheckSuspiciousLogin call.
// Having a struct instead of a bare bool avoids a future breaking signature change
// if more signal fields are added (e.g., IsNewCountry, RiskScore).
type SuspiciousLoginResult struct {
	// Suspicious is true if the IP is not in the user's known login history.
	Suspicious bool

	// ForceMFA is true when Suspicious is true AND the configured action is
	// SuspiciousLoginChallengeMFA. The auth usecase should route to the MFA
	// challenge flow when this is set, regardless of whether MFA is enrolled.
	ForceMFA bool
}

// SuspiciousLoginConfig holds the knobs for the detection policy.
type SuspiciousLoginConfig struct {
	// Enabled controls whether suspicious login detection runs at all.
	Enabled bool

	// KnownIPWindow is how far back to look for prior successful logins from
	// this IP. A value of 90 days means "this IP is known if used in the last 3 months."
	KnownIPWindow time.Duration

	// Action determines what happens when a new IP is detected.
	Action SuspiciousLoginAction
}

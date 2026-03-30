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

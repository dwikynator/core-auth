package usecase

import (
	"context"
	"time"

	errs "github.com/dwikynator/core-auth/internal/libs/errors"
	"github.com/dwikynator/core-auth/internal/ratelimit"
)

type rateLimitUsecase struct {
	repo   ratelimit.LoginAttemptsRepository
	config ratelimit.Config
}

func NewRateLimiter(repo ratelimit.LoginAttemptsRepository, cfg ratelimit.Config) ratelimit.RateLimitUseCase {
	return &rateLimitUsecase{repo: repo, config: cfg}
}

// CheckIPLimit checks whether the calling IP has exceeded the request threshold.
// This should be called at the very start of the Login handler, before any
// credential lookup, to prevent timing-based user enumeration.
func (uc *rateLimitUsecase) CheckIPLimit(ctx context.Context, ip string) error {
	if ip == "" {
		return nil // No IP available (e.g., internal gRPC calls) — skip.
	}
	since := time.Now().Add(-uc.config.IPWindowDuration)
	count, err := uc.repo.CountFailedByIP(ctx, ip, since)
	if err != nil {
		// Fail open on DB error — we prefer availability over perfect rate limiting.
		return nil
	}
	if count >= uc.config.MaxFailedAttemptsPerIP {
		return errs.ErrTooManyRequests
	}
	return nil
}

// RecordAttempt persists a login attempt outcome.
func (uc *rateLimitUsecase) RecordAttempt(ctx context.Context, attempt *ratelimit.LoginAttempt) error {
	if attempt.AttemptedAt.IsZero() {
		attempt.AttemptedAt = time.Now()
	}
	// Fail silently: recording an attempt should never block the auth flow.
	_ = uc.repo.Record(ctx, attempt)
	return nil
}

// CheckAccountLockout checks whether a specific user has been locked out due
// to too many recent failed login attempts.
func (uc *rateLimitUsecase) CheckAccountLockout(ctx context.Context, userID string) error {
	since := time.Now().Add(-uc.config.AccountLockoutDuration)
	count, err := uc.repo.CountFailed(ctx, userID, since)
	if err != nil {
		return nil // Fail open on DB error.
	}
	if count >= uc.config.MaxFailedAttemptsPerAccount {
		return errs.ErrAccountLocked
	}
	return nil
}

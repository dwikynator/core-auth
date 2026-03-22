package verification

import "github.com/dwikynator/minato/merr"

// Sentinel errors for the verification domain.
var (
	ErrTokenNotFound    = merr.NotFound("TOKEN_NOT_FOUND", "verification token not found")
	ErrTokenExpired     = merr.Unauthorized("OTP_EXPIRED", "verification token has expired")
	ErrTokenAlreadyUsed = merr.Unauthorized("TOKEN_ALREADY_USED", "verification token has already been used")
)

package verification

import (
	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/minato/merr"
)

var (
	ErrTokenNotFound    = merr.NotFound(authv1.ErrorReason_INVALID_OTP.String(), "verification token not found")
	ErrTokenExpired     = merr.Unauthorized(authv1.ErrorReason_OTP_EXPIRED.String(), "verification token has expired")
	ErrTokenAlreadyUsed = merr.Unauthorized(authv1.ErrorReason_TOKEN_ALREADY_USED.String(), "verification token has already been used")
)

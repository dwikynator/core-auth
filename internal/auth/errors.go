package auth

import (
	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
	"github.com/dwikynator/minato/merr"
)

// Sentinel errors for the auth domain. Each maps to a specific gRPC status
// code and a machine-readable reason string that clients switch on.
//
// Reason strings match the ErrorReason enum in proto/auth/v1/errors.proto.
var (
	ErrUserNotFound       = merr.NotFound(authv1.ErrorReason_USER_NOT_FOUND.String(), "no user matches the given identifier")
	ErrUserAlreadyExists  = merr.Conflict(authv1.ErrorReason_USER_ALREADY_EXISTS.String(), "email, username, or phone is already registered")
	ErrInvalidCredentials = merr.Unauthorized(authv1.ErrorReason_INVALID_CREDENTIALS.String(), "wrong password or identifier")
	ErrInvalidIdentifier  = merr.BadRequest(authv1.ErrorReason_INVALID_IDENTIFIER_FORMAT.String(), "must provide at least one valid identifier (email, username, or phone)")
	ErrAccountNotVerified = merr.PreconditionFailed(authv1.ErrorReason_ACCOUNT_NOT_VERIFIED.String(), "account must be verified before logging in")
	ErrAlreadyVerified    = merr.PreconditionFailed(authv1.ErrorReason_ALREADY_VERIFIED.String(), "email is already verified")
	ErrTokenRevoked       = merr.Unauthorized(authv1.ErrorReason_INVALID_TOKEN.String(), "token has been revoked")
)

const errReasonInternal = "INTERNAL_ERROR"

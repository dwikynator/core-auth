package auth

import "github.com/dwikynator/minato/merr"

// Sentinel errors for the auth domain. Each maps to a specific gRPC status
// code and a machine-readable reason string that clients switch on.
//
// Reason strings match the ErrorReason enum in proto/auth/v1/errors.proto.
var (
	ErrUserNotFound       = merr.NotFound("USER_NOT_FOUND", "no user matches the given identifier")
	ErrUserAlreadyExists  = merr.Conflict("USER_ALREADY_EXISTS", "email, username, or phone is already registered")
	ErrInvalidCredentials = merr.Unauthorized("INVALID_CREDENTIALS", "wrong password or identifier")
	ErrInvalidIdentifier  = merr.BadRequest("INVALID_IDENTIFIER_FORMAT", "must provide at least one valid identifier (email, username, or phone)")
)

package auth

import (
	authv1 "github.com/dwikynator/core-auth/gen/auth/v1"
)

// PublicMethods returns the set of gRPC full-method names that do NOT require
// authentication. By using the auto-generated _FullMethodName constants,
// we guarantee 100% compile-time safety. If a method is renamed or removed in
// the proto file, the Go compiler will immediately flag the mismatch.
//
// Returned as a []string to match middleware.WithAuthSkipPaths variadic API.
// The middleware converts this to an O(1) map internally.
func PublicMethods() []string {
	return []string{
		authv1.AuthService_Register_FullMethodName,
		authv1.AuthService_Login_FullMethodName,
		authv1.AuthService_RefreshToken_FullMethodName,
		authv1.AuthService_SendOTP_FullMethodName,
		authv1.AuthService_VerifyOTP_FullMethodName,
		authv1.AuthService_SendMagicLink_FullMethodName,
		authv1.AuthService_VerifyMagicLink_FullMethodName,
		authv1.AuthService_ForgotPassword_FullMethodName,
		authv1.AuthService_ResetPassword_FullMethodName,
		authv1.AuthService_ChallengeMFA_FullMethodName,
		authv1.AuthService_GetOAuthURL_FullMethodName,
		authv1.AuthService_OAuthCallback_FullMethodName,
	}
}

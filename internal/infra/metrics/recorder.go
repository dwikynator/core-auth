package metrics

// RecordTokenIssued increments the tokens_issued_total counter.
// Call this immediately after a successful CreateSessionAndTokens invocation.
//
// grant_type values (by convention):
//   - "password"   — credential-based login (POST /v1/auth/login)
//   - "refresh"    — token rotation (POST /v1/auth/refresh)
//   - "mfa"        — post-MFA challenge token issuance
//   - "oauth"      — social provider login/registration
//   - "magic_link" — passwordless email login
func RecordTokenIssued(grantType string) {
	TokensIssuedTotal.WithLabelValues(grantType).Inc()
}

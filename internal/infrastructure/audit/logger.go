package audit

import (
	"context"
	"log/slog"
	"time"
)

// EventType categorizes security-critical actions.
type EventType string

const (
	EventRegister          EventType = "user.registered"
	EventLogin             EventType = "user.login"
	EventLoginFailed       EventType = "user.login_failed"
	EventLogout            EventType = "user.logout"
	EventOTPSent           EventType = "verification.otp_sent"
	EventOTPVerified       EventType = "verification.otp_verified"
	EventMagicLinkSent     EventType = "verification.magic_link_sent"
	EventMagicLinkUsed     EventType = "verification.magic_link_used"
	EventForgotPassword    EventType = "recovery.forgot_password"
	EventPasswordReset     EventType = "recovery.password_reset"
	EventPasswordChange    EventType = "recovery.password_changed"
	EventMFASetup          EventType = "mfa.setup"
	EventMFAConfirmed      EventType = "mfa.confirmed"
	EventMFAChallenged     EventType = "mfa.challenged"
	EventMFADisabled       EventType = "mfa.disabled"
	EventSessionRevoked    EventType = "session.revoked"
	EventAccountSuspend    EventType = "admin.account_suspended"
	EventAccountUnsuspend  EventType = "admin.account_unsuspended"
	EventAccountDeleted    EventType = "admin.account_deleted"
	EventOAuthLogin        EventType = "oauth.login"         // returning user logged in via social provider
	EventOAuthRegister     EventType = "oauth.register"      // new user created via social provider
	EventOAuthLinkRequired EventType = "oauth.link_required" // email conflict — existing account must be linked
	EventOAuthLink         EventType = "oauth.linked"        // social provider successfully linked to an existing account
	EventOAuthUnlink       EventType = "oauth.unlinked"      // social provider unlinked from an account
)

// Event represents a single audit log entry.
type Event struct {
	Type      EventType
	UserID    string
	IP        string
	UserAgent string
	Metadata  map[string]string // optional key-value pairs (e.g., "email", "reason")
	Timestamp time.Time
}

// Logger writes structured audit events. It is backend-agnostic:
// the current implementation uses slog, but future phases can swap in
// a database writer, message queue, or external SIEM without changing callers.
type Logger struct {
	logger *slog.Logger
}

// NewLogger creates an audit logger.
func NewLogger(logger *slog.Logger) *Logger {
	return &Logger{logger: logger}
}

// Log records an audit event as a structured slog entry.
//
// Output format (JSON mode):
//
//	{"time":"...","level":"INFO","msg":"audit","event":"user.login","user_id":"abc","ip":"1.2.3.4",...}
//
// The "audit" message prefix makes it trivial to grep/filter audit events
// from the rest of the application logs:
//
//	cat logs.json | jq 'select(.msg == "audit")'
func (l *Logger) Log(ctx context.Context, event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	attrs := []slog.Attr{
		slog.String("event", string(event.Type)),
		slog.String("user_id", event.UserID),
		slog.String("ip", event.IP),
		slog.String("user_agent", event.UserAgent),
		slog.Time("event_time", event.Timestamp),
	}

	for k, v := range event.Metadata {
		attrs = append(attrs, slog.String(k, v))
	}

	// Use LogAttrs for zero-allocation structured logging.
	l.logger.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

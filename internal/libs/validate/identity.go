package validate

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ── Email ───────────────────────────────────────────────────────────────────

// emailRe is a lightweight RFC-5321-ish check. Full RFC compliance is
// intentionally skipped — it gains nothing for an auth service.
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// NormaliseEmail lowercases the entire address and validates format.
func NormaliseEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if !emailRe.MatchString(email) {
		return "", fmt.Errorf("invalid email format")
	}
	return email, nil
}

// ── Phone ───────────────────────────────────────────────────────────────────

// phoneRe validates E.164 format: + followed by 7–15 digits.
var phoneRe = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

// NormalisePhone strips spaces/dashes and validates E.164.
func NormalisePhone(raw string) (string, error) {
	phone := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(strings.TrimSpace(raw))
	if !phoneRe.MatchString(phone) {
		return "", fmt.Errorf("phone must be in E.164 format (e.g. +628123456789)")
	}
	return phone, nil
}

// ── Username ────────────────────────────────────────────────────────────────

// usernameRe allows alphanumerics, underscores, and dots. 3–64 chars.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.]{3,64}$`)

// ValidateUsername checks format constraints. The original casing is preserved
// for display; case-insensitive uniqueness is enforced by the DB index.
func ValidateUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if !usernameRe.MatchString(username) {
		return "", fmt.Errorf("username must be 3–64 characters (letters, digits, _ and . only)")
	}
	return username, nil
}

// ── Password Policy ─────────────────────────────────────────────────────────

const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
)

// ValidatePassword enforces the minimum password policy.
func ValidatePassword(raw string) error {
	length := utf8.RuneCountInString(raw)
	if length < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if length > MaxPasswordLength {
		return fmt.Errorf("password must be at most %d characters", MaxPasswordLength)
	}

	var hasUpper, hasLower, hasDigit bool
	for _, r := range raw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

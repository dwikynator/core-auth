package email

import "fmt"

// OTPEmail builds the email for account verification OTPs.
func OTPEmail(to, otp string, expiryMinutes int) *Message {
	return &Message{
		To:      to,
		Subject: "Your verification code",
		HTML: fmt.Sprintf(`
			<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
				<h2>Verify your email</h2>
				<p>Your verification code is:</p>
				<p style="font-size: 32px; font-weight: bold; letter-spacing: 6px; text-align: center; 
				   background: #f4f4f5; padding: 16px; border-radius: 8px;">%s</p>
				<p>This code expires in <strong>%d minutes</strong>.</p>
				<p style="color: #71717a; font-size: 13px;">If you didn't request this, ignore this email.</p>
			</div>
		`, otp, expiryMinutes),
	}
}

// MagicLinkEmail builds the email for passwordless login.
func MagicLinkEmail(to, link string, expiryMinutes int) *Message {
	return &Message{
		To:      to,
		Subject: "Your sign-in link",
		HTML: fmt.Sprintf(`
			<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
				<h2>Sign in to your account</h2>
				<p>Click the button below to sign in. This link expires in <strong>%d minutes</strong>.</p>
				<p style="text-align: center; margin: 24px 0;">
					<a href="%s" 
					   style="background: #2563eb; color: white; padding: 12px 24px; 
					          border-radius: 6px; text-decoration: none; font-weight: 600;">
						Sign In
					</a>
				</p>
				<p style="color: #71717a; font-size: 13px;">
					If the button doesn't work, copy and paste this URL into your browser:<br/>
					<a href="%s" style="color: #2563eb;">%s</a>
				</p>
				<p style="color: #71717a; font-size: 13px;">If you didn't request this, ignore this email.</p>
			</div>
		`, expiryMinutes, link, link, link),
	}
}

// PasswordResetEmail builds the email for password recovery.
func PasswordResetEmail(to, link string, expiryMinutes int) *Message {
	return &Message{
		To:      to,
		Subject: "Reset your password",
		HTML: fmt.Sprintf(`
			<div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
				<h2>Reset your password</h2>
				<p>We received a request to reset your password. Click the button below to choose a new one.
				   This link expires in <strong>%d minutes</strong>.</p>
				<p style="text-align: center; margin: 24px 0;">
					<a href="%s" 
					   style="background: #2563eb; color: white; padding: 12px 24px; 
					          border-radius: 6px; text-decoration: none; font-weight: 600;">
						Reset Password
					</a>
				</p>
				<p style="color: #71717a; font-size: 13px;">
					If the button doesn't work, copy and paste this URL:<br/>
					<a href="%s" style="color: #2563eb;">%s</a>
				</p>
				<p style="color: #71717a; font-size: 13px;">If you didn't request this, your account is safe — just ignore this email.</p>
			</div>
		`, expiryMinutes, link, link, link),
	}
}

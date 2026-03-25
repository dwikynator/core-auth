package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Sender defines the contract for sending emails.
// This interface allows easy stubbing in tests and swapping providers.
type Sender interface {
	Send(ctx context.Context, msg *Message) error
}

// Message represents an outbound email.
type Message struct {
	To      string // recipient email address
	Subject string
	HTML    string // HTML body
}

// ResendClient sends emails via the Resend REST API.
type ResendClient struct {
	apiKey     string
	fromAddr   string
	httpClient *http.Client
}

// NewResendClient creates a ResendClient.
//
// fromAddr is the verified sender address in Resend (e.g., "noreply@yourdomain.com").
// The HTTP client uses a 10-second timeout to prevent hanging on slow responses.
func NewResendClient(apiKey, fromAddr string) *ResendClient {
	return &ResendClient{
		apiKey:   apiKey,
		fromAddr: fromAddr,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// resendPayload matches the Resend API v1 request body.
type resendPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// Send delivers an email via POST https://api.resend.com/emails.
func (c *ResendClient) Send(ctx context.Context, msg *Message) error {
	payload := resendPayload{
		From:    c.fromAddr,
		To:      []string{msg.To},
		Subject: msg.Subject,
		HTML:    msg.HTML,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("resend: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("resend: create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("resend: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend: status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

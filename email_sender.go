package main

import (
	"context"
	"log"
)

// consoleEmailSender is a dev stand-in implementing notify.EmailSender.
// Real deployments must replace this with a real provider (SES,
// SendGrid, Resend, Postmark) — see the api README.
type consoleEmailSender struct{}

func (s *consoleEmailSender) SendVerification(ctx context.Context, to string, rawToken string) error {
	log.Printf("[EMAIL] Verification token for %s: %s", to, rawToken)
	return nil
}

package main

import (
	"context"
	"log"
	"net/url"
)

// consoleEmailSender is a dev stand-in implementing notify.EmailSender.
// Real deployments must replace this with a real provider (SES,
// SendGrid, Resend, Postmark) — see the api README.
type consoleEmailSender struct{}

func (s *consoleEmailSender) SendVerification(ctx context.Context, to string, rawToken string) error {
	log.Printf("[EMAIL] Verification token for %s: %s", to, rawToken)
	return nil
}

// consoleMagicLinkSender is the magic-link equivalent of
// consoleEmailSender. It implements cryden's notify.MagicLinkSender —
// deliberately a separate interface on cryden's side, so this is a new
// type here rather than a second method on consoleEmailSender (see
// cryden's notify/magic_link_sender.go for why the engine kept them
// apart: "click to log in" is a different message from "confirm your
// new email").
type consoleMagicLinkSender struct {
	// BaseURL is this api deployment's own public URL. cryden hands over
	// only the raw token — the engine has no concept of your routing, so
	// the clickable link is assembled here. Real deployments should point
	// this at their own frontend route that reads ?token= and POSTs it to
	// /v1/magic-link/complete; the path below is a dev-time guess, not a
	// contract this repo owns.
	BaseURL string
}

func (s *consoleMagicLinkSender) SendMagicLink(ctx context.Context, to string, rawToken string) error {
	if s.BaseURL == "" {
		log.Printf("[MAGIC LINK] Token for %s: %s (BASE_URL unset, no clickable link)", to, rawToken)
		return nil
	}
	log.Printf("[MAGIC LINK] For %s: %s/magic-link?token=%s", to, s.BaseURL, url.QueryEscape(rawToken))
	return nil
}

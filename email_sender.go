package main

import (
	"context"
	"log"
	"net/url"

	"github.com/crydensync/api/templates"
)

// consoleEmailSender is a dev stand-in implementing notify.EmailSender.
// Real deployments must replace this with a real provider (SES,
// SendGrid, Resend, Postmark) — see the api README.
//
// Templates is optional. Nil means no EMAIL_TEMPLATE_DIR was configured,
// and the built-in line below is printed exactly as it always was; a
// non-nil set renders the operator's own copy instead. The two share the
// "[EMAIL]" prefix either way, so tailing a log for one still finds the
// other.
type consoleEmailSender struct {
	Templates *templates.Set
}

func (s *consoleEmailSender) SendVerification(ctx context.Context, to string, rawToken string) error {
	// The URL is deliberately empty: cryden hands over a token and no
	// notion of where a browser should take it, and this repo owns no
	// verification landing page to name.
	body, ok, err := s.Templates.Verification(templates.Data{To: to, Token: rawToken})
	if err != nil {
		return err
	}
	if ok {
		log.Printf("[EMAIL] verification message for %s:\n%s", to, body)
		return nil
	}
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
	// Templates is consoleEmailSender.Templates' counterpart, with the
	// same nil-means-built-in behaviour.
	Templates *templates.Set
}

func (s *consoleMagicLinkSender) SendMagicLink(ctx context.Context, to string, rawToken string) error {
	// The URL is assembled here rather than in the template on purpose:
	// it is a fact about this deployment's routing, which the template
	// author should not have to reconstruct from a token.
	link := ""
	if s.BaseURL != "" {
		link = s.BaseURL + "/magic-link?token=" + url.QueryEscape(rawToken)
	}

	body, ok, err := s.Templates.MagicLink(templates.Data{To: to, Token: rawToken, URL: link})
	if err != nil {
		return err
	}
	if ok {
		log.Printf("[MAGIC LINK] message for %s:\n%s", to, body)
		return nil
	}

	if link == "" {
		log.Printf("[MAGIC LINK] Token for %s: %s (BASE_URL unset, no clickable link)", to, rawToken)
		return nil
	}
	log.Printf("[MAGIC LINK] For %s: %s", to, link)
	return nil
}

// Package templates renders the message bodies this api sends, from
// plain-text template files on disk.
//
// It exists because cryden owns no template configuration at all, on
// purpose: a message body is a host app's copy — its wording, its brand,
// its legal boilerplate — and an auth engine that shipped default text
// would be putting words in its host's mouth. So the engine hands over a
// recipient and a raw token and nothing else, and what those become is
// decided here.
//
// Templates are deliberately plain text/template over .txt files rather
// than HTML. The senders this package feeds are console stand-ins (see
// email_sender.go in the repo root) whose entire purpose is to show an
// operator what a real provider would send, and a template language with
// no auto-escaping into a message a human reads in a log is one less way
// for the two to disagree.
package templates

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// File names Load looks for, relative to the directory it is given. The
// two are separate files rather than one file with two blocks because
// they are different messages to a different purpose: "confirm this
// address is yours" and "click here to log in" have different copy, and
// cryden keeps their senders apart for the same reason (see its
// notify/magic_link_sender.go).
const (
	VerificationFile = "verification.txt"
	MagicLinkFile    = "magic_link.txt"
)

// Data is what every template is rendered with. One struct for both
// messages rather than a type per message: the fields are the same three
// things in both cases, and a second type would be a second thing for a
// template author to look up.
type Data struct {
	// To is the recipient's email address as the engine gave it.
	To string

	// Token is the raw, single-use token. It is the entire secret of the
	// message — anyone holding it can complete the action it names — so a
	// template that logs it somewhere of its own is a template that
	// leaked.
	Token string

	// URL is a ready-to-click link, already escaped, for the messages
	// that have one. Empty for a verification message (the token is the
	// payload there, and this repo owns no verification landing page) and
	// empty for a magic link on a deployment with no BASE_URL set. A
	// template that wants to render it unconditionally should expect the
	// empty string rather than a missing field.
	URL string
}

// Set is the loaded templates. A nil *Set means "no template directory
// configured", which every method here handles — so a caller can hold a
// nil Set and pass it straight through to its senders without a branch
// at each call site. A non-nil Set always has at least one template; see
// Load.
type Set struct {
	verification *template.Template
	magicLink    *template.Template
}

// Load reads a template directory. A directory holding neither file is
// an error: pointing this deployment at a directory of templates and
// getting today's built-in text instead is the kind of setting that
// looks applied and isn't.
//
// One file is enough, though — each message falls back independently, so
// a deployment that wants its own magic-link copy without touching the
// verification one supplies only that file. A file that is present but
// does not parse is always an error, never a fallback: it is a typo in
// copy someone wrote on purpose, and silently sending them the old text
// would hide it until a user complained.
func Load(dir string) (*Set, error) {
	set := &Set{}
	var found int

	verification, err := loadOne(dir, VerificationFile)
	if err != nil {
		return nil, err
	}
	if verification != nil {
		set.verification = verification
		found++
	}

	magicLink, err := loadOne(dir, MagicLinkFile)
	if err != nil {
		return nil, err
	}
	if magicLink != nil {
		set.magicLink = magicLink
		found++
	}

	if found == 0 {
		return nil, fmt.Errorf("no templates found in %s — expected %s and/or %s",
			dir, VerificationFile, MagicLinkFile)
	}
	return set, nil
}

// Verification renders the verification-email body. ok is false when no
// verification template is configured, which is the caller's cue to use
// its own built-in text rather than to treat an empty body as a message.
func (s *Set) Verification(data Data) (body string, ok bool, err error) {
	if s == nil || s.verification == nil {
		return "", false, nil
	}
	body, err = render(s.verification, data)
	if err != nil {
		return "", false, err
	}
	return body, true, nil
}

// MagicLink is Verification's counterpart for the magic-link message,
// with the same ok meaning.
func (s *Set) MagicLink(data Data) (body string, ok bool, err error) {
	if s == nil || s.magicLink == nil {
		return "", false, nil
	}
	body, err = render(s.magicLink, data)
	if err != nil {
		return "", false, err
	}
	return body, true, nil
}

// loadOne reads and parses one template file, returning (nil, nil) when
// the file simply does not exist. That is the only "absent" case
// tolerated: a file that is there but unreadable — a permission problem,
// a directory where a file was expected — comes back as an error, since
// it is a deployment that meant to configure this and didn't.
func loadOne(dir, name string) (*template.Template, error) {
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading template %s: %w", path, err)
	}
	tmpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", path, err)
	}
	return tmpl, nil
}

// render executes one template and trims the trailing newline most
// editors leave on a file. Without that trim, every rendered body ends
// in a blank line that only shows up in the message a user actually
// receives — the classic thing that is nobody's bug until it is
// everybody's.
func render(tmpl *template.Template, data Data) (string, error) {
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("rendering template %s: %w", tmpl.Name(), err)
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

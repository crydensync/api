package templates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemplate drops one template file into dir, creating dir if the
// caller passed the result of t.TempDir() straight through.
func writeTemplate(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}

func TestSetRendersConfiguredTemplates(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, VerificationFile, "Confirm {{.To}}: {{.Token}}\n")
	writeTemplate(t, dir, MagicLinkFile, "Log in as {{.To}} at {{.URL}}\n")

	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}

	body, ok, err := set.Verification(Data{To: "user@example.com", Token: "tok_123"})
	if err != nil {
		t.Fatalf("Verification: %v", err)
	}
	if !ok {
		t.Fatal("Verification reported no template, want the one that was configured")
	}
	if want := "Confirm user@example.com: tok_123"; body != want {
		t.Errorf("Verification body = %q, want %q", body, want)
	}

	body, ok, err = set.MagicLink(Data{To: "user@example.com", Token: "tok_123", URL: "https://app.example.com/magic-link?token=tok_123"})
	if err != nil {
		t.Fatalf("MagicLink: %v", err)
	}
	if !ok {
		t.Fatal("MagicLink reported no template, want the one that was configured")
	}
	if want := "Log in as user@example.com at https://app.example.com/magic-link?token=tok_123"; body != want {
		t.Errorf("MagicLink body = %q, want %q", body, want)
	}
}

// The trailing newline most editors leave on a file is trimmed, because
// the alternative is a blank line at the end of every message a user
// receives — invisible in the file, obvious in the inbox.
func TestRenderedBodyHasNoTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, VerificationFile, "Confirm {{.To}}\n\n")

	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	body, _, err := set.Verification(Data{To: "user@example.com"})
	if err != nil {
		t.Fatalf("Verification: %v", err)
	}
	if body != "Confirm user@example.com" {
		t.Errorf("body = %q, want no trailing newline", body)
	}
}

// A nil Set is the "no EMAIL_TEMPLATE_DIR configured" case, and every
// render must answer ok=false rather than an empty body: the senders
// distinguish those two, and an empty body that looked like a message
// would be a blank email.
func TestNilSetRendersNothing(t *testing.T) {
	var set *Set

	if body, ok, err := set.Verification(Data{To: "user@example.com"}); ok || err != nil || body != "" {
		t.Errorf("Verification on a nil Set = (%q, %v, %v), want (\"\", false, nil)", body, ok, err)
	}
	if body, ok, err := set.MagicLink(Data{To: "user@example.com"}); ok || err != nil || body != "" {
		t.Errorf("MagicLink on a nil Set = (%q, %v, %v), want (\"\", false, nil)", body, ok, err)
	}
}

// Each message falls back on its own, so a deployment that only wants
// its own magic-link copy supplies only that file.
func TestOneTemplateIsEnough(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, MagicLinkFile, "Log in: {{.URL}}\n")

	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	if _, ok, _ := set.Verification(Data{}); ok {
		t.Error("Verification reported a template when none was configured")
	}
	if _, ok, err := set.MagicLink(Data{URL: "https://app.example.com/magic-link?token=x"}); err != nil || !ok {
		t.Errorf("MagicLink = (ok %v, err %v), want the configured template", ok, err)
	}
}

// The two ways a configured directory can be wrong. Both are startup
// failures rather than silent fallbacks: a directory somebody pointed
// this deployment at and got the old built-in text from is a setting
// that looks applied and isn't.
func TestLoadRejectsABrokenDirectory(t *testing.T) {
	t.Run("no templates at all", func(t *testing.T) {
		_, err := Load(t.TempDir())
		if err == nil {
			t.Fatal("an empty directory was accepted, want an error")
		}
		// The message names what was looked for, since the usual cause is
		// a file spelled differently.
		for _, name := range []string{VerificationFile, MagicLinkFile} {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("error = %q, want it to name %s", err, name)
			}
		}
	})

	t.Run("unparseable template", func(t *testing.T) {
		dir := t.TempDir()
		writeTemplate(t, dir, VerificationFile, "Confirm {{.To")
		_, err := Load(dir)
		if err == nil {
			t.Fatal("a template with an unclosed action was accepted, want an error")
		}
		if !strings.Contains(err.Error(), VerificationFile) {
			t.Errorf("error = %q, want it to name %s", err, VerificationFile)
		}
	})

	t.Run("field that does not exist", func(t *testing.T) {
		// Parsing succeeds on this one — it is Execute that fails, so it
		// exercises the render path rather than Load.
		dir := t.TempDir()
		writeTemplate(t, dir, VerificationFile, "Confirm {{.Tokne}}")
		set, err := Load(dir)
		if err != nil {
			t.Fatalf("Load(%s): %v", dir, err)
		}
		if _, _, err := set.Verification(Data{To: "user@example.com", Token: "tok"}); err == nil {
			t.Error("a misspelled field rendered without error, want the engine to report it")
		}
	})
}

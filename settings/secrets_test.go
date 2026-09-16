package settings

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const testKey = "a-test-encryption-key-long-enough-to-be-plausible"

func newTestSecrets(t *testing.T, key string) (*Secrets, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	secrets, err := NewSecrets(store, key)
	if err != nil {
		t.Fatalf("NewSecrets: %v", err)
	}
	return secrets, store
}

func TestSecretsRoundTripsACredential(t *testing.T) {
	ctx := context.Background()
	secrets, _ := newTestSecrets(t, testKey)

	const credential = "sk-ant-api03-this-is-the-api-key"
	if err := secrets.Put(ctx, KeyLLMProvider, []byte(credential)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := secrets.Get(ctx, KeyLLMProvider)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != credential {
		t.Errorf("Get = %q, want the credential back", got)
	}
}

// The whole reason this type exists, asserted against what is actually in
// the store rather than against Secrets' own answer: the bytes that land
// in the row must not contain the credential.
func TestSecretsNeverStoresThePlaintext(t *testing.T) {
	ctx := context.Background()
	secrets, store := newTestSecrets(t, testKey)

	const credential = "sk-ant-api03-this-is-the-api-key"
	if err := secrets.Put(ctx, KeyLLMProvider, []byte(credential)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	raw, ok := store.Raw(KeyLLMProvider)
	if !ok {
		t.Fatal("nothing was stored")
	}
	if strings.Contains(string(raw), "sk-ant") {
		t.Errorf("the stored bytes contain the credential: %q", raw)
	}
	if strings.Contains(string(raw), credential) {
		t.Errorf("the stored bytes are the credential verbatim: %q", raw)
	}
}

// Two writes of the same credential must not produce the same bytes. A
// fresh nonce per seal is what makes that true, and it is the property a
// store-and-compare attacker needs to be denied.
func TestSecretsSealsWithAFreshNonce(t *testing.T) {
	ctx := context.Background()
	secrets, store := newTestSecrets(t, testKey)

	const credential = "same-credential-both-times"
	if err := secrets.Put(ctx, KeyLLMProvider, []byte(credential)); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	first, _ := store.Raw(KeyLLMProvider)

	if err := secrets.Put(ctx, KeyLLMProvider, []byte(credential)); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	second, _ := store.Raw(KeyLLMProvider)

	if string(first) == string(second) {
		t.Error("sealing the same credential twice produced identical bytes, so the nonce is not fresh")
	}
}

// A changed key is a different failure from a missing setting, and an
// operator sent to re-enter a credential that is still on disk would be
// sent the wrong way. This asserts the two are distinguishable.
func TestSecretsSeparatesAChangedKeyFromAMissingSetting(t *testing.T) {
	ctx := context.Background()
	secrets, store := newTestSecrets(t, testKey)

	if _, err := secrets.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get with nothing stored = %v, want ErrNotFound", err)
	}

	if err := secrets.Put(ctx, KeyLLMProvider, []byte("a-credential")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The same rows, a different key — a redeploy with
	// SETTINGS_ENCRYPTION_KEY rotated and the table left alone.
	rotated, err := NewSecrets(store, "a-completely-different-encryption-key")
	if err != nil {
		t.Fatalf("NewSecrets with a rotated key: %v", err)
	}
	if _, err := rotated.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("Get with a rotated key = %v, want ErrUndecryptable", err)
	}
}

// Without a key every path that touches a credential refuses. This is the
// state a deployment that has never opened the AI settings screen is in,
// and the failure has to be a refusal rather than a write.
func TestSecretsWithoutAKeyRefusesEverything(t *testing.T) {
	ctx := context.Background()
	secrets, store := newTestSecrets(t, "")

	if secrets.Configured() {
		t.Error("Configured = true with no key, so a handler would offer a screen that cannot save")
	}
	if err := secrets.Put(ctx, KeyLLMProvider, []byte("a-credential")); !errors.Is(err, ErrNoEncryptionKey) {
		t.Errorf("Put with no key = %v, want ErrNoEncryptionKey", err)
	}
	if _, err := secrets.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrNoEncryptionKey) {
		t.Errorf("Get with no key = %v, want ErrNoEncryptionKey", err)
	}
	if _, ok := store.Raw(KeyLLMProvider); ok {
		t.Error("Put with no key stored something anyway, which is the one outcome this must prevent")
	}
}

// Clearing a setting must not need the key that sealed it. A deployment
// that has lost SETTINGS_ENCRYPTION_KEY would otherwise have no way to
// remove the row it can no longer read short of direct database access.
func TestSecretsDeletesWithoutAKey(t *testing.T) {
	ctx := context.Background()
	secrets, store := newTestSecrets(t, testKey)

	if err := secrets.Put(ctx, KeyLLMProvider, []byte("a-credential")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	noKey, err := NewSecrets(store, "")
	if err != nil {
		t.Fatalf("NewSecrets with no key: %v", err)
	}
	if err := noKey.Delete(ctx, KeyLLMProvider); err != nil {
		t.Fatalf("Delete with no key: %v", err)
	}
	if _, ok := store.Raw(KeyLLMProvider); ok {
		t.Error("the setting is still stored after Delete")
	}
}

// A nil Secrets is the shape a router built without the store has. Every
// method must answer rather than panic, because "not configured" is a
// wiring fact a handler reports, not a crash.
func TestNilSecretsIsUsable(t *testing.T) {
	ctx := context.Background()
	var secrets *Secrets

	if secrets.Configured() {
		t.Error("a nil Secrets reports itself configured")
	}
	if _, err := secrets.Get(ctx, KeyLLMProvider); !errors.Is(err, ErrNoEncryptionKey) {
		t.Errorf("Get on a nil Secrets = %v, want ErrNoEncryptionKey", err)
	}
	if err := secrets.Delete(ctx, KeyLLMProvider); !errors.Is(err, ErrNoEncryptionKey) {
		t.Errorf("Delete on a nil Secrets = %v, want ErrNoEncryptionKey", err)
	}
}

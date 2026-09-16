package settings

import (
	"context"
	"errors"
	"fmt"

	"github.com/crydensync/cryden/v2/security"
)

// ErrNoEncryptionKey means Secrets was built without a key. Every method
// on Secrets returns it rather than storing anything, because the
// alternative — writing a credential through unencrypted — is the one
// outcome this package exists to prevent, and a "just this once" path
// would be found by exactly the caller least likely to think about it.
var ErrNoEncryptionKey = errors.New("settings: an encryption key is required to store credentials")

// ErrUndecryptable means a value is stored under that key but the
// configured encryption key cannot open it.
var ErrUndecryptable = errors.New("settings: stored value could not be decrypted")

// Secrets is the only thing a handler is given. It wraps a Store and
// seals every value on the way in and opens every value on the way out,
// so no caller has to remember to encrypt and no caller can forget to.
//
// The encryption itself is cryden's, not this repo's:
// security.NewAESGCMEncryptor is the same AES-256-GCM encryptor the
// engine already uses for TOTP secrets. Reimplementing it here would mean
// two cryptographic implementations to keep correct and one more place
// for a nonce to be reused, and there is nothing about a provider API key
// that needs different treatment from a TOTP secret. What this repo adds
// is only the storage and the key it derives from.
type Secrets struct {
	store Store
	// encryptor is nil when no key is configured. Held as cryden's
	// interface rather than its concrete type so the nil case is one
	// check here and not a type assertion at each call.
	encryptor security.Encryptor
}

// NewSecrets returns a Secrets over store, sealing with an AES-256-GCM
// key derived from key.
//
// An empty key is not an error at construction — it produces a Secrets
// that refuses every read and write with ErrNoEncryptionKey. That is
// deliberate: this repo's convention is that an optional feature which
// isn't configured answers 404 rather than stopping the server from
// starting (see the ENCRYPTION_KEY gate in main.go), and a deployment
// that has never opened the AI settings screen should not fail to boot
// because it has not set a key for a feature it isn't using.
func NewSecrets(store Store, key string) (*Secrets, error) {
	if key == "" {
		return &Secrets{store: store}, nil
	}
	encryptor, err := security.NewAESGCMEncryptor(key)
	if err != nil {
		return nil, fmt.Errorf("settings: building the encryptor: %w", err)
	}
	return &Secrets{store: store, encryptor: encryptor}, nil
}

// Configured reports whether a key is set. Handlers use it to answer 404
// not_configured, the same shape every other unconfigured feature in this
// api uses, rather than surfacing ErrNoEncryptionKey as a server fault.
func (s *Secrets) Configured() bool {
	return s != nil && s.encryptor != nil
}

// Put seals plaintext and stores it under key.
func (s *Secrets) Put(ctx context.Context, key string, plaintext []byte) error {
	if !s.Configured() {
		return ErrNoEncryptionKey
	}
	sealed, err := s.encryptor.Encrypt(string(plaintext))
	if err != nil {
		return fmt.Errorf("settings: sealing %q: %w", key, err)
	}
	return s.store.Put(ctx, key, []byte(sealed))
}

// Get returns the decrypted value stored under key, or ErrNotFound.
//
// A decryption failure is reported as its own error rather than as
// ErrNotFound, and that distinction is load-bearing: "nothing is stored"
// and "something is stored that this key cannot open" call for different
// answers from an operator. The second almost always means the
// encryption key changed, and telling them the setting is missing would
// send them to re-enter a credential that is still there.
func (s *Secrets) Get(ctx context.Context, key string) ([]byte, error) {
	if !s.Configured() {
		return nil, ErrNoEncryptionKey
	}
	sealed, err := s.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.encryptor.Decrypt(string(sealed))
	if err != nil {
		return nil, fmt.Errorf("%w: %q (was the encryption key changed?)", ErrUndecryptable, key)
	}
	return []byte(plaintext), nil
}

// Delete removes key through the store. It needs no key of its own: a
// deployment that has lost its encryption key must still be able to clear
// the row it can no longer read, or the only way out is direct database
// access.
func (s *Secrets) Delete(ctx context.Context, key string) error {
	if s == nil || s.store == nil {
		return ErrNoEncryptionKey
	}
	return s.store.Delete(ctx, key)
}

package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crydensync/api/config"
)

const (
	appleTestClientID = "com.example.web"
	appleTestTeamID   = "TEAM123456"
	appleTestKeyID    = "KEY1234567"
	appleTestChildID  = "apple-kid-1"
)

func pemForECDSA(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling EC key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pemForRSA(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling RSA key: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func appleTestProvider(pem string) oauthProvider {
	return oauthProvider{
		name:            "apple",
		clientID:        appleTestClientID,
		appleTeamID:     appleTestTeamID,
		appleKeyID:      appleTestKeyID,
		applePrivateKey: pem,
	}
}

// TestAppleClientSecretIsVerifiable pins the shape Apple requires of the
// self-signed secret: ES256, the console's key ID in the header, and the
// team/client/issuer claims Apple validates against.
func TestAppleClientSecretIsVerifiable(t *testing.T) {
	key, pemStr := pemForECDSA(t)

	secret, err := appleClientSecret(appleTestProvider(pemStr))
	if err != nil {
		t.Fatalf("appleClientSecret: %v", err)
	}

	parsed, err := jwt.Parse(secret, func(tok *jwt.Token) (any, error) {
		return key.Public(), nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(appleTestTeamID), jwt.WithAudience(appleIssuer))
	if err != nil {
		t.Fatalf("parsing generated secret: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != appleTestKeyID {
		t.Fatalf("kid header = %q, want %q", kid, appleTestKeyID)
	}
	if alg, _ := parsed.Header["alg"].(string); alg != "ES256" {
		t.Fatalf("alg = %q, want ES256", alg)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T", parsed.Claims)
	}
	if sub, _ := claims["sub"].(string); sub != appleTestClientID {
		t.Fatalf("sub claim = %q, want the client ID %q", sub, appleTestClientID)
	}
	if exp, ok := claims["exp"].(float64); !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
		t.Fatalf("exp claim missing or already expired: %v", claims["exp"])
	}
}

// TestApplePrivateKeyMustBeEC keeps a wrong key type from surfacing as a
// confusing signing failure later.
func TestApplePrivateKeyMustBeEC(t *testing.T) {
	_, rsaPEM := pemForRSA(t)
	if _, err := appleClientSecret(appleTestProvider(rsaPEM)); err == nil {
		t.Fatal("expected an RSA key to be rejected, got nil error")
	}
	if _, err := appleClientSecret(appleTestProvider("not a pem")); err == nil {
		t.Fatal("expected a non-PEM value to be rejected, got nil error")
	}
}

// appleJWKS serves a one-key JWKS for the given RSA public key, so the
// verification path can be exercised without reaching Apple.
func appleJWKS(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("marshaling JWKS: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)

	originalURL := appleJWKSURL
	appleJWKSURL = srv.URL
	appleKeys = appleKeyCache{}
	t.Cleanup(func() {
		appleJWKSURL = originalURL
		appleKeys = appleKeyCache{}
	})
	return srv
}

func appleIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing id_token: %v", err)
	}
	return signed
}

func appleBaseClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   appleIssuer,
		"aud":   appleTestClientID,
		"sub":   "001234.abcdef0123456789.0900",
		"email": "user@privaterelay.appleid.com",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

// TestVerifyAppleIDToken is the property that matters most in this file:
// the identity comes from a signature-verified JWT, not a decoded one.
func TestVerifyAppleIDToken(t *testing.T) {
	key, _ := pemForRSA(t)
	appleJWKS(t, appleTestChildID, &key.PublicKey)
	token := appleIDToken(t, key, appleTestChildID, appleBaseClaims())

	sub, email, err := verifyAppleIDToken(t.Context(), token, appleTestClientID)
	if err != nil {
		t.Fatalf("verifyAppleIDToken: %v", err)
	}
	if sub != "001234.abcdef0123456789.0900" || email != "user@privaterelay.appleid.com" {
		t.Fatalf("got sub=%q email=%q", sub, email)
	}
}

func TestVerifyAppleIDTokenRejects(t *testing.T) {
	key, _ := pemForRSA(t)
	appleJWKS(t, appleTestChildID, &key.PublicKey)

	other, _ := pemForRSA(t)

	cases := map[string]string{
		"wrong audience": appleIDToken(t, key, appleTestChildID, jwt.MapClaims{
			"iss": appleIssuer, "aud": "com.someone.else", "sub": "x", "email": "u@example.com",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}),
		"wrong issuer": appleIDToken(t, key, appleTestChildID, jwt.MapClaims{
			"iss": "https://evil.example", "aud": appleTestClientID, "sub": "x", "email": "u@example.com",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}),
		"expired": appleIDToken(t, key, appleTestChildID, jwt.MapClaims{
			"iss": appleIssuer, "aud": appleTestClientID, "sub": "x", "email": "u@example.com",
			"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
		}),
		"signed by the wrong key": appleIDToken(t, other, appleTestChildID, appleBaseClaims()),
		"unknown key id":          appleIDToken(t, key, "some-other-kid", appleBaseClaims()),
		"no subject": appleIDToken(t, key, appleTestChildID, jwt.MapClaims{
			"iss": appleIssuer, "aud": appleTestClientID, "email": "u@example.com",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}),
	}

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := verifyAppleIDToken(t.Context(), token, appleTestClientID)
			if !errors.Is(err, errOAuthIdentityVerificationFailed) {
				t.Fatalf("err = %v, want errOAuthIdentityVerificationFailed", err)
			}
		})
	}
}

// TestVerifyAppleIDTokenRejectsNoneAlg covers the classic JWT footgun:
// an unsigned token must never be accepted, whatever its claims say.
func TestVerifyAppleIDTokenRejectsNoneAlg(t *testing.T) {
	key, _ := pemForRSA(t)
	appleJWKS(t, appleTestChildID, &key.PublicKey)

	tok := jwt.NewWithClaims(jwt.SigningMethodNone, appleBaseClaims())
	unsigned, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("building unsigned token: %v", err)
	}
	if _, _, err := verifyAppleIDToken(t.Context(), unsigned, appleTestClientID); !errors.Is(err, errOAuthIdentityVerificationFailed) {
		t.Fatalf("err = %v, want errOAuthIdentityVerificationFailed", err)
	}
}

// TestAppleProviderRequiresFullConfig pins the gate: Apple's signing
// material is configuration in a way no other provider's is, so a
// half-configured Apple must read as unavailable rather than fail at the
// first login attempt.
func TestAppleProviderRequiresFullConfig(t *testing.T) {
	full := config.Config{
		AppleClientID:   appleTestClientID,
		AppleTeamID:     appleTestTeamID,
		AppleKeyID:      appleTestKeyID,
		ApplePrivateKey: "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
	}

	enabled := &OAuthHandlers{Config: full}
	if _, ok := enabled.provider("apple"); !ok {
		t.Fatal("expected apple to be available when all four values are set")
	}

	cases := map[string]config.Config{
		"no client id":   {AppleTeamID: full.AppleTeamID, AppleKeyID: full.AppleKeyID, ApplePrivateKey: full.ApplePrivateKey},
		"no team id":     {AppleClientID: full.AppleClientID, AppleKeyID: full.AppleKeyID, ApplePrivateKey: full.ApplePrivateKey},
		"no key id":      {AppleClientID: full.AppleClientID, AppleTeamID: full.AppleTeamID, ApplePrivateKey: full.ApplePrivateKey},
		"no private key": {AppleClientID: full.AppleClientID, AppleTeamID: full.AppleTeamID, AppleKeyID: full.AppleKeyID},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			h := &OAuthHandlers{Config: cfg}
			if _, ok := h.provider("apple"); ok {
				t.Fatal("expected apple to be unavailable with incomplete config")
			}
		})
	}
}

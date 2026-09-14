package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// appleIssuer is both the `iss` Apple puts in an id_token and the `aud`
// our self-signed client secret must carry — Apple is the audience of
// the secret, we are the audience of the id_token.
const appleIssuer = "https://appleid.apple.com"

// appleClientSecretTTL is how long a generated client secret is valid.
// Apple's own limit is six months; ten minutes is short because the
// secret is generated per exchange anyway, so there is nothing to gain
// from a long-lived one — it just means a leaked secret is useless
// almost immediately.
const appleClientSecretTTL = 10 * time.Minute

// appleJWKSURL is a var rather than a const so tests can point it at a
// local server: signature verification is the part of this file worth
// testing, and it cannot be tested against Apple's real endpoint from a
// sandbox with no network.
var appleJWKSURL = appleIssuer + "/auth/keys"

// appleKeyCacheTTL bounds how long a fetched key set is reused. Apple
// rotates signing keys rarely and publishes no cache lifetime we honor,
// so an hour is short enough to pick up a rotation without re-fetching
// per login.
const appleKeyCacheTTL = time.Hour

type appleKeyCache struct {
	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

var appleKeys appleKeyCache

// appleClientSecret builds the ES256 JWT Apple wants in place of a
// static client secret. This is the whole reason Apple is not another
// mechanical provider case: every other provider hands you a string,
// Apple hands you a key and expects you to sign.
func appleClientSecret(p oauthProvider) (string, error) {
	if p.appleTeamID == "" || p.appleKeyID == "" || p.applePrivateKey == "" {
		return "", errOAuthProviderNotConfigured
	}

	key, err := parseApplePrivateKey(p.applePrivateKey)
	if err != nil {
		return "", err
	}

	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": p.appleTeamID,
		"iat": now.Unix(),
		"exp": now.Add(appleClientSecretTTL).Unix(),
		"aud": appleIssuer,
		"sub": p.clientID,
	})
	tok.Header["kid"] = p.appleKeyID
	return tok.SignedString(key)
}

// parseApplePrivateKey reads the PKCS#8 .p8 file Apple's developer
// console hands out. A non-EC key is rejected here rather than left to
// fail at signing time with a less obvious error.
func parseApplePrivateKey(pemValue string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemValue))
	if block == nil {
		return nil, fmt.Errorf("httpapi: apple private key is not PEM-encoded")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("httpapi: parsing apple private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("httpapi: apple private key is %T, want an EC (P-256) key", parsed)
	}
	return key, nil
}

// verifyAppleIDToken checks an id_token against Apple's published
// signing keys and returns the account's stable identifier and email.
// Apple is the only provider here with no userinfo endpoint: the
// identity travels inside this signed JWT, so it is verified rather
// than merely decoded — an unverified parse would let anyone who can
// reach our callback mint an account.
func verifyAppleIDToken(ctx context.Context, idToken, clientID string) (sub, email string, err error) {
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(idToken, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return appleSigningKey(ctx, kid)
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(appleIssuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", errOAuthIdentityVerificationFailed, err)
	}

	sub, _ = claims["sub"].(string)
	email, _ = claims["email"].(string)
	if sub == "" {
		return "", "", errOAuthIdentityVerificationFailed
	}
	return sub, email, nil
}

// appleSigningKey returns the RSA key for kid, fetching (and caching)
// Apple's key set as needed. A cache miss for a kid we already fetched
// forces one refetch, which is how a key rotation is picked up without
// waiting out the TTL.
func appleSigningKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errOAuthIdentityVerificationFailed
	}

	appleKeys.mu.Lock()
	defer appleKeys.mu.Unlock()

	_, known := appleKeys.keys[kid]
	if known && time.Since(appleKeys.fetchedAt) < appleKeyCacheTTL {
		return appleKeys.keys[kid], nil
	}

	keys, err := fetchAppleKeys(ctx)
	if err != nil {
		return nil, err
	}
	appleKeys.keys = keys
	appleKeys.fetchedAt = time.Now()

	key, ok := keys[kid]
	if !ok {
		return nil, errOAuthIdentityVerificationFailed
	}
	return key, nil
}

// fetchAppleKeys reads Apple's JWKS. Only RSA keys are accepted —
// Apple signs id_tokens with RS256, and anything else in the set is not
// something this flow will ever validate against.
func fetchAppleKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleJWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpapi: apple key set request failed: status %d", resp.StatusCode)
	}

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}

	out := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
		if err != nil {
			return nil, fmt.Errorf("httpapi: decoding apple key modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
		if err != nil {
			return nil, fmt.Errorf("httpapi: decoding apple key exponent: %w", err)
		}
		out[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	if len(out) == 0 {
		return nil, errOAuthIdentityVerificationFailed
	}
	return out, nil
}

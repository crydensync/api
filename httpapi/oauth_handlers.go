package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/crydensync/cryden/v2"
	"github.com/crydensync/cryden/v2/auth"

	"github.com/crydensync/api/config"
)

// oauthStateCookie is the name of the short-lived cookie holding the
// CSRF state value between the redirect and the callback. There's no
// session/cache store in this repo beyond Postgres, and a signed
// cookie is the standard, simplest fit for this exact problem — the
// value only needs to survive one browser round trip.
const oauthStateCookie = "cryden_oauth_state"

// oauthLinkUserCookie carries the linking user's ID through the
// provider redirect round trip. A Bearer token in an Authorization
// header cannot survive a browser redirect to a provider and back —
// there is no header to carry there. So LinkStart (which DOES see the
// real Authorization header, since it's called directly by an
// authenticated client, not via a redirect) signs the user ID with
// HMAC-SHA256 using the same JWT secret and stashes it in this
// cookie; LinkCallback verifies the signature rather than trusting
// the plain value, so a tampered cookie can't be used to link
// someone else's account.
const oauthLinkUserCookie = "cryden_oauth_link_user"

// oauthProvider is the minimal per-provider shape this handler needs.
// Each provider's actual endpoints/scopes are hardcoded below rather
// than made pluggable — adding a third provider means adding a third
// small case, not building a plugin system for two entries.
type oauthProvider struct {
	name         string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	userInfoURL  string
	scope        string
}

type OAuthHandlers struct {
	Engine *cryden.Engine
	Config config.Config
}

func (h *OAuthHandlers) provider(name string) (oauthProvider, bool) {
	switch name {
	case "google":
		if h.Config.GoogleClientID == "" || h.Config.GoogleClientSecret == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:         "google",
			clientID:     h.Config.GoogleClientID,
			clientSecret: h.Config.GoogleClientSecret,
			authURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL:     "https://oauth2.googleapis.com/token",
			userInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
			scope:        "openid email",
		}, true
	case "github":
		if h.Config.GitHubClientID == "" || h.Config.GitHubClientSecret == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:         "github",
			clientID:     h.Config.GitHubClientID,
			clientSecret: h.Config.GitHubClientSecret,
			authURL:      "https://github.com/login/oauth/authorize",
			tokenURL:     "https://github.com/login/oauth/access_token",
			userInfoURL:  "https://api.github.com/user",
			scope:        "read:user user:email",
		}, true
	default:
		return oauthProvider{}, false
	}
}

func (h *OAuthHandlers) callbackURL(providerName string) string {
	return h.Config.BaseURL + "/v1/oauth/" + providerName + "/callback"
}

// Start redirects the browser to the provider's consent screen. GET,
// not POST — this is a full browser navigation, not an API call a
// JS client makes with fetch.
func (h *OAuthHandlers) Start(w http.ResponseWriter, r *http.Request, providerName string) {
	p, ok := h.provider(providerName)
	if !ok {
		writeErr(w, errOAuthProviderNotConfigured)
		return
	}

	state, err := randomState()
	if err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/v1/oauth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes — plenty for a consent-screen round trip
	})

	q := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {h.callbackURL(p.name)},
		"response_type": {"code"},
		"scope":         {p.scope},
		"state":         {state},
	}
	http.Redirect(w, r, p.authURL+"?"+q.Encode(), http.StatusFound)
}

// Callback receives the provider's redirect, exchanges the code,
// fetches the confirmed identity, and calls cryden.LoginWithOAuth.
// This is the ONLY place in this repo that talks to a provider's
// token/userinfo endpoints — by the time cryden.LoginWithOAuth is
// called, the identity is already confirmed; the engine itself never
// makes an HTTP call.
func (h *OAuthHandlers) Callback(w http.ResponseWriter, r *http.Request, providerName string) {
	p, ok := h.provider(providerName)
	if !ok {
		writeErr(w, errOAuthProviderNotConfigured)
		return
	}

	if err := verifyState(r); err != nil {
		writeErr(w, err)
		return
	}
	clearStateCookie(w)

	code := r.URL.Query().Get("code")
	if code == "" {
		writeBadRequest(w, "missing code")
		return
	}

	externalID, email, err := exchangeAndFetchIdentity(r, p, h.callbackURL(p.name), code)
	if err != nil {
		writeErr(w, err)
		return
	}

	tokens, err := cryden.LoginWithOAuth(r.Context(), h.Engine, p.name, externalID, email, CallerIP(r), UserAgent(r))
	if err != nil {
		var conflict *auth.ErrOAuthEmailConflict
		if errors.As(err, &conflict) {
			// The confirmed decision: never auto-link. Surface this
			// as a distinct response the frontend routes to a
			// dedicated "link your accounts" screen — not a generic
			// login failure, and not silently resolved here.
			writeErr(w, err)
			return
		}
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, toTokensDTO(tokens))
}

// LinkStart begins the linking flow for an ALREADY-AUTHENTICATED
// user — call this behind RequireAuth. It signs the caller's user ID
// into a short-lived cookie (see oauthLinkUserCookie) because that ID
// cannot otherwise survive the redirect to the provider and back.
func (h *OAuthHandlers) LinkStart(w http.ResponseWriter, r *http.Request, providerName string) {
	p, ok := h.provider(providerName)
	if !ok {
		writeErr(w, errOAuthProviderNotConfigured)
		return
	}

	userID := UserIDFromContext(r)
	signed, err := signLinkUserID(h.Config.JWTSecret, userID)
	if err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthLinkUserCookie,
		Value:    signed,
		Path:     "/v1/oauth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	state, err := randomState()
	if err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Path:     "/v1/oauth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	q := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {h.linkCallbackURL(p.name)},
		"response_type": {"code"},
		"scope":         {p.scope},
		"state":         {state},
	}
	http.Redirect(w, r, p.authURL+"?"+q.Encode(), http.StatusFound)
}

// LinkCallback receives the provider's redirect for the linking flow.
// Deliberately NOT behind RequireAuth — there is no Authorization
// header on a browser redirect. Identity of the linking user instead
// comes from the signed cookie LinkStart set, verified here rather
// than trusted as plain text.
func (h *OAuthHandlers) LinkCallback(w http.ResponseWriter, r *http.Request, providerName string) {
	p, ok := h.provider(providerName)
	if !ok {
		writeErr(w, errOAuthProviderNotConfigured)
		return
	}

	if err := verifyState(r); err != nil {
		writeErr(w, err)
		return
	}
	clearStateCookie(w)

	cookie, err := r.Cookie(oauthLinkUserCookie)
	if err != nil {
		writeErr(w, errOAuthLinkSessionMissing)
		return
	}
	userID, err := verifyLinkUserID(h.Config.JWTSecret, cookie.Value)
	if err != nil {
		writeErr(w, errOAuthLinkSessionMissing)
		return
	}
	clearLinkUserCookie(w)

	code := r.URL.Query().Get("code")
	if code == "" {
		writeBadRequest(w, "missing code")
		return
	}

	externalID, email, err := exchangeAndFetchIdentity(r, p, h.linkCallbackURL(p.name), code)
	if err != nil {
		writeErr(w, err)
		return
	}

	if err := cryden.LinkOAuthIdentity(r.Context(), h.Engine, userID, p.name, externalID, email, CallerIP(r)); err != nil {
		writeErr(w, err)
		return
	}
	writeData(w, http.StatusOK, map[string]string{"status": "linked", "provider": p.name})
}

func (h *OAuthHandlers) linkCallbackURL(providerName string) string {
	return h.Config.BaseURL + "/v1/oauth/" + providerName + "/link/callback"
}

// signLinkUserID and verifyLinkUserID are a minimal HMAC-SHA256
// sign/verify pair — not a JWT, deliberately simpler, since this only
// ever needs to survive one short redirect round trip, not be a
// general-purpose bearer credential.
func signLinkUserID(secret, userID string) (string, error) {
	if secret == "" {
		return "", errOAuthLinkNotConfigured
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(userID)) + "." + sig, nil
}

func verifyLinkUserID(secret, value string) (string, error) {
	if secret == "" {
		return "", errOAuthLinkNotConfigured
	}
	parts := splitOnce(value, '.')
	if len(parts) != 2 {
		return "", errOAuthLinkSessionMissing
	}
	userIDBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errOAuthLinkSessionMissing
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(userIDBytes)
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[1])) {
		return "", errOAuthLinkSessionMissing
	}
	return string(userIDBytes), nil
}

func splitOnce(s string, sep byte) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}

func clearLinkUserCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthLinkUserCookie,
		Value:    "",
		Path:     "/v1/oauth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// fetchGitHubPrimaryEmail calls GET /user/emails and returns the
// primary, verified address. GitHub can return multiple emails
// (work, personal, noreply aliases) — only the primary+verified one
// is trustworthy enough to use as the account's identity.
func fetchGitHubPrimaryEmail(r *http.Request, providerToken string) (string, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+providerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("httpapi: github /user/emails request failed: status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", errOAuthEmailNotAvailable
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func verifyState(r *http.Request) error {
	cookie, err := r.Cookie(oauthStateCookie)
	if err != nil || cookie.Value == "" {
		return errOAuthStateMismatch
	}
	if r.URL.Query().Get("state") != cookie.Value {
		return errOAuthStateMismatch
	}
	return nil
}

func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookie,
		Value:    "",
		Path:     "/v1/oauth",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// exchangeAndFetchIdentity does the actual provider protocol work:
// exchange the code for a provider access token, then use that token
// to fetch the confirmed external ID and email. Deliberately the only
// function in this file that reaches out to a provider — everything
// above it is either request-shaped (redirect/state) or calls into
// the engine.
func exchangeAndFetchIdentity(r *http.Request, p oauthProvider, redirectURI, code string) (externalID, email string, err error) {
	tokenResp, err := exchangeCode(r, p, redirectURI, code)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("httpapi: oauth userinfo request failed: status %d", resp.StatusCode)
	}

	switch p.name {
	case "google":
		var info struct {
			Sub   string `json:"sub"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return "", "", err
		}
		return info.Sub, info.Email, nil
	case "github":
		var info struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return "", "", err
		}
		if info.Email == "" {
			// GitHub's /user endpoint only returns email if the
			// account has made it public. The verified primary
			// address instead comes from /user/emails, which needs
			// the same token and the same scope this handler already
			// requests (user:email).
			email, err := fetchGitHubPrimaryEmail(r, tokenResp)
			if err != nil {
				return "", "", err
			}
			return fmt.Sprintf("%d", info.ID), email, nil
		}
		return fmt.Sprintf("%d", info.ID), info.Email, nil
	default:
		return "", "", errOAuthProviderNotConfigured
	}
}

// exchangeCode trades the authorization code for a provider access
// token. Returns just the token string — this handler only ever needs
// it to make the one immediate userinfo call, never stores it.
func exchangeCode(r *http.Request, p oauthProvider, redirectURI, code string) (string, error) {
	form := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.tokenURL, nil)
	if err != nil {
		return "", err
	}
	req.URL.RawQuery = form.Encode() // both providers accept this as query or form body; query keeps this dependency-free
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("httpapi: oauth token exchange failed: status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("httpapi: oauth token exchange returned no access_token")
	}
	return tokenResp.AccessToken, nil
}

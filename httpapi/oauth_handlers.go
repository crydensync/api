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
	"strings"

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
	// extraAuthParams are merged into the authorization redirect's query.
	// Only Apple needs one (it is the only provider whose response mode
	// this handler has to pin down); everyone else leaves it empty.
	extraAuthParams url.Values
	// Apple's signing material — empty for every other provider, which
	// use a static clientSecret instead. See apple.go.
	appleTeamID     string
	appleKeyID      string
	applePrivateKey string
}

type OAuthHandlers struct {
	Engine *cryden.Engine
	Config config.Config
}

// oauthProviderNames is every provider this repo can speak to, in the
// order the admin health endpoint reports them. Deliberately adjacent to
// provider() below: a new case there without a name here would leave that
// provider out of the health report, which is the one way these two lists
// can silently disagree.
var oauthProviderNames = []string{"google", "github", "microsoft", "discord", "gitlab", "apple"}

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
	case "microsoft":
		if h.Config.MicrosoftClientID == "" || h.Config.MicrosoftClientSecret == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:         "microsoft",
			clientID:     h.Config.MicrosoftClientID,
			clientSecret: h.Config.MicrosoftClientSecret,
			authURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			tokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			userInfoURL:  "https://graph.microsoft.com/v1.0/me",
			// "common" rather than a single tenant so personal accounts
			// and any org's work accounts both work without per-tenant
			// configuration. User.Read is what makes the access token
			// audience-valid for the Graph /me call below.
			scope: "openid email profile User.Read",
		}, true
	case "discord":
		if h.Config.DiscordClientID == "" || h.Config.DiscordClientSecret == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:         "discord",
			clientID:     h.Config.DiscordClientID,
			clientSecret: h.Config.DiscordClientSecret,
			authURL:      "https://discord.com/oauth2/authorize",
			tokenURL:     "https://discord.com/api/oauth2/token",
			userInfoURL:  "https://discord.com/api/users/@me",
			scope:        "identify email",
		}, true
	case "gitlab":
		if h.Config.GitLabClientID == "" || h.Config.GitLabClientSecret == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:         "gitlab",
			clientID:     h.Config.GitLabClientID,
			clientSecret: h.Config.GitLabClientSecret,
			authURL:      "https://gitlab.com/oauth/authorize",
			tokenURL:     "https://gitlab.com/oauth/token",
			userInfoURL:  "https://gitlab.com/api/v4/user",
			scope:        "read_user",
		}, true
	case "apple":
		// All four values are required: Apple's "client secret" is a JWT
		// this repo signs with AppleKeyID/ApplePrivateKey for the team
		// named by AppleTeamID, so a half-configured Apple is not a
		// provider that half works, it is one that cannot sign at all.
		if h.Config.AppleClientID == "" || h.Config.AppleTeamID == "" || h.Config.AppleKeyID == "" || h.Config.ApplePrivateKey == "" {
			return oauthProvider{}, false
		}
		return oauthProvider{
			name:     "apple",
			clientID: h.Config.AppleClientID,
			// Deliberately no clientSecret — see apple.go's
			// appleClientSecret, which signs a fresh one per exchange.
			authURL:  appleIssuer + "/auth/authorize",
			tokenURL: appleIssuer + "/auth/token",
			// Apple has no userinfo endpoint: the identity arrives in the
			// token response's signed id_token instead (see
			// exchangeAndFetchAppleIdentity).
			userInfoURL: "",
			scope:       "name email",
			// query, not form_post: this handler's callback is a GET
			// redirect, and query mode keeps that route unchanged. The
			// name/email Apple only ever sends on a first authorization
			// arrives in the `user` form field under form_post, which
			// this repo does not need — it stores the id_token's email.
			extraAuthParams: url.Values{"response_mode": {"query"}},
			appleTeamID:     h.Config.AppleTeamID,
			appleKeyID:      h.Config.AppleKeyID,
			applePrivateKey: h.Config.ApplePrivateKey,
		}, true
	default:
		return oauthProvider{}, false
	}
}

// authQuery builds the authorization redirect's query. Kept as one
// function rather than inline in both flows so a provider-specific
// parameter (see oauthProvider.extraAuthParams) cannot be added to one
// flow and forgotten in the other.
func authQuery(p oauthProvider, redirectURI, state string) url.Values {
	q := url.Values{
		"client_id":     {p.clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {p.scope},
		"state":         {state},
	}
	for k, values := range p.extraAuthParams {
		q[k] = values
	}
	return q
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

	http.Redirect(w, r, p.authURL+"?"+authQuery(p, h.callbackURL(p.name), state).Encode(), http.StatusFound)
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
		// An account with a second factor enrolled pauses here too — an
		// OAuth login is still a login, so it goes through the same gate
		// and reports the pause the same way (see second_factor.go).
		if writeTokensOrPause(w, err) {
			return
		}
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

	http.Redirect(w, r, p.authURL+"?"+authQuery(p, h.linkCallbackURL(p.name), state).Encode(), http.StatusFound)
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
	// Apple is the one provider that does not follow the others' shape:
	// its client secret is signed per exchange, and there is no userinfo
	// call to make afterwards — the identity is in the token response.
	if p.name == "apple" {
		return exchangeAndFetchAppleIdentity(r, p, redirectURI, code)
	}

	tokenResp, err := exchangeCode(r, p, redirectURI, code, p.clientSecret)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
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
			email, err := fetchGitHubPrimaryEmail(r, tokenResp.AccessToken)
			if err != nil {
				return "", "", err
			}
			return fmt.Sprintf("%d", info.ID), email, nil
		}
		return fmt.Sprintf("%d", info.ID), info.Email, nil
	case "microsoft":
		var info struct {
			ID                string `json:"id"`
			Mail              string `json:"mail"`
			UserPrincipalName string `json:"userPrincipalName"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return "", "", err
		}
		// mail is the real address but is null for many personal
		// accounts; userPrincipalName is the fallback Microsoft
		// itself documents for exactly that case.
		email := info.Mail
		if email == "" {
			email = info.UserPrincipalName
		}
		if email == "" {
			return "", "", errOAuthEmailNotAvailable
		}
		return info.ID, email, nil
	case "discord":
		var info struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return "", "", err
		}
		if info.Email == "" {
			return "", "", errOAuthEmailNotAvailable
		}
		return info.ID, info.Email, nil
	case "gitlab":
		var info struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return "", "", err
		}
		if info.Email == "" {
			// /api/v4/user only returns the primary address because
			// this handler asks for read_user; anything else means the
			// account has no usable address, not that we should invent
			// one from the username.
			return "", "", errOAuthEmailNotAvailable
		}
		return fmt.Sprintf("%d", info.ID), info.Email, nil
	default:
		return "", "", errOAuthProviderNotConfigured
	}
}

// exchangeAndFetchAppleIdentity is Apple's version of the step above.
// Apple is the only provider whose client secret is not a static string
// (it is an ES256 JWT signed here) and the only one with no userinfo
// endpoint (the id_token in the token response carries the identity, and
// has to be verified against Apple's signing keys rather than decoded —
// see verifyAppleIDToken).
func exchangeAndFetchAppleIdentity(r *http.Request, p oauthProvider, redirectURI, code string) (externalID, email string, err error) {
	secret, err := appleClientSecret(p)
	if err != nil {
		return "", "", err
	}

	tokenResp, err := exchangeCode(r, p, redirectURI, code, secret)
	if err != nil {
		return "", "", err
	}
	if tokenResp.IDToken == "" {
		return "", "", errOAuthIdentityVerificationFailed
	}

	sub, email, err := verifyAppleIDToken(r.Context(), tokenResp.IDToken, p.clientID)
	if err != nil {
		return "", "", err
	}
	if email == "" {
		return "", "", errOAuthEmailNotAvailable
	}
	return sub, email, nil
}

// oauthTokenResponse is what a provider's token endpoint gives back.
// Only these two fields are ever read: the access token for the one
// immediate userinfo call, and Apple's id_token. Nothing here is stored
// — this API keeps no provider tokens.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

// exchangeCode trades the authorization code for a provider access
// token. clientSecret is passed in rather than read off p because Apple
// derives one per exchange; every other provider passes p.clientSecret.
func exchangeCode(r *http.Request, p oauthProvider, redirectURI, code, clientSecret string) (oauthTokenResponse, error) {
	form := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"grant_type":    {"authorization_code"},
	}
	// RFC 6749 §4.1.3 puts these parameters in the POST body, and that
	// is what Microsoft and Discord require — query parameters are not
	// accepted there. Google and GitHub accept the body form too, so
	// there is one code path rather than a per-provider branch.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthTokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauthTokenResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oauthTokenResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return oauthTokenResponse{}, fmt.Errorf("httpapi: oauth token exchange failed: status %d", resp.StatusCode)
	}

	var tokenResp oauthTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return oauthTokenResponse{}, err
	}
	if tokenResp.AccessToken == "" {
		return oauthTokenResponse{}, fmt.Errorf("httpapi: oauth token exchange returned no access_token")
	}
	return tokenResp, nil
}

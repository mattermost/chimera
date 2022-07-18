package api

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/mattermost/chimera/internal/metrics"

	"github.com/gorilla/csrf"
	"github.com/mattermost/chimera/internal/cache"

	"github.com/mattermost/chimera/internal/statuserr"
	"github.com/pkg/errors"

	"github.com/mattermost/chimera/internal/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	stateExtensionLength                   = 16
	chimeraAuthorizationVerificationCookie = "chimera_authz_verification"
)

func NewHandler(cache StateCache, baseURL *url.URL, confirmFormPath, cancelPagePath string, metricsCollector *metrics.Collector) (*Handler, error) {
	confirmForm, err := template.ParseFiles(confirmFormPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse confirmation form template")
	}

	return &Handler{
		stateCache:               cache,
		baseURL:                  baseURL.String(),
		confirmationFromTemplate: confirmForm,
		cancelPagePath:           cancelPagePath,
		useSecureCookie:          useSecureCookies(baseURL),
		metricsCollector:         metricsCollector,
	}, nil
}

type Handler struct {
	stateCache               StateCache
	baseURL                  string
	confirmationFromTemplate *template.Template
	cancelPagePath           string
	useSecureCookie          bool
	metricsCollector         *metrics.Collector
}

type StateCache interface {
	GetRedirectURI(state string) (cache.AuthorizationState, error)
	SetRedirectURI(state string, authzState cache.AuthorizationState) error
	DeleteState(state string) error
}

type AuthFormData struct {
	RedirectURL    string
	ConfirmAuthURL string
	ProviderName   string
	ProviderURL    string
	CancelAuthURL  string
	CsrfField      template.HTML
}

type TokenResponse struct {
	oauth2.Token
	ExpiresIn float64 `json:"expires_in"`
}

func (h *Handler) handleAuthorize(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger = loggerWithAppFields(c.Logger, c.OAuthApplication)
	c.Logger.Infof("Handling authorization")

	redirectURIRaw := r.URL.Query().Get("redirect_uri")
	if redirectURIRaw == "" {
		c.Logger.Warn("redirect_uri not present in authorize request")
		http.Error(w, "Redirect_uri needs to be specified", http.StatusBadRequest)
		return
	}

	err := validateRedirectURI(redirectURIRaw)
	if err != nil {
		c.Logger.WithError(err).Warn("invalid redirect_uri in authorize request")
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	scope, found := r.URL.Query()["scope"]
	if !found {
		scope = []string{}
	}

	// There is no specific guidelines to the size of `state` parameter.
	// The minimum length of 5 was chosen as it seems like minimal reasonable length.
	state := r.URL.Query().Get("state")
	if len(state) <= 5 {
		c.Logger.Warn("Invalid state parameter")
		http.Error(w, "State parameter is required and needs to be at least 5 characters long", http.StatusBadRequest)
		return
	}
	extendedState := fmt.Sprintf("%s%s", state, util.NewRandomString(stateExtensionLength))

	err = h.stateCache.SetRedirectURI(extendedState, cache.AuthorizationState{RedirectURI: redirectURIRaw})
	if err != nil {
		c.Logger.WithError(err).Error("Failed to save mapping of state to redirect URI in cache")
		http.Error(w, "Failed to save state", http.StatusInternalServerError)
		return
	}

	clientID := r.URL.Query().Get("client_id")

	// If needed we can do further verification here
	if clientID == "" {
		c.Logger.Warn("Client ID not provided")
		http.Error(w, "Client ID cannot be empty", http.StatusBadRequest)
		return
	}

	conf := h.makeOAuthConfig(scope, c.OAuthApplication)

	authURL := conf.AuthCodeURL(extendedState, oauth2.AccessTypeOffline)

	h.metricsCollector.IncAuthorizationRequested(c.OAuthApplication.Identifier)

	c.Logger.Infof("Redirecting to auth URL")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleAuthorizationCallback(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger = loggerWithAppFields(c.Logger, c.OAuthApplication)
	c.Logger.Info("Handling authorization callback")

	state := r.URL.Query().Get("state")

	chimeraAuthZState, err := h.getAuthZStateFromCache(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get redirect URI from cache")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	redirectURI, err := url.Parse(chimeraAuthZState.RedirectURI)
	if err != nil {
		c.Logger.Error("Failed to parse destination site URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Update redirect URI with params returned from OAuth provider such as `authorization_code`.
	originalState := state[:len(state)-stateExtensionLength]
	query := r.URL.Query()
	query.Set("state", originalState)
	redirectURI.RawQuery = query.Encode()

	redirectURIStr := redirectURI.String()

	verificationToken := util.NewRandomString(32)
	err = h.stateCache.SetRedirectURI(state, cache.AuthorizationState{RedirectURI: redirectURIStr, AuthorizationVerificationToken: verificationToken})
	if err != nil {
		c.Logger.Error("Failed to update redirect URL in cache")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.Logger.Info("Redirecting authorization callback to confirmation")
	http.Redirect(w, r, fmt.Sprintf("%s/v1/%s/%s/auth/chimera/confirm?state=%s", h.baseURL, c.OAuthApplication.Provider, c.OAuthApplication.Identifier, state), http.StatusFound)
}

func (h *Handler) handleGetConfirmAuthorization(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger = loggerWithAppFields(c.Logger, c.OAuthApplication)
	c.Logger.Info("Handling request for confirmation of Chimera authZ")

	state := r.URL.Query().Get("state")

	chimeraAuthZState, err := h.getAuthZStateFromCache(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get redirect URI from cache")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	// Strip URL query for cleaner display
	strippedURL, err := stripURLQuery(chimeraAuthZState.RedirectURI)
	if err != nil {
		c.Logger.Error("Failed to strip query from redirect URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data := AuthFormData{
		RedirectURL:    strippedURL,
		ConfirmAuthURL: fmt.Sprintf("%s/v1/%s/%s/auth/chimera/confirm?state=%s", h.baseURL, c.OAuthApplication.Provider, c.OAuthApplication.Identifier, state),
		ProviderName:   c.OAuthApplication.Provider.DisplayName(),
		ProviderURL:    c.OAuthApplication.Provider.HomepageURL(),
		CancelAuthURL:  fmt.Sprintf("%s/v1/%s/%s/auth/chimera/cancel?state=%s", h.baseURL, c.OAuthApplication.Provider, c.OAuthApplication.Identifier, state),
		CsrfField:      csrf.TemplateField(r),
	}

	c.Logger.Info("Displaying authZ confirmation from")
	http.SetCookie(w, h.chimeraAuthZTokenCookie(chimeraAuthZState.AuthorizationVerificationToken))
	w.WriteHeader(http.StatusOK)
	err = h.confirmationFromTemplate.Execute(w, data)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to send confirmation from")
	}
}

func (h *Handler) handleConfirmAuthorization(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger = loggerWithAppFields(c.Logger, c.OAuthApplication)
	c.Logger.Info("Handling request for confirmation of Chimera authZ")

	state := r.URL.Query().Get("state")
	chimeraAuthZState, err := h.verifyAuthorizationCompletion(r)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to verify authorization competition request")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	err = h.stateCache.DeleteState(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to cleanup authorization state")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.metricsCollector.IncAuthorizationConfirmed(c.OAuthApplication.Identifier)

	http.Redirect(w, r, chimeraAuthZState.RedirectURI, http.StatusFound)
}

func (h *Handler) handleCancelAuthorization(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger.Info("Handling request for canceling of Chimera authZ")

	state := r.URL.Query().Get("state")
	_, err := h.verifyAuthorizationCompletion(r)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to verify authorization cancellation request")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	err = h.stateCache.DeleteState(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to delete state")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h.metricsCollector.IncAuthorizationCanceled(c.OAuthApplication.Identifier)

	c.Logger.Info("Authorization canceled")
	http.ServeFile(w, r, h.cancelPagePath)
}

func (h *Handler) handleTokenExchange(c *OAuthAppContext, w http.ResponseWriter, r *http.Request) {
	c.Logger = loggerWithAppFields(c.Logger, c.OAuthApplication)
	c.Logger.Infof("Handling token exchange")

	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		c.Logger.Error("client ID and client secret not provided")
		http.Error(w, "client ID and client secret not provided", http.StatusBadRequest)
		return
	}
	// If needed we can enhance this check with some credentials specific to Proxy
	if clientID == "" || clientSecret == "" {
		c.Logger.Error("client ID or client secret not provided")
		http.Error(w, "client ID or client secret not provided", http.StatusBadRequest)
		return
	}

	scope, found := r.URL.Query()["scope"]
	if !found {
		scope = []string{}
	}
	conf := h.makeOAuthConfig(scope, c.OAuthApplication)

	err := r.ParseForm()
	if err != nil {
		c.Logger.WithError(err).Error("Failed to parse form")
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")
	if len(grantType) == 0 {
		c.Logger.Debug("Grant type not found in form, getting from query")
		grantType = r.URL.Query().Get("grant_type")
	}
	if len(grantType) == 0 {
		c.Logger.Error("Missing grant type")
		http.Error(w, "missing grant type", http.StatusBadRequest)
		return
	}
	c.Logger = c.Logger.WithField("grant_type", grantType)

	var token *oauth2.Token
	switch grantType {
	case "authorization_code":
		c.Logger.Debug("Using authorization code for token exchange")
		code := r.Form.Get("code")
		if len(code) == 0 {
			c.Logger.Debug("Authorization code not found in form, getting from query")
			code = r.URL.Query().Get("code")
		}
		if len(code) == 0 {
			c.Logger.Error("Missing authorization code")
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			return
		}

		c.Logger.Debug("Requesting token from upstream")
		token, err = conf.Exchange(context.Background(), code)
		if err != nil {
			c.Logger.WithError(err).Error("Failed to exchange token")
			http.Error(w, "failed to exchange token", http.StatusBadGateway)
			return
		}
	case "refresh_token":
		c.Logger.Debug("Using refresh token for token exchange")
		refreshToken := r.Form.Get("refresh_token")
		if len(refreshToken) == 0 {
			c.Logger.Debug("Refresh token not found in form, getting from query")
			refreshToken = r.URL.Query().Get("refresh_token")
		}
		if len(refreshToken) == 0 {
			c.Logger.Error("Missing refresh token")
			http.Error(w, "missing refresh token", http.StatusBadRequest)
			return
		}

		token = &oauth2.Token{RefreshToken: refreshToken}
		src := conf.TokenSource(context.Background(), token)

		c.Logger.Debug("Refreshing token from upstream")
		token, err = src.Token() // this actually goes and renews the tokens
		if err != nil {
			c.Logger.WithError(err).Error("Unable to get the new refreshed token")
			http.Error(w, "unable to get the new refreshed token", http.StatusBadGateway)
			return
		}
	default:
		c.Logger.Error("Invalid grant type")
		http.Error(w, "invalid grant type", http.StatusBadRequest)
		return
	}

	h.metricsCollector.IncGeneratedToken(c.OAuthApplication.Identifier)

	expiry, ok := token.Extra("expires_in").(float64)
	if !ok {
		c.Logger.Error(`Error in getting the "expires_in" field from the token`)
	}

	tokenResponse := &TokenResponse{
		ExpiresIn: expiry,
		Token:     *token,
	}

	c.Logger.Info("Responding with access token")
	writeJSON(w, tokenResponse, &Context{Logger: logrus.New()})
}

func (h *Handler) makeOAuthConfig(scope []string, app OAuthApp) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Scopes:       scope,
		Endpoint:     app.OAuthURLs.Endpoint(),
		RedirectURL:  app.OAuthURLs.RedirectURL(),
	}
}

func (h *Handler) getAuthZStateFromCache(state string) (cache.AuthorizationState, error) {
	authzState, err := h.stateCache.GetRedirectURI(state)
	if err != nil {
		if err == cache.ErrNotFound {
			return cache.AuthorizationState{}, statuserr.ErrWrap(http.StatusBadRequest, err, "state provided to webhook handler not found in cache")
		}
		return cache.AuthorizationState{}, statuserr.ErrWrap(http.StatusInternalServerError, err, "failed to get chimera authZ state from cache")
	}

	return authzState, nil
}

func (h *Handler) verifyAuthorizationCompletion(r *http.Request) (cache.AuthorizationState, error) {
	state := r.URL.Query().Get("state")
	authZVerificationTokenCookie, err := r.Cookie(chimeraAuthorizationVerificationCookie)
	if err != nil {
		return cache.AuthorizationState{}, statuserr.ErrWrap(http.StatusBadRequest, err, "chimera authZ cookie not provided")
	}

	chimeraAuthZState, err := h.getAuthZStateFromCache(state)
	if err != nil {
		return cache.AuthorizationState{}, errors.Wrap(err, "failed to get redirect URI from cache")
	}
	// If the verification token has not been set, the authorization callback from provider did not happen yet
	if chimeraAuthZState.AuthorizationVerificationToken == "" {
		return cache.AuthorizationState{}, statuserr.NewErr(http.StatusBadRequest, errors.New("attempt to confirm authorization that has not happen from provider side"))
	}

	if authZVerificationTokenCookie.Value != chimeraAuthZState.AuthorizationVerificationToken {
		return cache.AuthorizationState{}, statuserr.NewErr(http.StatusBadRequest, errors.New("authorization token from Cookie does not match the one in Chimera state"))
	}

	return chimeraAuthZState, nil
}

func (h *Handler) chimeraAuthZTokenCookie(token string) *http.Cookie {
	return &http.Cookie{Name: chimeraAuthorizationVerificationCookie, Value: token, Path: "/v1", Secure: h.useSecureCookie}
}

func validateRedirectURI(rawURL string) error {
	redirectURI, err := url.Parse(rawURL)
	if err != nil {
		return errors.Wrap(err, "failed to parse redirect_uri")
	}
	if redirectURI.Scheme != "https" && redirectURI.Scheme != "http" {
		return errors.Errorf("invalid redirect_uri schema: %s", redirectURI.Scheme)
	}
	if redirectURI.Opaque != "" {
		return errors.Errorf("redirect_uri contains opaque data: %s", rawURL)
	}
	return nil
}

func stripURLQuery(rawURL string) (string, error) {
	redirectURI, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	redirectURI.RawQuery = ""

	return redirectURI.String(), nil
}

func loggerWithAppFields(logger logrus.FieldLogger, app OAuthApp) logrus.FieldLogger {
	return logger.WithField("provider", app.Provider).
		WithField("app", app.Identifier)
}

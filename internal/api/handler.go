package api

import (
	"context"
	"fmt"
	"github.com/gorilla/csrf"
	"html/template"
	"net/http"
	"net/url"

	"github.com/mattermost/chimera/internal/cache"
	"github.com/mattermost/chimera/internal/statuserr"
	"github.com/pkg/errors"

	"github.com/gorilla/mux"
	"github.com/mattermost/chimera/internal/providers"
	"github.com/mattermost/chimera/internal/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	stateExtensionLength = 16
)

func NewHandler(appsRegistry map[string]OAuthApp, cache StateCache, baseURL, confirmFormPath, cancelPagePath string) (*Handler, error) {
	confirmForm, err := template.ParseFiles(confirmFormPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse confirmation form template")
	}

	return &Handler{
		stateCache:               cache,
		appsRegistry:             appsRegistry,
		baseURL:                  baseURL,
		confirmationFromTemplate: confirmForm,
		cancelPagePath:           cancelPagePath,
	}, nil
}

type Handler struct {
	stateCache               StateCache
	appsRegistry             map[string]OAuthApp
	baseURL                  string
	confirmationFromTemplate *template.Template
	cancelPagePath           string
}

type StateCache interface {
	GetRedirectURI(state string) (string, error)
	SetRedirectURI(state, redirectURI string) error
	DeleteState(state string) error
}

type AuthFormData struct {
	RedirectURL    string
	ConfirmAuthURL string
	ProviderName   string
	ProviderURL    string
	CancelAuthURL  string
	CsrfField template.HTML
}

func (h *Handler) handleAuthorize(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c.Logger = c.Logger.WithField("provider", app.Provider).
		WithField("app", app.Identifier)
	c.Logger.Infof("Handling authorization")

	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		c.Logger.Warn("redirect_uri not present in authorize request")
		http.Error(w, "Redirect_uri needs to be specified", http.StatusBadRequest)
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

	err := h.stateCache.SetRedirectURI(extendedState, redirectURI)
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

	conf := h.makeOAuthConfig(scope, app)

	authURL := conf.AuthCodeURL(extendedState, oauth2.AccessTypeOffline)
	c.Logger.Infof("Redirecting to auth URL")

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleAuthorizationCallback(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c.Logger = loggerWithAppFields(c.Logger, app)
	c.Logger.Info("Handling authorization callback")

	state := r.URL.Query().Get("state")

	redirectURIRaw, err := h.getRedirectURIFromCache(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get redirect URI from cache")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	redirectURI, err := url.Parse(redirectURIRaw)
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

	err = h.stateCache.SetRedirectURI(state, redirectURIStr)
	if err != nil {
		c.Logger.Error("Failed to update redirect URL in cache")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.Logger.Info("Redirecting authorization callback to confirmation")
	http.Redirect(w, r, fmt.Sprintf("%s/v1/%s/%s/auth/chimera/confirm?state=%s", h.baseURL, app.Provider, app.Identifier, state), http.StatusFound)
}

func (h *Handler) handleGetConfirmAuthorization(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c.Logger = loggerWithAppFields(c.Logger, app)
	c.Logger.Info("Handling request for confirmation of Chimera authZ")

	state := r.URL.Query().Get("state")
	fmt.Println("Handle confirm state: ", state)

	redirectURIRaw, err := h.getRedirectURIFromCache(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get redirect URI from cache")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	// Strip URL query for cleaner display
	strippedURL, err := stripURLQuery(redirectURIRaw)
	if err != nil {
		c.Logger.Error("Failed to strip query from redirect URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: we can send some cookie in response that will be required for cancellation
	// This could prevent some brute force cancellation requests.

	data := AuthFormData{
		RedirectURL:    strippedURL,
		ConfirmAuthURL: fmt.Sprintf("%s/v1/%s/%s/auth/chimera/confirm?state=%s", h.baseURL, app.Provider, app.Identifier, state),
		ProviderName:   app.Provider.DisplayName(),
		ProviderURL:    app.Provider.HomepageURL(),
		CancelAuthURL:  fmt.Sprintf("%s/v1/auth/chimera/cancel?state=%s", h.baseURL, state),
		CsrfField: csrf.TemplateField(r),
	}

	c.Logger.Info("Displaying authZ confirmation from")
	// TODO: set cookies
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	err = h.confirmationFromTemplate.Execute(w, data)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to send confirmation from")
	}
}

func (h *Handler) handleConfirmAuthorization(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c.Logger = loggerWithAppFields(c.Logger, app)
	c.Logger.Info("Handling request for confirmation of Chimera authZ")

	state := r.URL.Query().Get("state")

	redirectURIRaw, err := h.getRedirectURIFromCache(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to get redirect URI from cache")
		w.WriteHeader(statuserr.ErrToStatus(err))
		return
	}

	http.Redirect(w, r, redirectURIRaw, http.StatusFound)
}

func (h *Handler) handleCancelAuthorization(c *Context, w http.ResponseWriter, r *http.Request) {
	c.Logger.Info("Handling request for canceling of Chimera authZ")

	fmt.Println("COOKIES")
	for _, c := range r.Cookies() {
		fmt.Println(c.Name, "   ", c.Value)
	}

	state := r.URL.Query().Get("state")

	err := h.stateCache.DeleteState(state)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to delete state")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	c.Logger.Info("Authorization canceled")
	http.ServeFile(w, r, h.cancelPagePath)
}

func (h *Handler) handleTokenExchange(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	c.Logger = loggerWithAppFields(c.Logger, app)
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
	conf := h.makeOAuthConfig(scope, app)

	err := r.ParseForm()
	if err != nil {
		c.Logger.WithError(err).Error("Failed to parse form")
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if len(code) == 0 {
		fmt.Println("Getting code from query")
		code = r.URL.Query().Get("code")
	}
	if len(code) == 0 {
		c.Logger.Error("Missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to exchange token")
		http.Error(w, "failed to exchange token", http.StatusBadGateway)
		return
	}
	c.Logger.Info("Responding with access token")

	writeJSON(w, token, &Context{Logger: logrus.New()})
}

func (h *Handler) getOAuthApp(c *Context, r *http.Request) (OAuthApp, bool) {
	vars := mux.Vars(r)
	prov, found := vars["provider"]
	if !found {
		return OAuthApp{}, false
	}
	oauthProvider := providers.OAuthProvider(prov)
	if !providers.ContainsProvider(providers.ValidProviders, oauthProvider) {
		c.Logger.Warnf("Unsupported provider: %q", oauthProvider)
		return OAuthApp{}, false
	}

	appID, found := vars["app"]
	if !found {
		return OAuthApp{}, false
	}
	app, found := h.appsRegistry[appID]
	if !found {
		c.Logger.Warnf("App %q not found", appID)
		return OAuthApp{}, false
	}

	if app.Provider != oauthProvider {
		c.Logger.Warn("App ID does not match provider")
		return OAuthApp{}, false
	}

	return app, true
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

func (h *Handler) getRedirectURIFromCache(state string) (string, error) {
	redirectURIRaw, err := h.stateCache.GetRedirectURI(state)
	if err != nil {
		if err == cache.ErrNotFound {
			return "", statuserr.ErrWrap(http.StatusBadRequest, err, "state provided to webhook handler not found in cache")
		}
		return "", statuserr.ErrWrap(http.StatusInternalServerError, err, "failed to get state from cache")
	}

	return redirectURIRaw, nil
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

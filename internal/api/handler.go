package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/mattermost/chimera/internal/cache"

	"github.com/gorilla/mux"
	"github.com/mattermost/chimera/internal/providers"
	"github.com/mattermost/chimera/internal/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	stateExtensionLength = 16
)

func NewHandler(appsRegistry map[string]OAuthApp, cache StateCache) *Handler {
	return &Handler{
		stateCache:   cache,
		appsRegistry: appsRegistry,
	}
}

type Handler struct {
	stateCache   StateCache
	appsRegistry map[string]OAuthApp
}

type StateCache interface {
	GetRedirectURI(state string) (string, error)
	SetRedirectURI(state, redirectURI string) error
}

func (h *Handler) handleAuthorize(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

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

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleAuthorizationCallback(c *Context, w http.ResponseWriter, r *http.Request) {
	c.Logger.Debug("Handling authorization callback")

	state := r.URL.Query().Get("state")

	redirectURIRaw, err := h.stateCache.GetRedirectURI(state)
	if err != nil {
		if err == cache.ErrNotFound {
			c.Logger.Error("State provided to webhook handler not found")
			w.WriteHeader(http.StatusBadRequest)
		} else {
			c.Logger.Error("Failed to get state from cache")
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	redirectURI, err := url.Parse(redirectURIRaw)
	if err != nil {
		c.Logger.Error("Failed to parse destination site URL")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	originalState := state[:len(state)-stateExtensionLength]

	query := r.URL.Query()
	query.Set("state", originalState)

	redirectURI.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (h *Handler) handleTokenExchange(c *Context, w http.ResponseWriter, r *http.Request) {
	app, found := h.getOAuthApp(c, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

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
		c.Logger.Errorf("Missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := conf.Exchange(context.Background(), code)
	if err != nil {
		c.Logger.WithError(err).Errorf("Failed to exchange token")
		http.Error(w, "failed to exchange token", http.StatusBadGateway)
		return
	}

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

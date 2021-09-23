package api

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mattermost/chimera/internal/providers"

	"github.com/mattermost/chimera/internal/util"
	"github.com/sirupsen/logrus"
)

type Context struct {
	RequestID string
	Logger    logrus.FieldLogger
}

func (c *Context) Clone() *Context {
	return &Context{
		Logger: c.Logger,
	}
}

func (c *Context) Setup(r *http.Request) {
	c.RequestID = util.NewID()
	c.Logger = c.Logger.WithFields(logrus.Fields{
		"path":    r.URL.Path,
		"request": c.RequestID,
	})
}

type CtxHandlerFunc func(c *Context, w http.ResponseWriter, r *http.Request)

type contextHandler struct {
	context *Context
	handler CtxHandlerFunc
}

func addCtx(ctx *Context, handler CtxHandlerFunc) http.Handler {
	return &contextHandler{handler: handler, context: ctx}
}

func (h contextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	context := h.context.Clone()
	context.Setup(r)

	h.handler(context, w, r)
}

// OAuthAppContext is Context that includes OAuth Application.
// The application is derived from path variables on routs such as `v1/github/plugin-github/...`.
type OAuthAppContext struct {
	*Context
	OAuthApplication OAuthApp
}

type AppCtxHandlerFunc func(c *OAuthAppContext, w http.ResponseWriter, r *http.Request)

type appCtxHandler struct {
	appsRegistry map[string]OAuthApp
	context      *Context
	handler      AppCtxHandlerFunc
}

func (h appCtxHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	context := h.context.Clone()
	context.Setup(r)

	oauthApp, found := getOAuthApp(context, h.appsRegistry, r)
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	appCtx := &OAuthAppContext{context, oauthApp}

	h.handler(appCtx, w, r)
}

func addOAuthAppCtx(ctx *Context, handler AppCtxHandlerFunc, appsRegistry map[string]OAuthApp) http.Handler {
	return &appCtxHandler{handler: handler, context: ctx, appsRegistry: appsRegistry}
}

func getOAuthApp(c *Context, appsRegistry map[string]OAuthApp, r *http.Request) (OAuthApp, bool) {
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
	app, found := appsRegistry[appID]
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

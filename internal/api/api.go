package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/gorilla/csrf"

	"github.com/pkg/errors"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	BaseURL                  string
	ConfirmationTemplatePath string
	CancelPagePath           string
	CSRFSecret               []byte
}

// RegisterAPI registers the API endpoints on the given router.
func RegisterAPI(context *Context, oauthApps map[string]OAuthApp, cache StateCache, cfg Config) (*mux.Router, error) {
	rootRouter := mux.NewRouter()

	rootRouter.Handle("/metrics", promhttp.Handler())

	rootRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok"))
	})

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse base URL")
	}

	csrfHandler := csrf.Protect(cfg.CSRFSecret, csrf.Secure(useSecureCookies(baseURL)), csrf.Path("/v1"))

	v1Router := rootRouter.PathPrefix("/v1").Subrouter()

	handler, err := NewHandler(cache, baseURL, cfg.ConfirmationTemplatePath, cfg.CancelPagePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create handler")
	}

	v1Router.Handle("/auth/chimera/cancel", csrfHandler(addCtx(context.Clone(), handler.handleCancelAuthorization))).Methods(http.MethodPost)

	oauthRouter := v1Router.PathPrefix("/{provider}/{app}").Subrouter()
	oauthRouter.Handle("/oauth/authorize", addOAuthAppCtx(context.Clone(), handler.handleAuthorize, oauthApps)).Methods(http.MethodGet)
	oauthRouter.Handle("/oauth/complete", addOAuthAppCtx(context.Clone(), handler.handleAuthorizationCallback, oauthApps))
	oauthRouter.Handle("/auth/chimera/confirm", csrfHandler(addOAuthAppCtx(context.Clone(), handler.handleGetConfirmAuthorization, oauthApps))).Methods(http.MethodGet)
	oauthRouter.Handle("/auth/chimera/confirm", csrfHandler(addOAuthAppCtx(context.Clone(), handler.handleConfirmAuthorization, oauthApps))).Methods(http.MethodPost)
	oauthRouter.Handle("/oauth/token", addOAuthAppCtx(context.Clone(), handler.handleTokenExchange, oauthApps)).Methods(http.MethodPost)

	return rootRouter, nil
}

func writeJSON(w http.ResponseWriter, v interface{}, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		c.Logger.WithError(err).Error("Failed to write json response")
	}
}

func useSecureCookies(baseURL *url.URL) bool {
	if baseURL.Scheme == "http" {
		return false
	}
	return true
}

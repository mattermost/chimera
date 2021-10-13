package api

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/mattermost/chimera/internal/metrics"

	"github.com/gorilla/csrf"

	"github.com/pkg/errors"

	"github.com/gorilla/mux"
)

type Config struct {
	BaseURL                  string
	ConfirmationTemplatePath string
	CancelPagePath           string
	StylesFilePath           string
}

// RegisterAPI registers the API endpoints on the given router.
func RegisterAPI(context *Context, oauthApps map[string]OAuthApp, cache StateCache, metrics *metrics.Collector, cfg Config) (*mux.Router, error) {
	rootRouter := mux.NewRouter()
	rootRouter.Use(commonHeadersMiddleware)

	rootRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok"))
	})

	rootRouter.HandleFunc("/static/styles.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, cfg.StylesFilePath)
	})

	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse base URL")
	}

	// Secret passed to the CSRF handler is used for generating and verifying HMAC of Cookies values
	// which in case of CSRF cookies is not necessary, therefore the value is hardcoded.
	csrfHandler := csrf.Protect([]byte("not-secret"), csrf.Secure(useSecureCookies(baseURL)), csrf.Path("/v1"))

	v1Router := rootRouter.PathPrefix("/v1").Subrouter()
	v1Router.Use(metrics.MetricsMiddleware)

	handler, err := NewHandler(cache, baseURL, cfg.ConfirmationTemplatePath, cfg.CancelPagePath, metrics)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create handler")
	}

	oauthRouter := v1Router.PathPrefix("/{provider}/{app}").Subrouter()
	oauthRouter.Handle("/oauth/authorize", addOAuthAppCtx(context.Clone(), handler.handleAuthorize, oauthApps)).Methods(http.MethodGet)
	oauthRouter.Handle("/oauth/complete", addOAuthAppCtx(context.Clone(), handler.handleAuthorizationCallback, oauthApps))
	oauthRouter.Handle("/auth/chimera/confirm", csrfHandler(addOAuthAppCtx(context.Clone(), handler.handleGetConfirmAuthorization, oauthApps))).Methods(http.MethodGet)
	oauthRouter.Handle("/auth/chimera/confirm", csrfHandler(addOAuthAppCtx(context.Clone(), handler.handleConfirmAuthorization, oauthApps))).Methods(http.MethodPost)
	oauthRouter.Handle("/auth/chimera/cancel", csrfHandler(addOAuthAppCtx(context.Clone(), handler.handleCancelAuthorization, oauthApps))).Methods(http.MethodPost)
	oauthRouter.Handle("/oauth/token", addOAuthAppCtx(context.Clone(), handler.handleTokenExchange, oauthApps)).Methods(http.MethodPost)

	return rootRouter, nil
}

func commonHeadersMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; font-src fonts.gstatic.com; style-src 'self' fonts.googleapis.com")

		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v interface{}, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		c.Logger.WithError(err).Error("Failed to write json response")
	}
}

func useSecureCookies(baseURL *url.URL) bool {
	return baseURL.Scheme != "http"
}

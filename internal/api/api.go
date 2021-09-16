package api

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterAPI registers the API endpoints on the given router.
func RegisterAPI(context *Context, oauthApps map[string]OAuthApp, cache StateCache, baseURL, confirmationTemplatePath, cancelPagePath string) (*mux.Router, error) {
	rootRouter := mux.NewRouter()

	rootRouter.Handle("/metrics", promhttp.Handler())

	rootRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok"))
	})

	v1Router := rootRouter.PathPrefix("/v1").Subrouter()

	handler, err := NewHandler(oauthApps, cache, baseURL, confirmationTemplatePath, cancelPagePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create handler")
	}

	v1Router.Handle("/auth/chimera/cancel", addCtx(context.Clone(), handler.handleCancelAuthorization)).Methods(http.MethodPost)

	oauthRouter := v1Router.PathPrefix("/{provider}/{app}").Subrouter()
	oauthRouter.Handle("/oauth/authorize", addCtx(context.Clone(), handler.handleAuthorize)).Methods(http.MethodGet)
	oauthRouter.Handle("/oauth/complete", addCtx(context.Clone(), handler.handleAuthorizationCallback))
	oauthRouter.Handle("/auth/chimera/confirm", addCtx(context.Clone(), handler.handleGetConfirmAuthorization)).Methods(http.MethodGet)
	oauthRouter.Handle("/auth/chimera/confirm", addCtx(context.Clone(), handler.handleConfirmAuthorization)).Methods(http.MethodPost)
	oauthRouter.Handle("/oauth/token", addCtx(context.Clone(), handler.handleTokenExchange)).Methods(http.MethodPost)

	return rootRouter, nil
}

func writeJSON(w http.ResponseWriter, v interface{}, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		c.Logger.WithError(err).Error("Failed to write json response")
	}
}

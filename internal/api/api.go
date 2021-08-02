package api

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterAPI registers the API endpoints on the given router.
func RegisterAPI(context *Context, oauthApps map[string]OAuthApp, cache StateCache) *mux.Router {
	rootRouter := mux.NewRouter()

	rootRouter.Handle("/metrics", promhttp.Handler())

	rootRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok"))
	})

	v1Router := rootRouter.PathPrefix("/v1").Subrouter()

	handler := NewHandler(oauthApps, cache)

	oauthRouter := v1Router.PathPrefix("/{provider}/{app}").Subrouter()
	oauthRouter.Handle("/oauth/authorize", addCtx(context.Clone(), handler.handleAuthorize)).Methods(http.MethodGet)
	oauthRouter.Handle("/oauth/complete", addCtx(context.Clone(), handler.handleAuthorizationCallback))
	oauthRouter.Handle("/oauth/token", addCtx(context.Clone(), handler.handleTokenExchange)).Methods(http.MethodPost)

	return rootRouter
}

func writeJSON(w http.ResponseWriter, v interface{}, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		c.Logger.WithError(err).Error("Failed to write json response")
	}
}

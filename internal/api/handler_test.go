package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/chimera/internal/cache"
	"github.com/mattermost/chimera/internal/oauthapps"

	"github.com/mattermost/chimera/internal/providers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func Test_HandleAuthorize(t *testing.T) {
	oauthApps := map[string]OAuthApp{
		"github-plugin": {
			OAuthAppConfig: oauthapps.OAuthAppConfig{
				Identifier:   "github-plugin",
				Provider:     providers.GitHub,
				ClientID:     "abcd",
				ClientSecret: "abcd-secret",
			},
			OAuthURLs: providers.GithubOAuthProvider{},
		},
		"zoom-plugin": {
			OAuthAppConfig: oauthapps.OAuthAppConfig{
				Identifier: "zoom-plugin",
				Provider:   providers.Zoom,
			},
		},
	}

	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, cache.NewInMemoryCache(10*time.Minute), "https://chimera", "testdata/test-form.html")
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newNoRedirectsClient()

	// Authorize
	githubAppPathPrefix := fmt.Sprintf("%s/v1/github/github-plugin", server.URL)
	authURL, err := url.Parse(fmt.Sprintf("%s/oauth/authorize", githubAppPathPrefix))
	require.NoError(t, err)

	authURL.RawQuery = url.Values{
		"redirect_uri": {"http://my-mm/oauth/complete"},
		"client_id":    {"dummy-id"},
		"state":        {"some-state"},
	}.Encode()

	req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
	require.NoError(t, err)

	resp := assertRespStatus(t, client, req, http.StatusFound)

	location, err := resp.Location()
	require.NoError(t, err)
	assert.Equal(t, "github.com", location.Host)
	assert.Equal(t, "/login/oauth/authorize", location.Path)
	assert.Equal(t, "offline", location.Query().Get("access_type"))
	assert.Equal(t, "abcd", location.Query().Get("client_id"))
	assert.Equal(t, "code", location.Query().Get("response_type"))
	assert.Contains(t, location.Query().Get("state"), "some-state")
	assert.True(t, strings.HasPrefix(location.String(), "https://github.com/login/oauth/authorize"))

	t.Run("fail if no redirect_uri", func(t *testing.T) {
		authURL.RawQuery = url.Values{
			"client_id": {"dummy-id"},
			"state":     {"some-state"},
		}.Encode()

		req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusBadRequest)
	})

	t.Run("fail if to short state", func(t *testing.T) {
		authURL.RawQuery = url.Values{
			"redirect_uri": {"http://my-mm/oauth/complete"},
			"client_id":    {"dummy-id"},
			"state":        {"sta"},
		}.Encode()

		req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusBadRequest)
	})

	t.Run("404 if app does not exist", func(t *testing.T) {
		authURL := fmt.Sprintf("%s/v1/github/not-a-plugin/oauth/authorize", server.URL)

		req, err := http.NewRequest(http.MethodGet, authURL, nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusNotFound)
	})

	t.Run("404 if invalid provider", func(t *testing.T) {
		authURL := fmt.Sprintf("%s/v1/git/plugin/oauth/authorize", server.URL)

		req, err := http.NewRequest(http.MethodGet, authURL, nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusNotFound)
	})

	t.Run("404 if provider does not match app provider", func(t *testing.T) {
		authURL := fmt.Sprintf("%s/v1/zoom/github-plugin/oauth/authorize", server.URL)

		req, err := http.NewRequest(http.MethodGet, authURL, nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusNotFound)
	})
}

func Test_HandleAuthorizationCallback(t *testing.T) {
	oauthApps := map[string]OAuthApp{
		"github-plugin": {
			OAuthAppConfig: oauthapps.OAuthAppConfig{
				Identifier:   "github-plugin",
				Provider:     providers.GitHub,
				ClientID:     "abcd",
				ClientSecret: "abcd-secret",
			},
			OAuthURLs: providers.GithubOAuthProvider{},
		},
	}

	cache := cache.NewInMemoryCache(10*time.Minute)

	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, cache,"https://chimera", "testdata/test-form.html")
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	client := newNoRedirectsClient()

	// Authorize to save state in cache
	githubAppPathPrefix := fmt.Sprintf("%s/v1/github/github-plugin", server.URL)
	authURL, err := url.Parse(fmt.Sprintf("%s/oauth/authorize", githubAppPathPrefix))
	require.NoError(t, err)

	authURL.RawQuery = url.Values{
		"redirect_uri": {"http://my-mm/oauth/complete"},
		"client_id":    {"dummy-id"},
		"state":        {"some-state"},
	}.Encode()

	req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
	require.NoError(t, err)
	resp := assertRespStatus(t, client, req, http.StatusFound)

	location, err := resp.Location()
	require.NoError(t, err)
	state := location.Query().Get("state")

	// Make Auth callback
	callbackURL, err := url.Parse(fmt.Sprintf("%s/oauth/complete", githubAppPathPrefix))
	require.NoError(t, err)

	callbackURL.RawQuery = url.Values{
		"state":              {state},
		"authorization_code": {"abcd-code"},
	}.Encode()

	req, err = http.NewRequest(http.MethodGet, callbackURL.String(), nil)
	require.NoError(t, err)
	resp = assertRespStatus(t, client, req, http.StatusFound)

	location, err = resp.Location()
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(location.String(),"https://chimera/v1/auth/chimera/confirm?state=some-state"))

	redirectURIRaw, err := cache.GetRedirectURI(location.Query().Get("state"))
	require.NoError(t, err)
	redirectURI, err := url.Parse(redirectURIRaw)
	require.NoError(t, err)
	assert.Equal(t, "abcd-code", redirectURI.Query().Get("authorization_code"))
	assert.Equal(t, "some-state", redirectURI.Query().Get("state"))

	t.Run("return 400 when state is invalid", func(t *testing.T) {
		callbackURL.RawQuery = url.Values{
			"state":              {"invalid-state"},
			"authorization_code": {"abcd-code"},
		}.Encode()

		req, err = http.NewRequest(http.MethodGet, callbackURL.String(), nil)
		require.NoError(t, err)
		_ = assertRespStatus(t, client, req, http.StatusBadRequest)
	})
}

// TODO: test for confirmation page

type mockOAuthURLs struct {
	tokenURL string
}

func (m mockOAuthURLs) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  "",
		TokenURL: m.tokenURL,
	}
}

func (m mockOAuthURLs) RedirectURL() string { return "" }

func Test_HandleExchangeToken(t *testing.T) {
	mockURLs := &mockOAuthURLs{}

	oauthApps := map[string]OAuthApp{
		"github-plugin": {
			OAuthAppConfig: oauthapps.OAuthAppConfig{
				Identifier:   "github-plugin",
				Provider:     providers.GitHub,
				ClientID:     "abcd",
				ClientSecret: "abcd-secret",
			},
			OAuthURLs: mockURLs,
		},
	}

	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, cache.NewInMemoryCache(10*time.Minute), "https://chimera", "testdata/test-form.html")
	require.NoError(t, err)
	router.HandleFunc("/mock-token", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(`{"access_token":"abcd-access-token"}`))
	})

	server := httptest.NewServer(router)
	defer server.Close()

	mockURLs.tokenURL = fmt.Sprintf("%s/mock-token", server.URL)

	proxyTokenURL := fmt.Sprintf("%s/v1/github/github-plugin/oauth/token", server.URL)

	oauthConfig := oauth2.Config{
		ClientID:     "client",
		ClientSecret: "client",
		Endpoint: oauth2.Endpoint{
			TokenURL:  proxyTokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes: []string{"test"},
	}

	token, err := oauthConfig.Exchange(context.Background(), "abcd-auth-code", oauth2.AccessTypeOffline)
	require.NoError(t, err)
	assert.Equal(t, "abcd-access-token", token.AccessToken)

	t.Run("return 400 if client ID and secret not provided", func(t *testing.T) {
		oauthConfig := oauth2.Config{
			ClientID:     "",
			ClientSecret: "",
			Endpoint: oauth2.Endpoint{
				TokenURL:  proxyTokenURL,
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			Scopes: []string{"test"},
		}

		_, err := oauthConfig.Exchange(context.Background(), "abcd-auth-code", oauth2.AccessTypeOffline)
		require.Error(t, err)
	})

	t.Run("return 400 if missing auth code", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, proxyTokenURL, nil)
		require.NoError(t, err)
		req.SetBasicAuth("test", "test")

		_ = assertRespStatus(t, http.DefaultClient, req, http.StatusBadRequest)
	})
}

func newNoRedirectsClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func assertRespStatus(t *testing.T, client *http.Client, req *http.Request, status int) *http.Response {
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, status, resp.StatusCode)
	return resp
}

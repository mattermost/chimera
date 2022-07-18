package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/chimera/internal/metrics"

	"golang.org/x/net/html"

	"github.com/mattermost/chimera/internal/cache"
	"github.com/mattermost/chimera/internal/oauthapps"

	prommodel "github.com/prometheus/client_model/go"

	"github.com/mattermost/chimera/internal/providers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	gorillaCSRFCookie = "_gorilla_csrf"
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

	cfg := Config{
		BaseURL:                  "https://chimera",
		ConfirmationTemplatePath: "testdata/test-form.html",
	}
	metricsCollector := metrics.NewCollector(logrus.New())

	stateCache := cache.NewInMemoryCache(10 * time.Minute)
	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, stateCache, metricsCollector, cfg)
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

	// Request Chimera authorization expecting success
	location := requestChimeraAuthorization(t, authURL.String(), client)

	extendedStateToken := location.Query().Get("state")
	authZState, err := stateCache.GetRedirectURI(extendedStateToken)
	require.NoError(t, err)

	// Assert authorization state
	assert.Equal(t, "http://my-mm/oauth/complete", authZState.RedirectURI)
	assert.Empty(t, authZState.AuthorizationVerificationToken)

	// Assert redirect URI
	assert.Equal(t, "github.com", location.Host)
	assert.Equal(t, "/login/oauth/authorize", location.Path)
	assert.Equal(t, "offline", location.Query().Get("access_type"))
	assert.Equal(t, "abcd", location.Query().Get("client_id"))
	assert.Equal(t, "code", location.Query().Get("response_type"))
	assert.Contains(t, location.Query().Get("state"), "some-state")
	assert.True(t, strings.HasPrefix(location.String(), "https://github.com/login/oauth/authorize"))

	t.Run("invalid redirect_uri", func(t *testing.T) {
		for _, testCase := range []struct {
			description string
			redirectURI string
		}{
			{
				description: "invalid URL",
				redirectURI: "http://not valid.com",
			},
			{
				description: "invalid schema",
				redirectURI: "ssh://my-mm.com",
			},
			{
				description: "contains opaque char",
				redirectURI: "https:\\u0020my-mm.com",
			},
		} {
			t.Run(testCase.description, func(t *testing.T) {
				authURL.RawQuery = url.Values{
					"redirect_uri": {testCase.redirectURI},
					"client_id":    {"dummy-id"},
					"state":        {"some-state"},
				}.Encode()

				req, err := http.NewRequest(http.MethodGet, authURL.String(), nil)
				require.NoError(t, err)
				assertRespStatus(t, client, req, http.StatusBadRequest)
			})
		}
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

	t.Run("assert metrics recorded", func(t *testing.T) {
		metricRecords, err := metricsCollector.Registry.Gather()
		require.NoError(t, err)

		assertCounterMetric(t,
			metricRecords,
			"chimera_http_response_status",
			map[string]string{"method": "GET", "path": "/v1/github/github-plugin/oauth/authorize", "status": "302"},
			1,
		)
		assertHistogramMetricObserved(t,
			metricRecords,
			"chimera_http_response_time_seconds",
			map[string]string{"method": "GET", "path": "/v1/github/github-plugin/oauth/authorize"},
		)

		assertCounterMetric(t,
			metricRecords,
			"chimera_app_authorization_request_count",
			map[string]string{"app": "github-plugin"},
			1,
		)
	})
}

func Test_HandleFullAuthorization(t *testing.T) {
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

	stateCache := cache.NewInMemoryCache(10 * time.Minute)
	server := httptest.NewUnstartedServer(nil)
	metricsCollector := metrics.NewCollector(logrus.New())

	cfg := Config{
		BaseURL:                  fmt.Sprintf("http://%s", server.Listener.Addr().String()),
		ConfirmationTemplatePath: "testdata/test-form.html",
		CancelPagePath:           "testdata/test-cancel-page.html",
	}

	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, stateCache, metricsCollector, cfg)
	require.NoError(t, err)
	server.Config = &http.Server{Handler: router}
	server.Start()
	defer server.Close()

	client := newNoRedirectsClient()

	// To avoid duplicating logic for all initial steps, this parametrizes test running either
	// authorization confirmation or cancellation at the end.
	for _, testCase := range []struct {
		description          string
		initialOAuthState    string
		finalizationFunction func(confirmURL, cancelURL *url.URL, csrfToken string, cookies map[string]*http.Cookie)
	}{
		{
			description:       "confirm authorization",
			initialOAuthState: "some-state",
			finalizationFunction: func(confirmURL, cancelURL *url.URL, csrfToken string, cookies map[string]*http.Cookie) {
				csrfTokenCookie := cookies[gorillaCSRFCookie]
				authZVerificationTokenCookie := cookies[chimeraAuthorizationVerificationCookie]

				// Handle Confirm Authorization
				t.Run("failed to confirm AuthZ without CSRF token", func(t *testing.T) {
					req, err := http.NewRequest(http.MethodPost, confirmURL.String(), nil)
					require.NoError(t, err)
					req.AddCookie(authZVerificationTokenCookie)
					assertRespStatus(t, client, req, http.StatusForbidden)
				})
				t.Run("failed to cancel AuthZ without CSRF token", func(t *testing.T) {
					req, err := http.NewRequest(http.MethodPost, cancelURL.String(), nil)
					require.NoError(t, err)
					req.AddCookie(authZVerificationTokenCookie)
					assertRespStatus(t, client, req, http.StatusForbidden)
				})
				t.Run("failed to confirm AuthZ without AuthZ Verification token", func(t *testing.T) {
					req, err := http.NewRequest(http.MethodPost, confirmURL.String(), nil)
					require.NoError(t, err)
					setCSRF(req, csrfTokenCookie, csrfToken)
					assertRespStatus(t, client, req, http.StatusBadRequest)
				})
				t.Run("failed to cancel AuthZ without AuthZ Verification token", func(t *testing.T) {
					req, err := http.NewRequest(http.MethodPost, cancelURL.String(), nil)
					require.NoError(t, err)
					setCSRF(req, csrfTokenCookie, csrfToken)
					assertRespStatus(t, client, req, http.StatusBadRequest)
				})

				req, err := http.NewRequest(http.MethodPost, confirmURL.String(), nil)
				require.NoError(t, err)
				setCSRF(req, csrfTokenCookie, csrfToken)
				req.AddCookie(authZVerificationTokenCookie)
				resp := assertRespStatus(t, client, req, http.StatusFound)
				assertRedirectLocation(t, resp, "http://my-mm/oauth/complete?authorization_code=abcd-code&state=some-state")

				t.Run("fail to confirm second time - authz state should be deleted", func(t *testing.T) {
					assertRespStatus(t, client, req, http.StatusBadRequest)
				})
			},
		},
		{
			description:       "cancel authorization",
			initialOAuthState: "some-state-cancel",
			finalizationFunction: func(confirmURL, cancelURL *url.URL, csrfToken string, cookies map[string]*http.Cookie) {
				csrfTokenCookie := cookies[gorillaCSRFCookie]
				authZVerificationTokenCookie := cookies[chimeraAuthorizationVerificationCookie]

				// Handle Cancel Authorization
				req, err := http.NewRequest(http.MethodPost, cancelURL.String(), nil)
				require.NoError(t, err)
				setCSRF(req, csrfTokenCookie, csrfToken)
				req.AddCookie(authZVerificationTokenCookie)
				resp := assertRespStatus(t, client, req, http.StatusOK)

				body, err := ioutil.ReadAll(resp.Body)
				require.NoError(t, err)
				assert.Equal(t, "Cancel Page", string(body))

				t.Run("fail to confirm after already cancelled", func(t *testing.T) {
					req, err = http.NewRequest(http.MethodPost, confirmURL.String(), nil)
					require.NoError(t, err)
					setCSRF(req, csrfTokenCookie, csrfToken)
					req.AddCookie(authZVerificationTokenCookie)
					assertRespStatus(t, client, req, http.StatusBadRequest)
				})
			},
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			githubAppPathPrefix := fmt.Sprintf("%s/v1/github/github-plugin", server.URL)
			authURL, err := url.Parse(fmt.Sprintf("%s/oauth/authorize", githubAppPathPrefix))
			require.NoError(t, err)

			authURL.RawQuery = url.Values{
				"redirect_uri": {"http://my-mm/oauth/complete"},
				"client_id":    {"dummy-id"},
				"state":        {testCase.initialOAuthState},
			}.Encode()

			// Request Chimera authorization expecting success
			location := requestChimeraAuthorization(t, authURL.String(), client)

			extendedStateToken := location.Query().Get("state")

			// Make Auth callback
			callbackURL, err := url.Parse(fmt.Sprintf("%s/oauth/complete", githubAppPathPrefix))
			require.NoError(t, err)

			callbackURL.RawQuery = url.Values{
				"state":              {extendedStateToken},
				"authorization_code": {"abcd-code"},
			}.Encode()

			req, err := http.NewRequest(http.MethodGet, callbackURL.String(), nil)
			require.NoError(t, err)
			resp := assertRespStatus(t, client, req, http.StatusFound)

			authConfirmURL, err := resp.Location()
			require.NoError(t, err)
			assert.Equal(t, authConfirmURL.String(), fmt.Sprintf("%s/v1/github/github-plugin/auth/chimera/confirm?state=%s", server.URL, extendedStateToken))

			// Assert Redirect URI was updated and Authorization Verification Token set.
			chimeraAuthZState, err := stateCache.GetRedirectURI(extendedStateToken)
			require.NoError(t, err)
			assert.NotEmpty(t, chimeraAuthZState.AuthorizationVerificationToken)
			redirectURI, err := url.Parse(chimeraAuthZState.RedirectURI)
			require.NoError(t, err)
			assert.Equal(t, "abcd-code", redirectURI.Query().Get("authorization_code"))
			assert.Equal(t, testCase.initialOAuthState, redirectURI.Query().Get("state"))

			t.Run("return 400 when state is invalid", func(t *testing.T) {
				callbackURL.RawQuery = url.Values{
					"state":              {"invalid-state"},
					"authorization_code": {"abcd-code"},
				}.Encode()

				req, err = http.NewRequest(http.MethodGet, callbackURL.String(), nil)
				require.NoError(t, err)
				_ = assertRespStatus(t, client, req, http.StatusBadRequest)
			})

			// Handle Ask for Authorization Confirmation
			req, err = http.NewRequest(http.MethodGet, authConfirmURL.String(), nil)
			require.NoError(t, err)
			resp = assertRespStatus(t, client, req, http.StatusOK)
			assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
			confirmAuthCookies := getCookiesMap(resp.Cookies())
			assert.Equal(t, chimeraAuthZState.AuthorizationVerificationToken, confirmAuthCookies[chimeraAuthorizationVerificationCookie].Value)
			assert.NotEmpty(t, confirmAuthCookies[gorillaCSRFCookie].Value)

			authForm, err := ioutil.ReadAll(resp.Body)
			require.NoError(t, err)

			authFormParams := strings.Split(string(authForm), "\n")
			assert.Len(t, authFormParams, 6)
			assert.Equal(t, "http://my-mm/oauth/complete", authFormParams[0])

			confirmURL, err := url.Parse(authFormParams[1])
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("%s/v1/github/github-plugin/auth/chimera/confirm?state=%s", server.URL, extendedStateToken), confirmURL.String())

			assert.Equal(t, "GitHub", authFormParams[2])
			assert.Equal(t, "https://github.com", authFormParams[3])

			cancelURL, err := url.Parse(authFormParams[4])
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("%s/v1/github/github-plugin/auth/chimera/cancel?state=%s", server.URL, extendedStateToken), cancelURL.String())

			csrfField := authFormParams[5]
			csrfToken := extractCSRFToken(t, csrfField)
			assert.NotEmpty(t, csrfToken)

			// Run Authorization finalization
			testCase.finalizationFunction(confirmURL, cancelURL, csrfToken, confirmAuthCookies)
		})
	}

	// Requires both tests in a table to run.
	metricRecords, err := metricsCollector.Registry.Gather()
	require.NoError(t, err)

	assertCounterMetric(t,
		metricRecords,
		"chimera_app_authorization_confirmations_count",
		map[string]string{"app": "github-plugin"},
		1,
	)
	assertCounterMetric(t,
		metricRecords,
		"chimera_app_authorization_cancellations_count",
		map[string]string{"app": "github-plugin"},
		1,
	)
}

// requestChimeraAuthorization requests initial Chimera authorization and returns redirection location.
func requestChimeraAuthorization(t *testing.T, authURL string, client *http.Client) *url.URL {
	req, err := http.NewRequest(http.MethodGet, authURL, nil)
	require.NoError(t, err)
	resp := assertRespStatus(t, client, req, http.StatusFound)

	location, err := resp.Location()
	require.NoError(t, err)

	return location
}

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
	startTime := time.Now()

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
	metricsCollector := metrics.NewCollector(logrus.New())

	cfg := Config{
		BaseURL:                  "https://chimera",
		ConfirmationTemplatePath: "testdata/test-form.html",
	}

	router, err := RegisterAPI(&Context{Logger: logrus.New()}, oauthApps, cache.NewInMemoryCache(10*time.Minute), metricsCollector, cfg)
	require.NoError(t, err)
	router.HandleFunc("/mock-token", func(writer http.ResponseWriter, request *http.Request) {
		resp := []byte(`{"access_token":"abcd-access-token", "expires_in": 10000, "refresh_token": "abcd-refresh"}`)

		err = request.ParseForm()
		require.NoError(t, err)

		grantType := request.Form.Get("grant_type")
		if grantType == "refresh_token" {
			resp = []byte(`{"access_token":"refreshed-access-token", "expires_in": 1000, "refresh_token": "abcd-refresh"}`)
		}

		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		writer.Write(resp)
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
	assert.Equal(t, "abcd-refresh", token.RefreshToken)
	assert.True(t, token.Expiry.Sub(startTime) >= time.Duration(10000)*time.Second) // expires_in is set to 10000, so we expect at least that much time

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

	t.Run("return 400 if grant type is missing", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, proxyTokenURL, nil)
		require.NoError(t, err)
		req.SetBasicAuth("test", "test")

		_ = assertRespStatus(t, http.DefaultClient, req, http.StatusBadRequest)
	})

	t.Run("return 400 if grant type is invalid", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"abcd"},
		}
		req, err := http.NewRequest(http.MethodPost, proxyTokenURL, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, err)
		req.SetBasicAuth("test", "test")

		_ = assertRespStatus(t, http.DefaultClient, req, http.StatusBadRequest)
	})

	t.Run("return 400 if grant type is refresh_token but refresh token is missing", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"refresh_token"},
		}
		req, err := http.NewRequest(http.MethodPost, proxyTokenURL, strings.NewReader(form.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		require.NoError(t, err)
		req.SetBasicAuth("test", "test")

		_ = assertRespStatus(t, http.DefaultClient, req, http.StatusBadRequest)
	})

	t.Run("return 200 if grant type is refresh_token and refresh token is present", func(t *testing.T) {
		startTime := time.Now()

		// Copy the token and erase AccessToken so that tokenSource.Token()
		// actually refreshes the token.
		tokenToRefresh := *token
		tokenToRefresh.AccessToken = ""

		tokenSrc := oauthConfig.TokenSource(context.Background(), &tokenToRefresh)

		token, err = tokenSrc.Token()
		require.NoError(t, err)
		assert.Equal(t, "refreshed-access-token", token.AccessToken)
		assert.Equal(t, "abcd-refresh", token.RefreshToken)
		assert.True(t, token.Expiry.Sub(startTime) >= time.Duration(1000)*time.Second) // expires_in is set to 1000, so we expect at least that much time
	})

	t.Run("assert metrics recorded", func(t *testing.T) {
		metricRecords, err := metricsCollector.Registry.Gather()
		require.NoError(t, err)

		assertCounterMetric(t,
			metricRecords,
			"chimera_http_response_status",
			map[string]string{"method": "POST", "path": "/v1/github/github-plugin/oauth/token", "status": "200"},
			2,
		)
		assertHistogramMetricObserved(t,
			metricRecords,
			"chimera_http_response_time_seconds",
			map[string]string{"method": "POST", "path": "/v1/github/github-plugin/oauth/token"},
		)
		assertCounterMetric(t,
			metricRecords,
			"chimera_app_generated_tokens_count",
			map[string]string{"app": "github-plugin"},
			2,
		)
	})
}

func newNoRedirectsClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func getCookiesMap(cookies []*http.Cookie) map[string]*http.Cookie {
	cookieMap := make(map[string]*http.Cookie)
	for _, c := range cookies {
		cookieMap[c.Name] = c
	}
	return cookieMap
}

func assertRespStatus(t *testing.T, client *http.Client, req *http.Request, status int) *http.Response {
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, status, resp.StatusCode)
	return resp
}

func assertRedirectLocation(t *testing.T, resp *http.Response, expectedLocation string) {
	location, err := resp.Location()
	require.NoError(t, err)
	assert.Equal(t, expectedLocation, location.String())
}

// This extracts 'value' attribute from HTML tag.
func extractCSRFToken(t *testing.T, htmlNode string) string {
	reader := strings.NewReader(htmlNode)
	tokenizer := html.NewTokenizer(reader)

	tt := tokenizer.Next()
	if tt == html.ErrorToken {
		t.Fatalf("csrf token not found in input")
	}
	_, hasAttr := tokenizer.TagName()
	for hasAttr {
		attrKey, attrValue, moreAttr := tokenizer.TagAttr()
		if string(attrKey) == "value" {
			return string(attrValue)
		}
		hasAttr = moreAttr
	}

	t.Fatalf("csrf token not found in input")
	return ""
}

func setCSRF(r *http.Request, cookie *http.Cookie, csrfToken string) {
	r.AddCookie(cookie)
	r.Header.Set("X-CSRF-Token", csrfToken)
}

// Metrics test helpers

func assertHistogramMetricObserved(t *testing.T, records []*prommodel.MetricFamily, name string, labels map[string]string) {
	metric := getMetric(t, records, name, labels)
	require.NotNil(t, metric.Histogram.SampleCount)
	assert.True(t, *metric.Histogram.SampleCount > 0)
}

func assertCounterMetric(t *testing.T, records []*prommodel.MetricFamily, name string, labels map[string]string, value float64) {
	metric := getMetric(t, records, name, labels)
	require.NotNil(t, metric.Counter.Value)
	assert.Equal(t, value, *metric.Counter.Value)
}

func getMetric(t *testing.T, records []*prommodel.MetricFamily, name string, labels map[string]string) *prommodel.Metric {
	metricFamily := getMetricFamily(records, name)
	require.NotNil(t, metricFamily)
	metric := getMetricMatchingLabels(metricFamily.Metric, labels)
	require.NotNil(t, metricFamily)
	return metric
}

func getMetricFamily(records []*prommodel.MetricFamily, name string) *prommodel.MetricFamily {
	for _, r := range records {
		if *r.Name == name {
			return r
		}
	}
	return nil
}

// getMetricMatchingLabels returns metric that matches all labels or nil.
func getMetricMatchingLabels(allMetrics []*prommodel.Metric, labels map[string]string) *prommodel.Metric {
	for _, m := range allMetrics {
		metricLabels := m.GetLabel()
		toFind := len(labels)
		for _, ml := range metricLabels {
			if labels[*ml.Name] == *ml.Value {
				toFind--
			}
		}
		if toFind == 0 {
			return m
		}
	}
	return nil
}

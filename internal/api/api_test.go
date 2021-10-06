package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/chimera/internal/metrics"

	"github.com/mattermost/chimera/internal/cache"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_HealthCheck(t *testing.T) {
	router := registerTestAPI(t)
	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/health", server.URL))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	assertCommonHeaders(t, resp)
}

func Test_Static(t *testing.T) {
	router := registerTestAPI(t)
	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/static/styles.css", server.URL))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	content, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "div { }", string(content))

	assertCommonHeaders(t, resp)
}

func assertCommonHeaders(t *testing.T, resp *http.Response) {
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'; font-src fonts.gstatic.com; style-src 'self' fonts.googleapis.com", resp.Header.Get("Content-Security-Policy"))
}

func registerTestAPI(t *testing.T) *mux.Router {
	router, err := RegisterAPI(
		&Context{Logger: logrus.New()},
		map[string]OAuthApp{},
		cache.NewInMemoryCache(10*time.Minute),
		metrics.NewCollector(logrus.New()),
		Config{ConfirmationTemplatePath: "testdata/test-form.html", StylesFilePath: "testdata/styles.css"})
	require.NoError(t, err)
	return router
}

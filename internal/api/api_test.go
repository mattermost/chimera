package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mattermost/chimera/internal/cache"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPI_HealthCheck(t *testing.T) {
	router := RegisterAPI(&Context{Logger: logrus.New()}, map[string]OAuthApp{}, cache.NewInMemoryCache(10*time.Minute))
	server := httptest.NewServer(router)
	defer server.Close()

	resp, err := http.Get(fmt.Sprintf("%s/health", server.URL))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

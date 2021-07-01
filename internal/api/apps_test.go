package api

import (
	"testing"

	"github.com/mattermost/chimera/internal/oauthapps"
	"github.com/mattermost/chimera/internal/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthAppsFromConfig(t *testing.T) {

	config := []oauthapps.OAuthAppConfig{
		{
			Identifier:   "plugin-github",
			ClientID:     "gh-client",
			ClientSecret: "gh-secret",
			Provider:     providers.GitHub,
		},
		{
			Identifier:   "plugin-zoom",
			ClientID:     "z-client",
			ClientSecret: "z-secret",
			Provider:     providers.Zoom,
		},
		{
			Identifier:   "plugin-gitlab",
			ClientID:     "gl-client",
			ClientSecret: "gl-secret",
			Provider:     providers.GitLab,
		},
	}

	oauthApps, err := OAuthAppsFromConfig(config, "http://localhost:1234")
	require.NoError(t, err)

	githubApp, found := oauthApps["plugin-github"]
	require.True(t, found)
	assertConfigMatchApp(t, config[0], githubApp)
	_, ok := githubApp.OAuthURLs.(providers.GithubOAuthProvider)
	require.True(t, ok)

	zoomApp, found := oauthApps["plugin-zoom"]
	require.True(t, found)
	assertConfigMatchApp(t, config[1], zoomApp)
	_, ok = zoomApp.OAuthURLs.(providers.ZoomOAuthProvider)
	require.True(t, ok)

	gitlabApp, found := oauthApps["plugin-gitlab"]
	require.True(t, found)
	assertConfigMatchApp(t, config[2], gitlabApp)
	_, ok = gitlabApp.OAuthURLs.(providers.GitLabOAuthProvider)
	require.True(t, ok)
}

func assertConfigMatchApp(t *testing.T, config oauthapps.OAuthAppConfig, app OAuthApp) {
	assert.Equal(t, config.ClientID, app.ClientID)
	assert.Equal(t, config.ClientSecret, app.ClientSecret)
	assert.Equal(t, config.ExtraData, app.ExtraData)
	assert.Equal(t, config.Provider, app.Provider)
}

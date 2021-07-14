package oauthapps

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/mattermost/chimera/internal/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConfig = `{
  "apps": [
    {
      "identifier": "plugin-github",
      "clientID": "github-client-id",
      "clientSecret": "github-client-secret",
      "provider": "github"
    },
    {
      "identifier": "plugin-zoom-user-level",
      "clientID": "zoom-client-id",
      "clientSecret": "zoom-client-secret",
      "provider": "zoom"
    },
    {
      "identifier": "plugin-gitlab",
      "clientID": "gitlab-client-id",
      "clientSecret": "gitlab-client-secret",
      "provider": "gitlab"
    }
  ]
}`

func TestNewAppsConfigFromFile(t *testing.T) {
	file, err := ioutil.TempFile("", "apps_config.json")
	require.NoError(t, err)
	defer os.Remove(file.Name())

	_, err = file.Write([]byte(testConfig))
	require.NoError(t, err)

	cfg, err := NewAppsConfigFromFile(file.Name())
	require.NoError(t, err)

	expectedCfg := AppsConfig{
		Apps: []OAuthAppConfig{
			{
				Identifier:   "plugin-github",
				ClientID:     "github-client-id",
				ClientSecret: "github-client-secret",
				Provider:     providers.GitHub,
			},
			{
				Identifier:   "plugin-zoom-user-level",
				ClientID:     "zoom-client-id",
				ClientSecret: "zoom-client-secret",
				Provider:     providers.Zoom,
			},
			{
				Identifier:   "plugin-gitlab",
				ClientID:     "gitlab-client-id",
				ClientSecret: "gitlab-client-secret",
				Provider:     providers.GitLab,
			},
		},
	}

	assert.Equal(t, expectedCfg, cfg)
}

func TestConfig_Validate_Ok(t *testing.T) {
	for _, testCase := range []struct {
		description string
		provider    string
	}{
		{
			description: "github provider",
			provider:    "github",
		},
		{
			description: "zoom provider",
			provider:    "zoom",
		},
		{
			description: "gitlab provider",
			provider:    "gitlab",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			cfg := AppsConfig{Apps: []OAuthAppConfig{
				{
					Identifier:   "github-plugin",
					ClientID:     "abcd",
					ClientSecret: "vxyz",
					Provider:     providers.OAuthProvider(testCase.provider),
				},
			}}
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}

func TestConfig_Validate_Err(t *testing.T) {
	for _, testCase := range []struct {
		description   string
		config        AppsConfig
		errorContains string
	}{
		{
			description: "unsupported provider",
			config: AppsConfig{
				Apps: []OAuthAppConfig{
					{
						Identifier:   "github-plugin",
						ClientID:     "abcd",
						ClientSecret: "vxyz",
						Provider:     "githuuub",
					},
				},
			},
			errorContains: "invalid provider",
		},
		{
			description: "credentials not provided",
			config: AppsConfig{
				Apps: []OAuthAppConfig{
					{
						Identifier:   "github-plugin",
						ClientID:     "",
						ClientSecret: "",
						Provider:     "github",
					},
				},
			},
			errorContains: "some credentials not specified for app",
		},
		{
			description: "no unique identifier",
			config: AppsConfig{
				Apps: []OAuthAppConfig{
					{
						Identifier:   "plugin",
						ClientID:     "abcd",
						ClientSecret: "vxyz",
						Provider:     "github",
					},
					{
						Identifier:   "plugin",
						ClientID:     "abcd",
						ClientSecret: "vxyz",
						Provider:     "zoom",
					},
				},
			},
			errorContains: "app identifier \"plugin\" is not unique",
		},
		{
			description: "empty identifier",
			config: AppsConfig{
				Apps: []OAuthAppConfig{
					{
						Identifier:   "",
						ClientID:     "abcd",
						ClientSecret: "vxyz",
						Provider:     "github",
					},
				},
			},
			errorContains: "app identifier cannot be empty",
		},
		{
			description: "identifier not path compatible",
			config: AppsConfig{
				Apps: []OAuthAppConfig{
					{
						Identifier:   "some invalid identifier",
						ClientID:     "abcd",
						ClientSecret: "vxyz",
						Provider:     "github",
					},
				},
			},
			errorContains: "app identifier must be path compatible",
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			err := testCase.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.errorContains)
		})
	}
}

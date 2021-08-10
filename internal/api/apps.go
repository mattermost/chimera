package api

import (
	"fmt"

	"github.com/mattermost/chimera/internal/oauthapps"
	"github.com/mattermost/chimera/internal/providers"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	zoomRedirectFormat      = "%s/v1/zoom/%s/oauth/complete"
	gitLabRedirectFormat    = "%s/v1/gitlab/%s/oauth/complete"
	microsoftRedirectFormat = "%s/v1/microsoft/%s/oauth/complete"
)

type OAuthApp struct {
	oauthapps.OAuthAppConfig
	OAuthURLs
}

type OAuthURLs interface {
	Endpoint() oauth2.Endpoint
	RedirectURL() string
}

func OAuthAppsFromConfig(appsConfig []oauthapps.OAuthAppConfig, baseURL string) (map[string]OAuthApp, error) {
	oauthApps := make(map[string]OAuthApp, len(appsConfig))
	for _, app := range appsConfig {
		urls, err := NewOAuthURLs(app.Provider, app.Identifier, baseURL, app.ExtraData)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create OAuth URLs from app config")
		}

		oauthApps[app.Identifier] = OAuthApp{
			OAuthAppConfig: app,
			OAuthURLs:      urls,
		}
	}

	return oauthApps, nil
}

func NewOAuthURLs(provider providers.OAuthProvider, appIdentifier, baseURL string, extraData map[string]interface{}) (OAuthURLs, error) {
	switch provider {
	case providers.GitHub:
		return providers.GithubOAuthProvider{}, nil
	case providers.Zoom:
		return providers.NewZoomOAuthProvider(fmt.Sprintf(zoomRedirectFormat, baseURL, appIdentifier)), nil
	case providers.GitLab:
		return providers.NewGitLabOAuthProvider(fmt.Sprintf(gitLabRedirectFormat, baseURL, appIdentifier)), nil
	case providers.Microsoft:
		tenantID := ""
		if extraData != nil {
			var ok bool
			tenantID, ok = extraData["tenant"].(string)
			if ok {
				return nil, fmt.Errorf("microsoft tenant is not a string in %q app", appIdentifier)
			}
		}

		return providers.NewMicrosoftOAuthProvider(tenantID, fmt.Sprintf(microsoftRedirectFormat, baseURL, appIdentifier)), nil
	}

	return nil, fmt.Errorf("invalid provider %q", provider)
}

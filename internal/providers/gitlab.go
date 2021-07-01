package providers

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/gitlab"
)

type GitLabOAuthProvider struct {
	redirectURI string
}

func NewGitLabOAuthProvider(redirectURI string) GitLabOAuthProvider {
	return GitLabOAuthProvider{
		redirectURI: redirectURI,
	}
}

func (g GitLabOAuthProvider) Endpoint() oauth2.Endpoint {
	return gitlab.Endpoint
}

func (g GitLabOAuthProvider) RedirectURL() string {
	return g.redirectURI
}

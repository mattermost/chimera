package providers

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GithubOAuthProvider struct{}

func (g GithubOAuthProvider) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (g GithubOAuthProvider) RedirectURL() string {
	return ""
}

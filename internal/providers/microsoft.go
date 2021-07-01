package providers

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type MicrosoftOAuthProvider struct {
	redirectURI string
	tenantID    string
}

func NewMicrosoftOAuthProvider(tenantID, redirectURI string) MicrosoftOAuthProvider {
	return MicrosoftOAuthProvider{
		redirectURI: redirectURI,
		tenantID:    tenantID,
	}
}

func (m MicrosoftOAuthProvider) Endpoint() oauth2.Endpoint {
	return microsoft.AzureADEndpoint(m.tenantID)
}

func (m MicrosoftOAuthProvider) RedirectURL() string {
	return m.redirectURI
}

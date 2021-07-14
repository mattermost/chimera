package providers

import (
	"fmt"

	"golang.org/x/oauth2"
)

const zoomBaseURL = "https://zoom.us"

func zoomAuthURL() string {
	return fmt.Sprintf("%s/%s/%s", zoomBaseURL, "oauth", "authorize")
}
func zoomTokenURL() string {
	return fmt.Sprintf("%s/%s/%s", zoomBaseURL, "oauth", "token")
}

type ZoomOAuthProvider struct {
	redirectURI string
}

func NewZoomOAuthProvider(redirectURI string) ZoomOAuthProvider {
	return ZoomOAuthProvider{
		redirectURI: redirectURI,
	}
}

func (z ZoomOAuthProvider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:   zoomAuthURL(),
		TokenURL:  zoomTokenURL(),
		AuthStyle: oauth2.AuthStyleInHeader,
	}
}

func (z ZoomOAuthProvider) RedirectURL() string {
	return z.redirectURI
}

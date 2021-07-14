package providers

type OAuthProvider string

const (
	GitHub    OAuthProvider = "github"
	Zoom      OAuthProvider = "zoom"
	GitLab    OAuthProvider = "gitlab"
	Microsoft OAuthProvider = "microsoft"
)

var ValidProviders = []OAuthProvider{GitHub, Zoom, GitLab, Microsoft}

func ContainsProvider(collection []OAuthProvider, toFind OAuthProvider) bool {
	for _, elem := range collection {
		if toFind == elem {
			return true
		}
	}
	return false
}

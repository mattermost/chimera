package providers

type OAuthProvider string

const (
	GitHub    OAuthProvider = "github"
	Zoom      OAuthProvider = "zoom"
	GitLab    OAuthProvider = "gitlab"
	Microsoft OAuthProvider = "microsoft"
)

type ProviderMetadata struct {
	DisplayName string
	HomepageURL string
}

var providerStaticData map[OAuthProvider]ProviderMetadata = map[OAuthProvider]ProviderMetadata{
	GitHub:    {DisplayName: "GitHub", HomepageURL: "https://github.com"},
	Zoom:      {DisplayName: "Zoom", HomepageURL: "https://zoom.us"},
	GitLab:    {DisplayName: "GitLab", HomepageURL: "https://gitlab.com"},
	Microsoft: {DisplayName: "Microsoft", HomepageURL: "https://microsoft.com"},
}

func (p OAuthProvider) DisplayName() string {
	return providerStaticData[p].DisplayName
}

func (p OAuthProvider) HomepageURL() string {
	return providerStaticData[p].HomepageURL
}

var ValidProviders = []OAuthProvider{GitHub, Zoom, GitLab, Microsoft}

func ContainsProvider(collection []OAuthProvider, toFind OAuthProvider) bool {
	for _, elem := range collection {
		if toFind == elem {
			return true
		}
	}
	return false
}

package providers

type OAuthProvider string

const (
	GitHub    OAuthProvider = "github"
	Zoom      OAuthProvider = "zoom"
	GitLab    OAuthProvider = "gitlab"
	Microsoft OAuthProvider = "microsoft"
)

type ProviderStaticData struct {
	DisplayName string
	HomepageURL string
}

var providerData map[OAuthProvider]ProviderStaticData = map[OAuthProvider]ProviderStaticData{
	GitHub:    {DisplayName: "GitHub", HomepageURL: "https://github.com"},
	Zoom:      {DisplayName: "Zoom", HomepageURL: "https://zoom.us"},
	GitLab:    {DisplayName: "GitLab", HomepageURL: "https://gitlab.com"},
	Microsoft: {DisplayName: "Microsoft", HomepageURL: "https://microsoft.com"},
}

func (p OAuthProvider) DisplayName() string {
	return providerData[p].DisplayName
}

func (p OAuthProvider) HomepageURL() string {
	return providerData[p].HomepageURL
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

package oauthapps

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/mattermost/chimera/internal/providers"
	"github.com/pkg/errors"
)

func NewAppsConfigFromFile(path string) (AppsConfig, error) {
	conf, err := ioutil.ReadFile(path)
	if err != nil {
		return AppsConfig{}, errors.Wrap(err, "failed to read apps config file")
	}

	var appsConfig AppsConfig
	err = json.Unmarshal(conf, &appsConfig)
	if err != nil {
		return AppsConfig{}, errors.Wrap(err, "failed to unmarshal apps config")
	}

	return appsConfig, nil
}

type AppsConfig struct {
	Apps []OAuthAppConfig `json:"apps"`
}

func (c AppsConfig) Validate() error {
	apps := map[string]OAuthAppConfig{}

	errs := []error{}

	for _, app := range c.Apps {
		err := app.Validate()
		if err != nil {
			errs = append(errs, err)
		}
		if _, found := apps[app.Identifier]; found {
			errs = append(errs, fmt.Errorf("app identifier %q is not unique", app.Identifier))
		}
		apps[app.Identifier] = app
	}

	if len(errs) > 0 {
		return fmt.Errorf("config is invalid: %v", errs)
	}

	return nil
}

type OAuthAppConfig struct {
	Identifier   string
	ClientID     string
	ClientSecret string
	Provider     providers.OAuthProvider
	ExtraData    map[string]interface{}
}

func (a OAuthAppConfig) Validate() error {
	if a.Identifier == "" {
		return fmt.Errorf("app identifier cannot be empty")
	}
	if a.Identifier != url.PathEscape(a.Identifier) {
		return fmt.Errorf("app identifier must be path compatible")
	}

	if !providers.ContainsProvider(providers.ValidProviders, a.Provider) {
		return fmt.Errorf("app %q has invalid provider %q", a.Identifier, a.Provider)
	}

	if a.ClientID == "" || a.ClientSecret == "" {
		return fmt.Errorf("some credentials not specified for app %q", a.Identifier)
	}

	return nil
}

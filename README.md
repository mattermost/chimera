![Chimera_Logo](https://user-images.githubusercontent.com/7295363/200433383-df069590-5177-43e0-870c-28e626ebc86a.png)

> An OAuth2 proxy to external OAuth providers. 

# Chimera

Chimera works with predefined applications by adding credentials to the requests and proxying them to OAuth providers.

## Chimera at Mattermost

Although there is nothing exclusive for Mattermost use case, Chimera acts as an OAuth2 proxy for some plugins to make it easier for Cloud customers to connect plugins running on their instances.

Thanks to Chimera, users can skip registration of their own OAuth2 applications on the provider side (such as GitHub or Zoom) and use applications pre-created by Mattermost company. This allows them to connect their plugins much easier ripping benefits of awesome integrations even faster :rocket:

### Plugins support

Current support for Chimera in Mattermost plugins.

| Plugin                                                                  | Chimera Support Status |
|-------------------------------------------------------------------------|:----------------------:|
| [GitHub Plugin](https://github.com/mattermost/mattermost-plugin-github) |           ✅            |
| [GitLab Plugin](https://github.com/mattermost/mattermost-plugin-gitlab) |           ✅            |

### Using Chimera on managed instance

[Mattermost Cloud managed installations](https://mattermost.com/pricing-cloud/) are preconfigured with Chimera. To use it with supported plugin enable **Use Preregistered OAuth Application** option in the plugin settings.


### On Premise instances

It is possible to use Chimera with on-premise instances, but it requires a lot of configuration and **is not officially supported** yet.


## Configuration

### OAuth applications configuration

To use Chimera, it needs to be configured with pre-registered OAuth applications on provider side.

The example shows configuration with GitHub OAuth2 application:
```json
{
  "apps": [
    {
      "identifier": "my-github-application",
      "clientID": "client-id",
      "clientSecret": "super-secret",
      "provider": "github"
    }
  ]
}
```

### Configuring with Mattermost Instance

To configure a Mattermost instance to use specific Chimera instance set Chimera URL in the following environment variable for the Mattermost server:
```
export MM_PLUGINSETTINGS_CHIMERAOAUTHPROXYURL=https://your-chimera.com
```

[Mattermost Cloud managed installations](https://mattermost.com/pricing-cloud/) are preconfigured with Chimera run and managed by Mattermost, therefor no configuration is needed.

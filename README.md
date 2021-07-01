# Chimera

Chimera is an OAuth2 proxy to external OAuth providers. 
It works with predefined applications by adding credentials to the requests and proxying them to OAuth providers.

## OAuth applications configuration

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


# git-credential-idcat

`git-credential-idcat` is a Git credential helper for using private GitHub repositories through
an idcat service. For more information about idcat, please see https://github.com/nresare/idcat.
When Git asks for credentials for an HTTPS GitHub remote, the helper picks up a
bearer token from a local command and uses that with a remote idcat service to exchange it for
an installation token that can be used to authenticate with GitHub for push and pull operations.

Requests for non-GitHub hosts, non-HTTPS URLs, or GitHub URLs without an owner/repository path are
ignored so that other credential helpers can handle them.

## Installation

```sh
cargo install git-credential-idcat
```

Configure Git to use the helper:

```sh
git config --global credential.helper idcat
```

To use a non-default configuration file:

```sh
git config --global credential.helper "idcat --config /path/to/credential-helper.toml"
```

## Configuration

By default, the helper reads:

```text
~/.config/idcat/credential-helper.toml
```

Example:

```toml
github-app = "deployments"
idcat-endpoint = "https://idcat.example.com"
token-source = "cat /var/run/secrets/tokens/idcat"
```

`github-app` selects the GitHub App configured in idcat. `idcat-endpoint` is the base URL of the
idcat service. `token-source` is a shell command that prints a bearer token accepted by idcat, such
as a Kubernetes service account token or another OIDC token.

When Git accesses `https://github.com/OWNER/REPO.git`, the helper calls:

```text
POST {idcat-endpoint}/installation-token/{github-app}/OWNER/REPO
```

with the token-source output as the bearer token. The response body is returned to Git as the
password, with `x-access-token` as the username.

## License

MIT

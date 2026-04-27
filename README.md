# idcat

`idcat` is a small Axum service that hides the GitHub App authentication dance behind one internal endpoint.

It reads a GitHub App RSA private key from the filesystem, signs a short-lived GitHub App JWT, and exchanges that JWT for a GitHub installation access token.

## Configuration

```toml
bind_address = "0.0.0.0:8080"
private_key_directory = "/var/run/secrets/idcat"

[authentication]
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github_app]]
name = "deployments"
app_id = 123456
secret_key = "deployments-private-key.pem"

[[github_app]]
name = "release-bot"
app_id = 234567
secret_key = "release-bot-private-key.pem"

[[installation]]
github_app = "deployments"

[installation.required_claims]
organization_slug = "my-buildkite-org"
pipeline_slug = "deploy-idcat"

[[installation]]
github_app = "release-bot"

[installation.permissions]
contents = "read"
metadata = "read"

[installation.required_claims]
sub = "system:serviceaccount:default:default"
```

Mount the private keys as files. For example, in Kubernetes this could be a Secret volume mounted at `private_key_directory`, but `idcat` only reads files from the filesystem.

```sh
kubectl create secret generic idcat \
  --from-file=private-key.pem=/path/to/github-app-private-key.pem
```

The application does not need Kubernetes API permissions to read private keys.

## API

```sh
curl -X POST \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  http://localhost:8080/installation-token/deployments/github_user/repo_name
```

The response body is the GitHub installation token:

```text
ghs_...
```

To proxy a repository-scoped GitHub API request through an installation token, prefix the GitHub
`/repos/{owner}/{repo}` path with `/proxy/{github_app}`. The GitHub app name selects the
configured GitHub App and authorization policy, while the owner/repo pair comes from the proxied
GitHub API path:

```sh
curl -X GET \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  http://localhost:8080/proxy/deployments/repos/github_user/repo_name/contents/README.md
```

## Running

```sh
cargo run -- --config-file idcat.toml
```

For local testing, authentication and `required_claims` checks can be bypassed:

```sh
cargo run -- --config-file idcat.toml --disable-auth
```

Use `--debug` to log detailed installation-token flow steps:

```sh
cargo run -- --config-file idcat.toml --debug
```

GitHub App installation IDs are cached in memory after the first lookup. Installation tokens are
cached in memory for 50 minutes per GitHub app, repo, and permission set.

## License

MIT

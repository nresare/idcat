# idcat

`idcat` is a small Axum service that hides the GitHub App authentication dance behind one internal endpoint.

It reads a GitHub App RSA private key from the filesystem, signs a short-lived GitHub App JWT, and exchanges that JWT for a GitHub installation access token.

## Configuration

```toml
private-key-directory = "/var/run/secrets/idcat"

[[identity-provider]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github-app]]
name = "deployments"
app-id = 123456
secret-key = "deployments-private-key.pem"

[[access-policy]]
github-app = "deployments"
identity-provider = "kubernetes"

[access-policy.required-claims]
sub = "system:serviceaccount:default:default"
```

See `idcat.toml.example` for a fuller configuration with multiple identity providers and GitHub Apps.

Mount the private keys as files. For example, in Kubernetes this could be a Secret volume mounted at `private-key-directory`, but `idcat` only reads files from the filesystem.

```sh
kubectl create secret generic idcat \
  --from-file=private-key.pem=/path/to/github-app-private-key.pem
```

The application does not need Kubernetes API permissions to read private keys.

When built with the `kms` feature, `key-source` may be set to `kms`. In that mode,
`secret-key` selects an AWS KMS alias instead of a filesystem path. Values without
the `alias/` prefix are treated as alias names, so `secret-key = "deployments"`
uses `alias/deployments`. AWS credentials and region are loaded from the ambient
AWS SDK configuration.

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
`/repos/{owner}/{repo}` path with `/proxy/{github-app}`. The GitHub app name selects the
configured GitHub App and access policy, while the owner/repo pair comes from the proxied
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

For local testing, authentication and `required-claims` checks can be bypassed:

```sh
cargo run -- --config-file idcat.toml --disable-auth
```

Use `--debug` to log detailed installation-token flow steps:

```sh
cargo run -- --config-file idcat.toml --debug
```

GitHub App installation IDs are cached in memory after the first lookup. Installation tokens are
cached in memory for 50 minutes per GitHub app and repo.

## License

MIT

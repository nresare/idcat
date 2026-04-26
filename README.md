# idcat

`idcat` is a small Axum service that hides the GitHub App authentication dance behind one internal endpoint.

It reads a GitHub App RSA private key from the filesystem, signs a short-lived GitHub App JWT, and exchanges that JWT for a GitHub installation access token.

## Configuration

```toml
bind_address = "0.0.0.0:8080"
github_api_url = "https://api.github.com"
github_app_id = 123456
private_key_directory = "/var/run/secrets/idcat"

[authentication]
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[installation]]
allowed_subjects = ["system:serviceaccount:idelephant:default"]
repo = "github_user/repo_name"
secret_key = "private-key.pem"

[[installation]]
allowed_subjects = ["system:serviceaccount:default:default"]
repo = "github_user/other_repo"
secret_key = "other-private-key.pem"

[installation.permissions]
contents = "read"
metadata = "read"
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
  http://localhost:8080/installation-token/github_user/repo_name
```

The response body is the GitHub installation token:

```text
ghs_...
```

To proxy a repository-scoped GitHub API request through an installation token, prefix the GitHub
`/repos/{owner}/{repo}` path with `/proxy`. The owner/repo pair is extracted from the path and used
to select the configured installation and authorization policy:

```sh
curl -X GET \
  -H "Authorization: Bearer $KUBERNETES_JWT" \
  http://localhost:8080/proxy/repos/github_user/repo_name/contents/README.md
```

## Running

```sh
cargo run -- --config-file idcat.toml
```

For local testing, authentication and `allowed_subjects` checks can be bypassed:

```sh
cargo run -- --config-file idcat.toml --disable-auth
```

Use `--debug` to log detailed installation-token flow steps:

```sh
cargo run -- --config-file idcat.toml --debug
```

GitHub App installation IDs are cached in memory after the first lookup. Installation tokens are
cached in memory for 50 minutes per repo and permission set.

## License

MIT

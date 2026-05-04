// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default)]
    pub key_source: KeySource,
    #[serde(default = "default_private_key_directory")]
    pub private_key_directory: String,
    #[serde(rename = "identity-provider", default)]
    pub identity_providers: Vec<IdentityProviderConfig>,
    #[serde(rename = "github-app", default)]
    pub github_apps: Vec<GithubAppConfig>,
    #[serde(rename = "access-policy", default)]
    pub access_policies: Vec<AccessPolicyConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KeySource {
    #[default]
    Local,
    Kms,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct IdentityProviderConfig {
    pub name: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub issuer: String,
    pub validation_key: Option<String>,
    #[serde(default = "default_authentication_algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GithubAppConfig {
    pub name: String,
    pub app_id: u64,
    pub secret_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessPolicyConfig {
    pub github_app: String,
    #[serde(rename = "identity-provider")]
    pub identity_provider: Option<String>,
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content)
            .map_err(|error| anyhow::anyhow!("Could not parse config file '{path}': {error}"))
    }

    pub fn validate(&self, disable_auth: bool) -> anyhow::Result<()> {
        if self.bind_address.is_empty() {
            anyhow::bail!("bind-address must not be empty");
        }
        if self.key_source == KeySource::Local && self.private_key_directory.is_empty() {
            anyhow::bail!("private-key-directory must not be empty");
        }
        if self.key_source == KeySource::Kms && !cfg!(feature = "kms") {
            anyhow::bail!("key-source 'kms' requires idcat to be built with the 'kms' feature");
        }
        if self.access_policies.is_empty() {
            anyhow::bail!("at least one [[access-policy]] entry is required");
        }
        let mut identity_providers = std::collections::HashSet::new();
        if !disable_auth && self.identity_providers.is_empty() {
            anyhow::bail!("at least one [[identity-provider]] entry is required");
        }
        for identity_provider in &self.identity_providers {
            identity_provider.validate()?;
            if !identity_providers.insert(identity_provider.name.clone()) {
                anyhow::bail!("duplicate identity-provider '{}'", identity_provider.name);
            }
        }

        if self.github_apps.is_empty() {
            anyhow::bail!("at least one [[github-app]] entry is required");
        }
        let mut github_apps = std::collections::HashSet::new();
        for github_app in &self.github_apps {
            if github_app.name.is_empty() {
                anyhow::bail!("github-app names must not be empty");
            }
            if github_app.name.contains('/') {
                anyhow::bail!("github-app '{}' name must not contain '/'", github_app.name);
            }
            if github_app.app_id == 0 {
                anyhow::bail!(
                    "github-app '{}' app-id must be greater than 0",
                    github_app.name
                );
            }
            if github_app.secret_key.is_empty() {
                anyhow::bail!("github-app '{}' must define secret-key", github_app.name);
            }
            if self.key_source == KeySource::Local
                && (Path::new(&github_app.secret_key).is_absolute()
                    || github_app.secret_key.contains(".."))
            {
                anyhow::bail!(
                    "github-app '{}' secret-key must be a relative file name",
                    github_app.name
                );
            }
            if !github_apps.insert(github_app.name.clone()) {
                anyhow::bail!("duplicate github-app '{}'", github_app.name);
            }
        }

        let mut access_policies = std::collections::HashSet::new();
        for access_policy in &self.access_policies {
            if access_policy.github_app.is_empty() {
                anyhow::bail!("access-policy entries must define github-app");
            }
            if !github_apps.contains(&access_policy.github_app) {
                anyhow::bail!(
                    "access-policy references unknown github-app '{}'",
                    access_policy.github_app
                );
            }
            if !disable_auth {
                let identity_provider =
                    access_policy.identity_provider.as_deref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "access-policy for github-app '{}' must define identity-provider",
                            access_policy.github_app
                        )
                    })?;
                if identity_provider.is_empty() {
                    anyhow::bail!(
                        "access-policy for github-app '{}' identity-provider must not be empty",
                        access_policy.github_app
                    );
                }
                if !identity_providers.contains(identity_provider) {
                    anyhow::bail!(
                        "access-policy for github-app '{}' references unknown identity-provider '{}'",
                        access_policy.github_app,
                        identity_provider
                    );
                }
            }
            if !disable_auth && access_policy.required_claims.is_empty() {
                anyhow::bail!(
                    "access-policy for github-app '{}' must define at least one required-claim",
                    access_policy.github_app
                );
            }
            if !access_policies.insert(access_policy.github_app.clone()) {
                anyhow::bail!(
                    "duplicate access-policy for github-app '{}'",
                    access_policy.github_app
                );
            }
        }
        Ok(())
    }
}

impl IdentityProviderConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            anyhow::bail!("identity-provider names must not be empty");
        }
        if self.audience.is_empty() {
            anyhow::bail!(
                "identity-provider '{}' audience must not be empty",
                self.name
            );
        }
        if self.issuer.is_empty() {
            anyhow::bail!("identity-provider '{}' issuer must not be empty", self.name);
        }
        crate::auth::algorithm(self)?;
        Ok(())
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_private_key_directory() -> String {
    "/var/run/secrets/idcat".to_string()
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

#[cfg(test)]
mod tests {
    use super::{Config, KeySource};

    #[test]
    fn parses_minimal_config() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[identity-provider]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation-key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[[access-policy]]
github-app = "default"
identity-provider = "kubernetes"

[access-policy.required-claims]
sub = "system:serviceaccount:idelephant:default"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.key_source, KeySource::Local);
        assert_eq!(config.private_key_directory, "/var/run/secrets/idcat");
    }

    #[test]
    #[cfg(feature = "kms")]
    fn accepts_kms_key_source_when_kms_feature_is_enabled() {
        let config: Config = toml::from_str(
            r#"
key-source = "kms"

[[github-app]]
name = "default"
app-id = 42
secret-key = "default"

[[access-policy]]
github-app = "default"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
        assert_eq!(config.key_source, KeySource::Kms);
    }

    #[test]
    #[cfg(not(feature = "kms"))]
    fn rejects_kms_key_source_when_kms_feature_is_disabled() {
        let config: Config = toml::from_str(
            r#"
key-source = "kms"

[[github-app]]
name = "default"
app-id = 42
secret-key = "default"

[[access-policy]]
github-app = "default"
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "key-source 'kms' requires idcat to be built with the 'kms' feature"
        );
    }

    #[test]
    fn rejects_duplicate_access_policies_for_github_app() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[identity-provider]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation-key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[[access-policy]]
github-app = "default"
identity-provider = "kubernetes"

[access-policy.required-claims]
sub = "system:serviceaccount:idelephant:default"

[[access-policy]]
github-app = "default"
identity-provider = "kubernetes"

[access-policy.required-claims]
sub = "system:serviceaccount:idelephant:default"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "duplicate access-policy for github-app 'default'"
        );
    }

    #[test]
    fn rejects_access_policy_with_unknown_identity_provider() {
        let config: Config = toml::from_str(
            r#"
[[identity-provider]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[access-policy]]
github-app = "default"
identity-provider = "buildkite"

[access-policy.required-claims]
sub = "system:serviceaccount:idelephant:default"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "access-policy for github-app 'default' references unknown identity-provider 'buildkite'"
        );
    }

    #[test]
    fn disable_auth_skips_authentication_and_required_claims_validation() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[access-policy]]
github-app = "default"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }
}

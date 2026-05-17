// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use serde::Deserialize;
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
    #[serde(rename = "role", default)]
    pub roles: Vec<authzoo::RoleConfig>,
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
pub struct GithubAppConfig {
    pub name: String,
    pub app_id: u64,
    pub secret_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessPolicyConfig {
    pub github_app: String,
    pub role: Option<String>,
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
        let role_validator = authzoo::TokenValidator::new(self.roles.clone())?;
        if !disable_auth && self.roles.is_empty() {
            anyhow::bail!("at least one [[role]] entry is required");
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
                let role = access_policy.role.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "access-policy for github-app '{}' must define role",
                        access_policy.github_app
                    )
                })?;
                if role.is_empty() {
                    anyhow::bail!(
                        "access-policy for github-app '{}' role must not be empty",
                        access_policy.github_app
                    );
                }
                role_validator.ensure_roles_exist([role])?;
            }
        }
        Ok(())
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_private_key_directory() -> String {
    "/var/run/secrets/idcat".to_string()
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

[[role]]
name = "kubernetes-default"
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

[role.claims]
sub = "system:serviceaccount:idelephant:default"

[[access-policy]]
github-app = "default"
role = "kubernetes-default"
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
    fn accepts_multiple_access_policies_for_github_app() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[role]]
name = "kubernetes-default"
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
role = "kubernetes-default"

[[access-policy]]
github-app = "default"
role = "kubernetes-default"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn rejects_access_policy_with_unknown_role() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "kubernetes"
audience = "idcat"
issuer = "https://kubernetes.default.svc"

[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"

[[access-policy]]
github-app = "default"
role = "buildkite"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(error.to_string(), "unknown role 'buildkite'");
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

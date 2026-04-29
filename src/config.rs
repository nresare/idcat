// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default)]
    pub key_source: KeySource,
    #[serde(default = "default_private_key_directory")]
    pub private_key_directory: String,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    #[serde(rename = "github_app", default)]
    pub github_apps: Vec<GithubAppConfig>,
    #[serde(rename = "installation", default)]
    pub installations: Vec<InstallationConfig>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    #[default]
    Local,
    Kms,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthenticationConfig {
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub issuer: String,
    pub validation_key: Option<String>,
    #[serde(default = "default_authentication_algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GithubAppConfig {
    pub name: String,
    pub app_id: u64,
    pub secret_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallationConfig {
    pub github_app: String,
    #[serde(default)]
    pub required_claims: BTreeMap<String, String>,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
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
            anyhow::bail!("bind_address must not be empty");
        }
        if self.key_source == KeySource::Local && self.private_key_directory.is_empty() {
            anyhow::bail!("private_key_directory must not be empty");
        }
        if self.key_source == KeySource::Kms && !cfg!(feature = "kms") {
            anyhow::bail!("key_source 'kms' requires idcat to be built with the 'kms' feature");
        }
        if !disable_auth {
            self.authentication.validate()?;
        }
        if self.installations.is_empty() {
            anyhow::bail!("at least one [[installation]] entry is required");
        }

        if self.github_apps.is_empty() {
            anyhow::bail!("at least one [[github_app]] entry is required");
        }
        let mut github_apps = std::collections::HashSet::new();
        for github_app in &self.github_apps {
            if github_app.name.is_empty() {
                anyhow::bail!("github_app names must not be empty");
            }
            if github_app.name.contains('/') {
                anyhow::bail!("github_app '{}' name must not contain '/'", github_app.name);
            }
            if github_app.app_id == 0 {
                anyhow::bail!(
                    "github_app '{}' app_id must be greater than 0",
                    github_app.name
                );
            }
            if github_app.secret_key.is_empty() {
                anyhow::bail!("github_app '{}' must define secret_key", github_app.name);
            }
            if self.key_source == KeySource::Local
                && (Path::new(&github_app.secret_key).is_absolute()
                    || github_app.secret_key.contains(".."))
            {
                anyhow::bail!(
                    "github_app '{}' secret_key must be a relative file name",
                    github_app.name
                );
            }
            if !github_apps.insert(github_app.name.clone()) {
                anyhow::bail!("duplicate github_app '{}'", github_app.name);
            }
        }

        let mut installations = std::collections::HashSet::new();
        for installation in &self.installations {
            if installation.github_app.is_empty() {
                anyhow::bail!("installation entries must define github_app");
            }
            if !github_apps.contains(&installation.github_app) {
                anyhow::bail!(
                    "installation references unknown github_app '{}'",
                    installation.github_app
                );
            }
            if !disable_auth && installation.required_claims.is_empty() {
                anyhow::bail!(
                    "installation for github_app '{}' must define at least one required_claim",
                    installation.github_app
                );
            }
            if !installations.insert(installation.github_app.clone()) {
                anyhow::bail!(
                    "duplicate installation for github_app '{}'",
                    installation.github_app
                );
            }
        }
        Ok(())
    }
}

impl AuthenticationConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.audience.is_empty() {
            anyhow::bail!("authentication.audience must not be empty");
        }
        if self.issuer.is_empty() {
            anyhow::bail!("authentication.issuer must not be empty");
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
[[github_app]]
name = "default"
app_id = 42
secret_key = "private-key.pem"

[authentication]
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[[installation]]
github_app = "default"

[installation.required_claims]
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
key_source = "kms"

[[github_app]]
name = "default"
app_id = 42
secret_key = "default"

[[installation]]
github_app = "default"
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
key_source = "kms"

[[github_app]]
name = "default"
app_id = 42
secret_key = "default"

[[installation]]
github_app = "default"
"#,
        )
        .unwrap();

        let error = config.validate(true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "key_source 'kms' requires idcat to be built with the 'kms' feature"
        );
    }

    #[test]
    fn rejects_duplicate_installations_for_github_app() {
        let config: Config = toml::from_str(
            r#"
[[github_app]]
name = "default"
app_id = 42
secret_key = "private-key.pem"

[authentication]
audience = "idcat"
issuer = "https://kubernetes.default.svc"
validation_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFi8U2NAcihFpXAvLmOz
K1GfRjFzTuGWVDEBjjyEjSiDeBFZEl+gq3TnDFw9+TQPPbjLbFou5HIZ11PoT+sp
d26cU1FsvNEJMzlr4esgzdd9bR7lMcz/Y3CkSga1fQupgp85VpKfE0X7oUVDQYQq
vyuxfmcMdoBLwBXU9nWXL8Y6QaHCUuekpYLgiQf+mBqh1n3LJqllCL/73zIcGmk+
Kbh2b10d0fDtaUzw7mfbFW7S34v2wAs8SjsUPq6OhtTnmhUR1sZQ2AAJWQdm+lVr
S0kRuvb81yBZzXrfzskMnNL2PQ7aZuO0D3XHNgzTtze6+jJdgAm2UeSA4QIDAQAB
-----END PUBLIC KEY-----
"""

[[installation]]
github_app = "default"

[installation.required_claims]
sub = "system:serviceaccount:idelephant:default"

[[installation]]
github_app = "default"

[installation.required_claims]
sub = "system:serviceaccount:idelephant:default"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "duplicate installation for github_app 'default'"
        );
    }

    #[test]
    fn disable_auth_skips_authentication_and_required_claims_validation() {
        let config: Config = toml::from_str(
            r#"
[[github_app]]
name = "default"
app_id = 42
secret_key = "private-key.pem"

[[installation]]
github_app = "default"
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }
}

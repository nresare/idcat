use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_github_api_url")]
    pub github_api_url: String,
    pub github_app_id: u64,
    #[serde(default = "default_private_key_directory")]
    pub private_key_directory: String,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    #[serde(rename = "installation", default)]
    pub installations: Vec<InstallationConfig>,
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
pub struct InstallationConfig {
    pub repo: String,
    pub secret_key: String,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
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

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.bind_address.is_empty() {
            anyhow::bail!("bind_address must not be empty");
        }
        if self.github_api_url.is_empty() {
            anyhow::bail!("github_api_url must not be empty");
        }
        if self.github_app_id == 0 {
            anyhow::bail!("github_app_id must be greater than 0");
        }
        if self.private_key_directory.is_empty() {
            anyhow::bail!("private_key_directory must not be empty");
        }
        self.authentication.validate()?;
        if self.installations.is_empty() {
            anyhow::bail!("at least one [[installation]] entry is required");
        }

        let mut repos = std::collections::HashSet::new();
        for installation in &self.installations {
            if installation.repo.is_empty() {
                anyhow::bail!("installation repos must not be empty");
            }
            if !installation.repo.contains('/') {
                anyhow::bail!(
                    "installation repo '{}' must use owner/repo format",
                    installation.repo
                );
            }
            if installation.secret_key.is_empty() {
                anyhow::bail!(
                    "installation '{}' must define secret_key",
                    installation.repo
                );
            }
            if Path::new(&installation.secret_key).is_absolute()
                || installation.secret_key.contains("..")
            {
                anyhow::bail!(
                    "installation '{}' secret_key must be a relative file name",
                    installation.repo
                );
            }
            if installation.allowed_subjects.is_empty() {
                anyhow::bail!(
                    "installation '{}' must define at least one allowed_subject",
                    installation.repo
                );
            }
            if !repos.insert(installation.repo.clone()) {
                anyhow::bail!("duplicate installation repo '{}'", installation.repo);
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

fn default_github_api_url() -> String {
    "https://api.github.com".to_string()
}

fn default_private_key_directory() -> String {
    "/var/run/secrets/idcat".to_string()
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn parses_minimal_config() {
        let config: Config = toml::from_str(
            r#"
github_app_id = 42

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
repo = "github_user/repo_name"
secret_key = "private-key.pem"
allowed_subjects = ["system:serviceaccount:idelephant:default"]
"#,
        )
        .unwrap();

        config.validate().unwrap();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.github_api_url, "https://api.github.com");
        assert_eq!(config.private_key_directory, "/var/run/secrets/idcat");
    }

    #[test]
    fn rejects_duplicate_installation_repos() {
        let config: Config = toml::from_str(
            r#"
github_app_id = 42

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
repo = "github_user/repo_name"
secret_key = "first.pem"
allowed_subjects = ["system:serviceaccount:idelephant:default"]

[[installation]]
repo = "github_user/repo_name"
secret_key = "second.pem"
allowed_subjects = ["system:serviceaccount:idelephant:default"]
"#,
        )
        .unwrap();

        let error = config.validate().unwrap_err();
        assert_eq!(
            error.to_string(),
            "duplicate installation repo 'github_user/repo_name'"
        );
    }
}

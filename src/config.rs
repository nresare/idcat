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
    #[serde(rename = "role", default)]
    pub roles: Vec<authzoo::RoleConfig>,
    #[serde(rename = "github-app", default)]
    pub github_apps: Vec<GithubAppConfig>,
    #[serde(rename = "installation-policy", default)]
    pub installation_policies: Vec<InstallationPolicyConfig>,
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
    #[serde(default)]
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InstallationPolicyConfig {
    pub github_app: String,
    pub repository: String,
    pub role: String,
    #[serde(rename = "required-claims", default)]
    pub required_claims: BTreeMap<String, authzoo::ClaimRequirement>,
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
            if !disable_auth {
                for role in &github_app.allowed_roles {
                    if role.is_empty() {
                        anyhow::bail!(
                            "github-app '{}' allowed-roles must not contain empty entries",
                            github_app.name
                        );
                    }
                }
                role_validator
                    .ensure_roles_exist(github_app.allowed_roles.iter().map(String::as_str))?;
            }
        }
        if !disable_auth {
            for installation_policy in &self.installation_policies {
                if installation_policy.github_app.is_empty() {
                    anyhow::bail!("installation-policy github-app must not be empty");
                }
                if !github_apps.contains(&installation_policy.github_app) {
                    anyhow::bail!(
                        "installation-policy references unknown github-app '{}'",
                        installation_policy.github_app
                    );
                }
                if !is_repository_name(&installation_policy.repository) {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' must define repository as owner/name",
                        installation_policy.github_app
                    );
                }
                if installation_policy.role.is_empty() {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' repository '{}' must define role",
                        installation_policy.github_app,
                        installation_policy.repository
                    );
                }
                role_validator.ensure_roles_exist([installation_policy.role.as_str()])?;
                if installation_policy.required_claims.is_empty() {
                    anyhow::bail!(
                        "installation-policy for github-app '{}' repository '{}' role '{}' must define at least one required-claim",
                        installation_policy.github_app,
                        installation_policy.repository,
                        installation_policy.role
                    );
                }
                let role_claims = &role_validator.roles()[&installation_policy.role].claims;
                for (claim, requirement) in &installation_policy.required_claims {
                    if claim.is_empty() {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' required-claim names must not be empty",
                            installation_policy.github_app,
                            installation_policy.repository,
                            installation_policy.role
                        );
                    }
                    requirement.validate(&installation_policy.role, claim)?;
                    if role_claims.contains_key(claim) {
                        anyhow::bail!(
                            "installation-policy for github-app '{}' repository '{}' role '{}' required-claim '{}' duplicates a role claim",
                            installation_policy.github_app,
                            installation_policy.repository,
                            installation_policy.role,
                            claim
                        );
                    }
                }
            }
            for github_app in &self.github_apps {
                let has_installation_policy = self
                    .installation_policies
                    .iter()
                    .any(|installation_policy| installation_policy.github_app == github_app.name);
                if github_app.allowed_roles.is_empty() && !has_installation_policy {
                    anyhow::bail!(
                        "github-app '{}' must define at least one allowed-role or installation-policy",
                        github_app.name
                    );
                }
            }
        }
        Ok(())
    }
}

fn is_repository_name(repository: &str) -> bool {
    let Some((owner, name)) = repository.split_once('/') else {
        return false;
    };
    !owner.is_empty() && !name.is_empty() && !name.contains('/')
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
allowed-roles = ["kubernetes-default"]

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
    fn accepts_multiple_allowed_roles_for_github_app() {
        let config: Config = toml::from_str(
            r#"
[[github-app]]
name = "default"
app-id = 42
secret-key = "private-key.pem"
allowed-roles = ["kubernetes-default", "buildkite-deploy"]

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

[[role]]
name = "buildkite-deploy"
audience = "idcat"
issuer = "https://agent.buildkite.com"
validation-key = "shared-secret"
algorithms = ["HS256"]
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
    }

    #[test]
    fn accepts_installation_policy_with_required_claims() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"

[installation-policy.required-claims]
repository = "myorg/gamma"
"#,
        )
        .unwrap();

        config.validate(false).unwrap();
        assert_eq!(config.installation_policies.len(), 1);
    }

    #[test]
    fn rejects_github_app_with_unknown_allowed_role() {
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
allowed-roles = ["buildkite"]
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(error.to_string(), "unknown role 'buildkite'");
    }

    #[test]
    fn rejects_github_app_without_allowed_roles() {
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
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "github-app 'default' must define at least one allowed-role or installation-policy"
        );
    }

    #[test]
    fn rejects_installation_policy_without_required_claims() {
        let config: Config = toml::from_str(
            r#"
[[role]]
name = "github-workflow"
audience = "idcat"
issuer = "https://token.actions.githubusercontent.com"
validation-key = "shared-secret"
algorithms = ["HS256"]

[[github-app]]
name = "deployments"
app-id = 42
secret-key = "private-key.pem"

[[installation-policy]]
github-app = "deployments"
repository = "myorg/alfa"
role = "github-workflow"
"#,
        )
        .unwrap();

        let error = config.validate(false).unwrap_err();
        assert_eq!(
            error.to_string(),
            "installation-policy for github-app 'deployments' repository 'myorg/alfa' role 'github-workflow' must define at least one required-claim"
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
"#,
        )
        .unwrap();

        config.validate(true).unwrap();
    }
}

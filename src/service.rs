// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{Config, GithubAppConfig, InstallationPolicyConfig, KeySource};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use crate::signer::{LocalSigner, Signer};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct AppState {
    pub github_apps: Arc<Vec<GithubAppConfig>>,
    pub installation_policies: Arc<Vec<InstallationPolicyConfig>>,
    pub token_validator: TokenValidator,
    pub github: GithubClient,
    pub key_source: KeySource,
    pub private_key_store: FilePrivateKeyStore,
    #[cfg(feature = "kms")]
    pub kms_signers: Option<crate::kms::KmsSignerFactory>,
}

pub async fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    #[cfg(feature = "kms")]
    let kms_signers = match config.key_source {
        KeySource::Local => None,
        KeySource::Kms => Some(crate::kms::KmsSignerFactory::from_env().await),
    };

    Ok(AppState {
        github_apps: Arc::new(config.github_apps.clone()),
        installation_policies: Arc::new(config.installation_policies.clone()),
        token_validator: TokenValidator::new(config.roles.clone(), disable_auth)?,
        github: GithubClient::new()?,
        key_source: config.key_source,
        private_key_store: FilePrivateKeyStore::new(&config.private_key_directory),
        #[cfg(feature = "kms")]
        kms_signers,
    })
}

impl AppState {
    pub fn github_app(&self, github_app_name: &str) -> Result<&GithubAppConfig, AppError> {
        debug!(github_app = %github_app_name, "searching configured GitHub apps");
        self.github_apps
            .iter()
            .find(|github_app| github_app.name == github_app_name)
            .ok_or_else(|| AppError::NotFound(format!("unknown github_app '{github_app_name}'")))
    }

    pub fn authorize_github_app(
        &self,
        github_app: &GithubAppConfig,
        repo: &str,
        bearer_token: Option<&str>,
    ) -> Result<(), AppError> {
        if !self.token_validator.auth_enabled() {
            debug!(
                github_app = %github_app.name,
                repo = %repo,
                "skipping authorization because auth is disabled"
            );
            return Ok(());
        }
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let matching_roles = self.token_validator.validate(bearer_token);
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            ?matching_roles,
            allowed_roles = ?github_app.allowed_roles,
            "matched roles for source token"
        );
        let mut authorized = matching_roles.iter().any(|role| {
            github_app
                .allowed_roles
                .iter()
                .any(|allowed| allowed == role)
        });
        if !authorized {
            authorized = self
                .installation_policies
                .iter()
                .any(|installation_policy| {
                    installation_policy.github_app == github_app.name
                        && installation_policy.repository == repo
                        && self.token_validator.validate_role_with_claims(
                            &installation_policy.role,
                            &installation_policy.required_claims,
                            bearer_token,
                        )
                });
        }
        if !authorized {
            return Err(AppError::Unauthorized(format!(
                "source token did not match any allowed role for github-app '{}' and repository '{}'",
                github_app.name, repo
            )));
        }
        Ok(())
    }

    pub fn signer(&self, secret_key: &str) -> anyhow::Result<Box<dyn Signer>> {
        match self.key_source {
            KeySource::Local => {
                let private_key_pem = self.private_key_store.private_key_pem(secret_key)?;
                Ok(Box::new(LocalSigner::from_rsa_pem(&private_key_pem)?))
            }
            KeySource::Kms => {
                #[cfg(feature = "kms")]
                {
                    let kms_signers = self
                        .kms_signers
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("AWS KMS signer factory not initialized"))?;
                    Ok(Box::new(kms_signers.signer_for_secret_key(secret_key)))
                }
                #[cfg(not(feature = "kms"))]
                {
                    anyhow::bail!(
                        "key_source 'kms' requires idcat to be built with the 'kms' feature"
                    )
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct TokenValidator {
    inner: Option<authzoo::TokenValidator>,
}

impl TokenValidator {
    pub fn new(roles: Vec<authzoo::RoleConfig>, disable_auth: bool) -> anyhow::Result<Self> {
        let inner = if disable_auth {
            None
        } else {
            Some(authzoo::TokenValidator::new(roles)?)
        };
        Ok(Self { inner })
    }

    pub fn validate(&self, bearer_token: &str) -> Vec<String> {
        match &self.inner {
            Some(validator) => validator.validate(bearer_token),
            None => Vec::new(),
        }
    }

    pub fn validate_role_with_claims(
        &self,
        role_name: &str,
        required_claims: &BTreeMap<String, authzoo::ClaimRequirement>,
        bearer_token: &str,
    ) -> bool {
        let Some(validator) = &self.inner else {
            return false;
        };
        let Some(role) = validator.roles().get(role_name) else {
            return false;
        };
        let mut role = role.clone();
        role.claims.extend(required_claims.clone());
        authzoo::TokenValidator::new(vec![role])
            .map(|validator| {
                validator
                    .validate(bearer_token)
                    .iter()
                    .any(|role| role == role_name)
            })
            .unwrap_or(false)
    }

    pub fn auth_enabled(&self) -> bool {
        self.inner.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, TokenValidator};
    use crate::config::{GithubAppConfig, InstallationPolicyConfig, KeySource};
    use crate::error::AppError;
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_state(github_apps: Vec<GithubAppConfig>) -> AppState {
        test_state_with_installation_policies(github_apps, Vec::new())
    }

    fn test_state_with_installation_policies(
        github_apps: Vec<GithubAppConfig>,
        installation_policies: Vec<InstallationPolicyConfig>,
    ) -> AppState {
        AppState {
            github_apps: Arc::new(github_apps),
            installation_policies: Arc::new(installation_policies),
            token_validator: TokenValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        }
    }

    fn github_workflow_role() -> authzoo::RoleConfig {
        authzoo::RoleConfig {
            name: "github-workflow".to_string(),
            audience: "idcat".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            validation_key: Some("secret".to_string()),
            algorithms: vec![authzoo::JwtAlgorithm::Hs256],
            claims: BTreeMap::new(),
        }
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        aud: &'a str,
        iss: &'a str,
        exp: u64,
        repository: &'a str,
    }

    fn github_workflow_token(repository: &str) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &TestClaims {
                sub: "repo:myorg/gamma:ref:refs/heads/main",
                aud: "idcat",
                iss: "https://token.actions.githubusercontent.com",
                exp: 4_102_444_800,
                repository,
            },
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap()
    }

    #[test]
    fn github_app_returns_matching_config() {
        let state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            allowed_roles: vec!["buildkite-deploy".to_string()],
        }]);

        let github_app = state.github_app("default").unwrap();
        assert_eq!(
            github_app.allowed_roles,
            vec!["buildkite-deploy".to_string()]
        );
    }

    #[test]
    fn authorize_github_app_passes_when_auth_disabled() {
        let state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            allowed_roles: Vec::new(),
        }]);

        let github_app = state.github_app("default").unwrap().clone();
        state
            .authorize_github_app(&github_app, "myorg/alfa", None)
            .unwrap();
    }

    #[test]
    fn authorize_github_app_requires_bearer_token_when_auth_enabled() {
        let mut state = test_state(vec![GithubAppConfig {
            name: "default".to_string(),
            app_id: 42,
            secret_key: "private-key.pem".to_string(),
            allowed_roles: vec!["kubernetes-default".to_string()],
        }]);
        state.token_validator = TokenValidator::new(Vec::new(), false).unwrap();

        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "myorg/alfa", None)
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }

    #[test]
    fn authorize_github_app_accepts_installation_policy_with_required_claims() {
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "repository".to_string(),
            authzoo::ClaimRequirement::equals("myorg/gamma"),
        );
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                allowed_roles: Vec::new(),
            }],
            vec![InstallationPolicyConfig {
                github_app: "default".to_string(),
                repository: "myorg/alfa".to_string(),
                role: "github-workflow".to_string(),
                required_claims,
            }],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/gamma");
        let github_app = state.github_app("default").unwrap().clone();
        state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap();
    }

    #[test]
    fn authorize_github_app_rejects_installation_policy_when_required_claims_do_not_match() {
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "repository".to_string(),
            authzoo::ClaimRequirement::equals("myorg/gamma"),
        );
        let mut state = test_state_with_installation_policies(
            vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
                allowed_roles: Vec::new(),
            }],
            vec![InstallationPolicyConfig {
                github_app: "default".to_string(),
                repository: "myorg/alfa".to_string(),
                role: "github-workflow".to_string(),
                required_claims,
            }],
        );
        state.token_validator = TokenValidator::new(vec![github_workflow_role()], false).unwrap();

        let token = github_workflow_token("myorg/epsilon");
        let github_app = state.github_app("default").unwrap().clone();
        let error = state
            .authorize_github_app(&github_app, "myorg/alfa", Some(&token))
            .unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }
}

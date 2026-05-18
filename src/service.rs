// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{Config, GithubAppConfig, KeySource};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use crate::signer::{LocalSigner, Signer};
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct AppState {
    pub github_apps: Arc<Vec<GithubAppConfig>>,
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
        bearer_token: Option<&str>,
    ) -> Result<(), AppError> {
        if !self.token_validator.auth_enabled() {
            debug!(
                github_app = %github_app.name,
                "skipping authorization because auth is disabled"
            );
            return Ok(());
        }
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let matching_roles = self.token_validator.validate(bearer_token);
        debug!(
            github_app = %github_app.name,
            ?matching_roles,
            allowed_roles = ?github_app.allowed_roles,
            "matched roles for source token"
        );
        let authorized = matching_roles.iter().any(|role| {
            github_app
                .allowed_roles
                .iter()
                .any(|allowed| allowed == role)
        });
        if !authorized {
            return Err(AppError::Unauthorized(format!(
                "source token did not match any allowed role for github-app '{}'",
                github_app.name
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

    pub fn auth_enabled(&self) -> bool {
        self.inner.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, TokenValidator};
    use crate::config::{GithubAppConfig, KeySource};
    use crate::error::AppError;
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use std::sync::Arc;

    fn test_state(github_apps: Vec<GithubAppConfig>) -> AppState {
        AppState {
            github_apps: Arc::new(github_apps),
            token_validator: TokenValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        }
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
        state.authorize_github_app(&github_app, None).unwrap();
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
        let error = state.authorize_github_app(&github_app, None).unwrap_err();
        assert!(matches!(error, AppError::Unauthorized(_)));
    }
}

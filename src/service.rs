// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{AccessPolicyConfig, Config, GithubAppConfig, KeySource};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use crate::signer::{LocalSigner, Signer};
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct AppState {
    pub github_apps: Arc<Vec<GithubAppConfig>>,
    pub access_policies: Arc<Vec<AccessPolicyConfig>>,
    pub subject_validator: SubjectValidator,
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
        access_policies: Arc::new(config.access_policies.clone()),
        subject_validator: SubjectValidator::new(config.roles.clone(), disable_auth)?,
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

    pub fn access_policies(
        &self,
        github_app_name: &str,
        repo: &str,
    ) -> Result<Vec<&AccessPolicyConfig>, AppError> {
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            "searching configured access policies"
        );
        let access_policies: Vec<_> = self
            .access_policies
            .iter()
            .filter(|access_policy| access_policy.github_app == github_app_name)
            .collect();
        if access_policies.is_empty() {
            return Err(AppError::NotFound(format!(
                "unknown access-policy for github_app '{github_app_name}'"
            )));
        }
        Ok(access_policies)
    }

    pub fn authorize_access_policy(
        &self,
        github_app_name: &str,
        repo: &str,
        claims: &authzoo::ValidatedClaims,
    ) -> Result<(), AppError> {
        let subject = claims.subject();

        debug!(
            github_app = %github_app_name,
            repo = %repo,
            subject = %subject,
            auth_enabled = self.subject_validator.auth_enabled(),
            "access policy authorization check passed"
        );
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
pub struct SubjectValidator {
    mode: SubjectValidationMode,
}

#[derive(Clone)]
enum SubjectValidationMode {
    Disabled,
    Enabled(authzoo::TokenValidator),
}

impl SubjectValidator {
    pub fn new(roles: Vec<authzoo::RoleConfig>, disable_auth: bool) -> anyhow::Result<Self> {
        let mode = if disable_auth {
            SubjectValidationMode::Disabled
        } else {
            SubjectValidationMode::Enabled(authzoo::TokenValidator::new(roles)?)
        };
        Ok(Self { mode })
    }

    pub fn validate(
        &self,
        role: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<authzoo::ValidatedClaims, AppError> {
        let validator = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("source token claim validation skipped because auth is disabled");
                return Ok(unauthenticated_claims());
            }
            SubjectValidationMode::Enabled(validator) => {
                let role = role.ok_or_else(|| {
                    AppError::Internal("access-policy is missing a role reference".to_string())
                })?;
                (validator, role)
            }
        };
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        debug!(
            role = %validator.1,
            "validating source token claims"
        );
        let claims = validator
            .0
            .validate_claims(validator.1, bearer_token)
            .map_err(|error| {
                AppError::Unauthorized(format!("failed to validate source token: {error}"))
            })?;
        debug!(subject = %claims.subject(), "source token claims validated");
        Ok(claims)
    }

    pub fn auth_enabled(&self) -> bool {
        matches!(self.mode, SubjectValidationMode::Enabled(_))
    }
}

fn unauthenticated_claims() -> authzoo::ValidatedClaims {
    serde_json::from_value(serde_json::json!({ "sub": "unauthenticated" }))
        .expect("static unauthenticated claims must deserialize")
}

#[cfg(test)]
mod tests {
    use super::{AppState, SubjectValidator};
    use crate::config::{AccessPolicyConfig, GithubAppConfig, KeySource};
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use std::sync::Arc;

    #[test]
    fn access_policies_returns_all_policies_for_github_app() {
        let state = AppState {
            github_apps: Arc::new(vec![GithubAppConfig {
                name: "default".to_string(),
                app_id: 42,
                secret_key: "private-key.pem".to_string(),
            }]),
            access_policies: Arc::new(vec![
                AccessPolicyConfig {
                    github_app: "default".to_string(),
                    role: Some("buildkite-deploy".to_string()),
                },
                AccessPolicyConfig {
                    github_app: "default".to_string(),
                    role: Some("kubernetes-deploy".to_string()),
                },
                AccessPolicyConfig {
                    github_app: "release-bot".to_string(),
                    role: Some("kubernetes-release".to_string()),
                },
            ]),
            subject_validator: SubjectValidator::new(Vec::new(), true).unwrap(),
            github: GithubClient::new().unwrap(),
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        };

        let policies = state.access_policies("default", "noa/idcat").unwrap();

        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].role.as_deref(), Some("buildkite-deploy"));
        assert_eq!(policies[1].role.as_deref(), Some("kubernetes-deploy"));
    }
}

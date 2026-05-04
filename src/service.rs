// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::auth;
use crate::config::{
    AccessPolicyConfig, Config, GithubAppConfig, IdentityProviderConfig, KeySource,
};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use crate::signer::{LocalSigner, Signer};
use jsonwebtoken::{Validation, decode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
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
        subject_validator: SubjectValidator::new(config.identity_providers.clone(), disable_auth),
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
        access_policy: &AccessPolicyConfig,
        claims: &SourceClaims,
    ) -> Result<(), AppError> {
        let subject = claims.subject();
        if self.subject_validator.auth_enabled()
            && let Some((claim_name, required_value)) =
                claims.first_missing_required_claim(&access_policy.required_claims)
        {
            return Err(AppError::Unauthorized(format!(
                "claim '{claim_name}' must equal '{required_value}' to use repo '{repo}' with github_app '{github_app_name}'"
            )));
        }

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
    Enabled(BTreeMap<String, IdentityProviderConfig>),
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceClaims {
    sub: String,
    #[serde(flatten)]
    claims: BTreeMap<String, Value>,
}

impl SourceClaims {
    fn unauthenticated() -> Self {
        Self {
            sub: "unauthenticated".to_string(),
            claims: BTreeMap::new(),
        }
    }

    pub fn subject(&self) -> &str {
        &self.sub
    }

    fn first_missing_required_claim<'a>(
        &self,
        required_claims: &'a BTreeMap<String, String>,
    ) -> Option<(&'a str, &'a str)> {
        required_claims
            .iter()
            .find(|(claim_name, required_value)| {
                self.claim_value(claim_name.as_str()) != Some(required_value.as_str())
            })
            .map(|(claim_name, required_value)| (claim_name.as_str(), required_value.as_str()))
    }

    fn claim_value(&self, claim_name: &str) -> Option<&str> {
        if claim_name == "sub" {
            return Some(&self.sub);
        }
        self.claims.get(claim_name).and_then(Value::as_str)
    }
}

impl SubjectValidator {
    pub fn new(identity_providers: Vec<IdentityProviderConfig>, disable_auth: bool) -> Self {
        let mode = if disable_auth {
            SubjectValidationMode::Disabled
        } else {
            let identity_providers = identity_providers
                .into_iter()
                .map(|identity_provider| (identity_provider.name.clone(), identity_provider))
                .collect();
            SubjectValidationMode::Enabled(identity_providers)
        };
        Self { mode }
    }

    pub fn validate(
        &self,
        identity_provider: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<SourceClaims, AppError> {
        let authentication = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("source token claim validation skipped because auth is disabled");
                return Ok(SourceClaims::unauthenticated());
            }
            SubjectValidationMode::Enabled(identity_providers) => {
                let identity_provider = identity_provider.ok_or_else(|| {
                    AppError::Internal(
                        "access-policy is missing an identity-provider reference".to_string(),
                    )
                })?;
                identity_providers.get(identity_provider).ok_or_else(|| {
                    AppError::Internal(format!(
                        "access-policy references unknown identity-provider '{identity_provider}'"
                    ))
                })?
            }
        };
        let bearer_token = bearer_token
            .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
        let algorithm = auth::algorithm(authentication)?;
        debug!(
            algorithm = ?algorithm,
            audience = %authentication.audience,
            issuer = %authentication.issuer,
            "validating source token claims"
        );
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&authentication.audience]);
        validation.set_issuer(&[&authentication.issuer]);
        debug!("resolving source token decoding key");
        let decoding_key =
            auth::resolving_decoding_key(authentication, bearer_token).map_err(AppError::from)?;

        let decoded =
            decode::<SourceClaims>(bearer_token, &decoding_key, &validation).map_err(|error| {
                AppError::Unauthorized(format!("failed to validate source token: {error}"))
            })?;
        debug!(subject = %decoded.claims.sub, "source token claims validated");
        Ok(decoded.claims)
    }

    pub fn auth_enabled(&self) -> bool {
        matches!(self.mode, SubjectValidationMode::Enabled(_))
    }
}

#[cfg(test)]
mod tests {
    use super::{AppState, SourceClaims, SubjectValidator};
    use crate::config::{AccessPolicyConfig, GithubAppConfig, KeySource};
    use crate::github::GithubClient;
    use crate::secret::FilePrivateKeyStore;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[test]
    fn required_claims_match_subject_and_custom_claims() {
        let claims: SourceClaims = serde_json::from_value(json!({
            "sub": "system:serviceaccount:default:default",
            "organization_slug": "my-buildkite-org",
            "pipeline_slug": "deploy-idcat"
        }))
        .unwrap();
        let required_claims = BTreeMap::from([
            (
                "organization_slug".to_string(),
                "my-buildkite-org".to_string(),
            ),
            ("pipeline_slug".to_string(), "deploy-idcat".to_string()),
            (
                "sub".to_string(),
                "system:serviceaccount:default:default".to_string(),
            ),
        ]);

        assert_eq!(claims.first_missing_required_claim(&required_claims), None);
    }

    #[test]
    fn required_claims_reject_missing_or_different_values() {
        let claims: SourceClaims = serde_json::from_value(json!({
            "sub": "system:serviceaccount:default:default",
            "pipeline_slug": "other-pipeline"
        }))
        .unwrap();
        let required_claims = BTreeMap::from([
            (
                "organization_slug".to_string(),
                "my-buildkite-org".to_string(),
            ),
            ("pipeline_slug".to_string(), "deploy-idcat".to_string()),
        ]);

        assert_eq!(
            claims.first_missing_required_claim(&required_claims),
            Some(("organization_slug", "my-buildkite-org"))
        );
    }

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
                    identity_provider: Some("buildkite".to_string()),
                    required_claims: BTreeMap::from([(
                        "pipeline_slug".to_string(),
                        "deploy-idcat".to_string(),
                    )]),
                },
                AccessPolicyConfig {
                    github_app: "default".to_string(),
                    identity_provider: Some("kubernetes".to_string()),
                    required_claims: BTreeMap::from([(
                        "sub".to_string(),
                        "system:serviceaccount:default:default".to_string(),
                    )]),
                },
                AccessPolicyConfig {
                    github_app: "release-bot".to_string(),
                    identity_provider: Some("kubernetes".to_string()),
                    required_claims: BTreeMap::new(),
                },
            ]),
            subject_validator: SubjectValidator::new(Vec::new(), true),
            github: GithubClient::new().unwrap(),
            key_source: KeySource::Local,
            private_key_store: FilePrivateKeyStore::new("/var/run/secrets/idcat"),
            #[cfg(feature = "kms")]
            kms_signers: None,
        };

        let policies = state.access_policies("default", "noa/idcat").unwrap();

        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].identity_provider.as_deref(), Some("buildkite"));
        assert_eq!(policies[1].identity_provider.as_deref(), Some("kubernetes"));
    }
}

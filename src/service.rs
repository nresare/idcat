// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::auth;
use crate::config::{AuthenticationConfig, Config, GithubAppConfig, InstallationConfig, KeySource};
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
    pub installations: Arc<Vec<InstallationConfig>>,
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
        installations: Arc::new(config.installations.clone()),
        subject_validator: SubjectValidator::new(config.authentication.clone(), disable_auth),
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

    pub fn installation(
        &self,
        github_app_name: &str,
        repo: &str,
        claims: &SourceClaims,
    ) -> Result<&InstallationConfig, AppError> {
        let subject = claims.subject();
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            subject = %subject,
            "searching configured installations"
        );
        let installation = self
            .installations
            .iter()
            .find(|installation| installation.github_app == github_app_name)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "unknown installation for github_app '{github_app_name}'"
                ))
            })?;

        if self.subject_validator.auth_enabled()
            && let Some((claim_name, required_value)) =
                claims.first_missing_required_claim(&installation.required_claims)
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
            "installation authorization check passed"
        );
        Ok(installation)
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
    Enabled(AuthenticationConfig),
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
    pub fn new(authentication: AuthenticationConfig, disable_auth: bool) -> Self {
        let mode = if disable_auth {
            SubjectValidationMode::Disabled
        } else {
            SubjectValidationMode::Enabled(authentication)
        };
        Self { mode }
    }

    pub fn validate(&self, bearer_token: Option<&str>) -> Result<SourceClaims, AppError> {
        let authentication = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("source token claim validation skipped because auth is disabled");
                return Ok(SourceClaims::unauthenticated());
            }
            SubjectValidationMode::Enabled(authentication) => authentication,
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
    use super::SourceClaims;
    use serde_json::json;
    use std::collections::BTreeMap;

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
}

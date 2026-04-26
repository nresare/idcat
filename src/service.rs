use crate::auth;
use crate::config::{AuthenticationConfig, Config, InstallationConfig};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use jsonwebtoken::{decode, Validation};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub installations: Arc<Vec<InstallationConfig>>,
    pub subject_validator: SubjectValidator,
    pub github: GithubClient,
    pub private_key_store: FilePrivateKeyStore,
}

pub fn build_app_state(config: &Config) -> anyhow::Result<AppState> {
    Ok(AppState {
        installations: Arc::new(config.installations.clone()),
        subject_validator: SubjectValidator::new(config.authentication.clone()),
        github: GithubClient::new(config.github_api_url.clone(), config.github_app_id)?,
        private_key_store: FilePrivateKeyStore::new(&config.private_key_directory),
    })
}

impl AppState {
    pub fn installation(&self, repo: &str, subject: &str) -> Result<&InstallationConfig, AppError> {
        let installation = self
            .installations
            .iter()
            .find(|installation| installation.repo == repo)
            .ok_or_else(|| AppError::NotFound(format!("unknown installation repo '{repo}'")))?;

        if !installation
            .allowed_subjects
            .iter()
            .any(|allowed_subject| allowed_subject == subject)
        {
            return Err(AppError::Unauthorized(format!(
                "subject '{subject}' is not allowed to use repo '{repo}'"
            )));
        }

        Ok(installation)
    }
}

#[derive(Clone)]
pub struct SubjectValidator {
    authentication: AuthenticationConfig,
}

#[derive(Debug, Deserialize)]
struct SourceClaims {
    sub: String,
}

impl SubjectValidator {
    pub fn new(authentication: AuthenticationConfig) -> Self {
        Self { authentication }
    }

    pub fn validate(&self, bearer_token: &str) -> Result<String, AppError> {
        let algorithm = auth::algorithm(&self.authentication)?;
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.authentication.audience]);
        validation.set_issuer(&[&self.authentication.issuer]);
        let decoding_key = auth::resolving_decoding_key(&self.authentication, bearer_token)
            .map_err(AppError::from)?;

        let decoded =
            decode::<SourceClaims>(bearer_token, &decoding_key, &validation).map_err(|error| {
                AppError::Unauthorized(format!("failed to validate source token: {error}"))
            })?;
        Ok(decoded.claims.sub)
    }
}

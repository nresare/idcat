// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::auth;
use crate::config::{AuthenticationConfig, Config, InstallationConfig};
use crate::error::AppError;
use crate::github::GithubClient;
use crate::secret::FilePrivateKeyStore;
use jsonwebtoken::{Validation, decode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct AppState {
    pub installations: Arc<Vec<InstallationConfig>>,
    pub subject_validator: SubjectValidator,
    pub github: GithubClient,
    pub private_key_store: FilePrivateKeyStore,
}

pub fn build_app_state(config: &Config, disable_auth: bool) -> anyhow::Result<AppState> {
    Ok(AppState {
        installations: Arc::new(config.installations.clone()),
        subject_validator: SubjectValidator::new(config.authentication.clone(), disable_auth),
        github: GithubClient::new(config.github_api_url.clone(), config.github_app_id)?,
        private_key_store: FilePrivateKeyStore::new(&config.private_key_directory),
    })
}

impl AppState {
    pub fn installation(&self, repo: &str, subject: &str) -> Result<&InstallationConfig, AppError> {
        debug!(repo = %repo, subject = %subject, "searching configured installations");
        let installation = self
            .installations
            .iter()
            .find(|installation| installation.repo == repo)
            .ok_or_else(|| AppError::NotFound(format!("unknown installation repo '{repo}'")))?;

        if self.subject_validator.auth_enabled()
            && !installation
                .allowed_subjects
                .iter()
                .any(|allowed_subject| allowed_subject == subject)
        {
            return Err(AppError::Unauthorized(format!(
                "subject '{subject}' is not allowed to use repo '{repo}'"
            )));
        }

        debug!(
            repo = %repo,
            subject = %subject,
            auth_enabled = self.subject_validator.auth_enabled(),
            "installation authorization check passed"
        );
        Ok(installation)
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

#[derive(Debug, Deserialize)]
struct SourceClaims {
    sub: String,
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

    pub fn validate(&self, bearer_token: Option<&str>) -> Result<String, AppError> {
        let authentication = match &self.mode {
            SubjectValidationMode::Disabled => {
                debug!("source subject validation skipped because auth is disabled");
                return Ok("unauthenticated".to_string());
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
        Ok(decoded.claims.sub)
    }

    pub fn auth_enabled(&self) -> bool {
        matches!(self.mode, SubjectValidationMode::Enabled(_))
    }
}

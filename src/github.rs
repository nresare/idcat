use crate::config::InstallationConfig;
use crate::jwt::build_github_app_jwt;
use anyhow::Context;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const GITHUB_API_VERSION_HEADER: &str = "X-GitHub-Api-Version";
const GITHUB_API_VERSION: &str = "2022-11-28";

#[derive(Clone)]
pub struct GithubClient {
    client: Client,
    api_url: String,
    app_id: u64,
}

#[derive(Debug, Serialize)]
struct CreateInstallationTokenRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_ids: Option<&'a [u64]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<&'a BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct RepositoryInstallationResponse {
    id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationTokenResponse {
    pub token: String,
    pub expires_at: String,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default)]
    pub repository_selection: Option<String>,
}

impl GithubClient {
    pub fn new(api_url: String, app_id: u64) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("idcat"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github+json"),
        );
        headers.insert(
            GITHUB_API_VERSION_HEADER,
            HeaderValue::from_static(GITHUB_API_VERSION),
        );
        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("failed to build GitHub API client")?;
        Ok(Self {
            client,
            api_url: api_url.trim_end_matches('/').to_string(),
            app_id,
        })
    }

    pub async fn create_installation_token(
        &self,
        private_key_pem: &str,
        installation: &InstallationConfig,
    ) -> anyhow::Result<InstallationTokenResponse> {
        let jwt = build_github_app_jwt(self.app_id, private_key_pem)?;
        let installation_id = self
            .repository_installation_id(&jwt, &installation.repo)
            .await?;
        let request = CreateInstallationTokenRequest {
            repository_ids: None,
            permissions: optional_map(&installation.permissions),
        };
        let response = self
            .client
            .post(format!(
                "{}/app/installations/{}/access_tokens",
                self.api_url, installation_id
            ))
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .json(&request)
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to request installation access token for '{}'",
                    installation.repo
                )
            })?;

        response
            .error_for_status()
            .with_context(|| {
                format!(
                    "GitHub installation access token request for '{}' returned an error status",
                    installation.repo
                )
            })?
            .json()
            .await
            .with_context(|| {
                format!(
                    "failed to parse GitHub installation access token response for '{}'",
                    installation.repo
                )
            })
    }

    async fn repository_installation_id(&self, jwt: &str, repo: &str) -> anyhow::Result<u64> {
        let (owner, repo_name) = repo
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("repo '{repo}' must use owner/repo format"))?;
        let installation: RepositoryInstallationResponse = self
            .client
            .get(format!(
                "{}/repos/{}/{}/installation",
                self.api_url, owner, repo_name
            ))
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .send()
            .await
            .with_context(|| format!("failed to resolve GitHub App installation for '{repo}'"))?
            .error_for_status()
            .with_context(|| {
                format!("GitHub App installation lookup for '{repo}' returned an error status")
            })?
            .json()
            .await
            .with_context(|| {
                format!("failed to parse GitHub App installation lookup response for '{repo}'")
            })?;
        Ok(installation.id)
    }
}

fn optional_map(values: &BTreeMap<String, String>) -> Option<&BTreeMap<String, String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

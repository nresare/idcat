// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::{GithubAppConfig, InstallationConfig};
use crate::jwt::build_github_app_jwt;
use anyhow::Context;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, USER_AGENT,
};
use reqwest::{Client, Method, Response};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::debug;

const GITHUB_API_VERSION_HEADER: &str = "X-GitHub-Api-Version";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_API_URL: &str = "https://api.github.com";
const INSTALLATION_TOKEN_CACHE_TTL: Duration = Duration::from_secs(50 * 60);

#[derive(Clone)]
pub struct GithubClient {
    client: Client,
    api_url: String,
    cache: Arc<Mutex<GithubCache>>,
}

#[derive(Default)]
struct GithubCache {
    installation_ids: BTreeMap<String, u64>,
    installation_tokens: BTreeMap<InstallationTokenCacheKey, CachedInstallationToken>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct InstallationTokenCacheKey {
    github_app: String,
    repo: String,
    permissions: BTreeMap<String, String>,
}

#[derive(Clone)]
struct CachedInstallationToken {
    token: InstallationTokenResponse,
    refresh_after: Instant,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallationTokenResponse {
    pub token: String,
    pub expires_at: String,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default)]
    pub repository_selection: Option<String>,
}

impl GithubClient {
    pub fn new() -> anyhow::Result<Self> {
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
            api_url: GITHUB_API_URL.to_string(),
            cache: Arc::new(Mutex::new(GithubCache::default())),
        })
    }

    pub async fn create_installation_token(
        &self,
        github_app: &GithubAppConfig,
        private_key_pem: &str,
        repo: &str,
        installation: &InstallationConfig,
    ) -> anyhow::Result<InstallationTokenResponse> {
        let token_cache_key = InstallationTokenCacheKey {
            github_app: github_app.name.clone(),
            repo: repo.to_string(),
            permissions: installation.permissions.clone(),
        };
        if let Some(token) = self.cached_installation_token(&token_cache_key).await {
            debug!(
                github_app = %github_app.name,
                repo = %repo,
                "using cached GitHub installation access token"
            );
            return Ok(token);
        }
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            "cached GitHub installation access token not found or expired"
        );
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            app_id = github_app.app_id,
            "building GitHub App JWT"
        );
        let jwt = build_github_app_jwt(github_app.app_id, private_key_pem)?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            "resolving GitHub App installation id"
        );
        let installation_id = self
            .cached_repository_installation_id(&jwt, &github_app.name, repo)
            .await?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            "resolved GitHub App installation id"
        );
        let request = CreateInstallationTokenRequest {
            repository_ids: None,
            permissions: optional_map(&installation.permissions),
        };
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            permission_count = installation.permissions.len(),
            "sending GitHub installation access token request"
        );
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
                    "failed to request installation access token for '{}' with github_app '{}'",
                    repo, github_app.name
                )
            })?;

        let token: InstallationTokenResponse = response
            .error_for_status()
            .with_context(|| {
                format!(
                    "GitHub installation access token request for '{}' with github_app '{}' returned an error status",
                    repo, github_app.name
                )
            })?
            .json()
            .await
            .with_context(|| {
                format!(
                    "failed to parse GitHub installation access token response for '{}' with github_app '{}'",
                    repo, github_app.name
                )
            })?;
        debug!(
            github_app = %github_app.name,
            repo = %repo,
            installation_id,
            expires_at = %token.expires_at,
            repository_selection = ?token.repository_selection,
            "parsed GitHub installation access token response"
        );
        self.cache_installation_token(token_cache_key, token.clone())
            .await;
        Ok(token)
    }

    pub async fn proxy_request(
        &self,
        method: Method,
        github_path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Vec<u8>,
        installation_token: &str,
    ) -> anyhow::Result<Response> {
        let url = self.proxy_url(github_path, query);
        debug!(method = %method, url = %url, "forwarding proxied GitHub API request");
        self.client
            .request(method, url)
            .headers(proxy_headers(headers, installation_token)?)
            .body(body)
            .send()
            .await
            .context("failed to forward proxied GitHub API request")
    }

    async fn repository_installation_id(&self, jwt: &str, repo: &str) -> anyhow::Result<u64> {
        let (owner, repo_name) = repo
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("repo '{repo}' must use owner/repo format"))?;
        debug!(repo = %repo, owner = %owner, repo_name = %repo_name, "looking up repository installation");
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
        debug!(repo = %repo, installation_id = installation.id, "repository installation lookup parsed");
        Ok(installation.id)
    }

    async fn cached_repository_installation_id(
        &self,
        jwt: &str,
        github_app_name: &str,
        repo: &str,
    ) -> anyhow::Result<u64> {
        let cache_key = format!("{github_app_name}/{repo}");
        if let Some(installation_id) = self
            .cache
            .lock()
            .await
            .installation_ids
            .get(&cache_key)
            .copied()
        {
            debug!(
                github_app = %github_app_name,
                repo = %repo,
                installation_id,
                "using cached GitHub App installation id"
            );
            return Ok(installation_id);
        }
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            "cached GitHub App installation id not found"
        );
        let installation_id = self.repository_installation_id(jwt, repo).await?;
        self.cache
            .lock()
            .await
            .installation_ids
            .insert(cache_key, installation_id);
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            installation_id,
            "cached GitHub App installation id"
        );
        Ok(installation_id)
    }

    async fn cached_installation_token(
        &self,
        key: &InstallationTokenCacheKey,
    ) -> Option<InstallationTokenResponse> {
        let now = Instant::now();
        self.cache
            .lock()
            .await
            .installation_tokens
            .get(key)
            .filter(|cached| cached.refresh_after > now)
            .map(|cached| cached.token.clone())
    }

    async fn cache_installation_token(
        &self,
        key: InstallationTokenCacheKey,
        token: InstallationTokenResponse,
    ) {
        let refresh_after = Instant::now() + INSTALLATION_TOKEN_CACHE_TTL;
        self.cache.lock().await.installation_tokens.insert(
            key,
            CachedInstallationToken {
                token,
                refresh_after,
            },
        );
    }

    fn proxy_url(&self, github_path: &str, query: Option<&str>) -> String {
        let path = github_path.trim_start_matches('/');
        match query {
            Some(query) if !query.is_empty() => format!("{}/{path}?{query}", self.api_url),
            _ => format!("{}/{path}", self.api_url),
        }
    }
}

fn optional_map(values: &BTreeMap<String, String>) -> Option<&BTreeMap<String, String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn proxy_headers(headers: &HeaderMap, installation_token: &str) -> anyhow::Result<HeaderMap> {
    let mut proxied = HeaderMap::new();
    for (name, value) in headers {
        if should_forward_header(name) {
            proxied.insert(name.clone(), value.clone());
        }
    }
    proxied.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {installation_token}"))
            .context("failed to build proxied GitHub Authorization header")?,
    );
    Ok(proxied)
}

fn should_forward_header(name: &HeaderName) -> bool {
    !matches!(
        name,
        &AUTHORIZATION
            | &HOST
            | &CONTENT_LENGTH
            | &reqwest::header::CONNECTION
            | &reqwest::header::PROXY_AUTHENTICATE
            | &reqwest::header::PROXY_AUTHORIZATION
            | &reqwest::header::TE
            | &reqwest::header::TRAILER
            | &reqwest::header::TRANSFER_ENCODING
            | &reqwest::header::UPGRADE
    )
}

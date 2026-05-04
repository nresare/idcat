// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

mod auth;
mod config;
mod error;
mod github;
mod jwt;
#[cfg(feature = "kms")]
#[allow(dead_code)]
mod kms;
mod kubernetes;
mod secret;
mod service;
mod signer;

use crate::config::Config;
use crate::error::AppError;
use crate::github::InstallationTokenResponse;
use crate::service::{AppState, build_app_state};
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, Path, State};
use axum::http::{HeaderMap, HeaderName, Method, Uri, header};
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::{Json, Router};
use clap::Parser;
use serde_json::{Value, json};
use std::net::SocketAddr;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Cli {
    #[arg(
        name = "config-file",
        short = 'c',
        long = "config-file",
        default_value = "/config/idcat.toml"
    )]
    config_path: String,
    #[arg(long = "disable-auth", default_value_t = false)]
    disable_auth: bool,
    #[arg(long = "debug", default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log_filter = if cli.debug {
        "idcat=debug,tower_http=info,axum::rejection=trace"
    } else {
        "idcat=info,tower_http=info,axum::rejection=info"
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(log_filter))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run(cli).await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(&cli.config_path)?;
    config.validate(cli.disable_auth)?;
    let bind_address: SocketAddr = config.bind_address.parse()?;

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        disable_auth = cli.disable_auth,
        debug = cli.debug,
        "starting idcat"
    );

    let state = build_app_state(&config, cli.disable_auth).await?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/installation-token/{github_app}/{owner}/{repo}",
            post(installation_token),
        )
        .route(
            "/proxy/{github_app}/repos/{owner}/{repo}",
            any(proxy_repo_root),
        )
        .route(
            "/proxy/{github_app}/repos/{owner}/{repo}/{*repo_path}",
            any(proxy_repo_path),
        )
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    info!(address = %bind_address, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn installation_token(
    Path((github_app, owner, repo)): Path<(String, String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, AppError> {
    let repo = format!("{owner}/{repo}");
    let token = create_installation_token_for_repo(&github_app, &repo, &state, &headers).await?;
    Ok(token.token)
}

async fn proxy_repo_root(
    Path((github_app, owner, repo)): Path<(String, String, String)>,
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    proxy_repo_request(ProxyRepoRequest {
        github_app,
        owner,
        repo_name: repo,
        repo_path: None,
        state,
        original_uri,
        method,
        headers,
        body,
    })
    .await
}

async fn proxy_repo_path(
    Path((github_app, owner, repo, repo_path)): Path<(String, String, String, String)>,
    State(state): State<AppState>,
    OriginalUri(original_uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    proxy_repo_request(ProxyRepoRequest {
        github_app,
        owner,
        repo_name: repo,
        repo_path: Some(repo_path),
        state,
        original_uri,
        method,
        headers,
        body,
    })
    .await
}

struct ProxyRepoRequest {
    github_app: String,
    owner: String,
    repo_name: String,
    repo_path: Option<String>,
    state: AppState,
    original_uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
}

async fn proxy_repo_request(request: ProxyRepoRequest) -> Result<Response, AppError> {
    let ProxyRepoRequest {
        github_app,
        owner,
        repo_name,
        repo_path,
        state,
        original_uri,
        method,
        headers,
        body,
    } = request;
    let repo = format!("{owner}/{repo_name}");
    let github_path = match repo_path {
        Some(repo_path) => format!("repos/{repo}/{repo_path}"),
        None => format!("repos/{repo}"),
    };
    debug!(
        github_app = %github_app,
        repo = %repo,
        github_path = %github_path,
        method = %method,
        "proxy request received"
    );
    let token = create_installation_token_for_repo(&github_app, &repo, &state, &headers).await?;
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|error| AppError::Internal(format!("failed to convert HTTP method: {error}")))?;
    let upstream_response = state
        .github
        .proxy_request(
            reqwest_method,
            &github_path,
            original_uri.query(),
            &headers,
            body.to_vec(),
            &token.token,
        )
        .await?;
    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let upstream_body = upstream_response
        .bytes()
        .await
        .map_err(|error| AppError::Internal(format!("failed to read proxied response: {error}")))?;
    debug!(
        github_app = %github_app,
        repo = %repo,
        github_path = %github_path,
        status = status.as_u16(),
        "proxy response received"
    );
    let mut response = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if should_return_proxy_header(name) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from(upstream_body))
        .map_err(|error| AppError::Internal(format!("failed to build proxied response: {error}")))
}

async fn create_installation_token_for_repo(
    github_app_name: &str,
    repo: &str,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<InstallationTokenResponse, AppError> {
    debug!(github_app = %github_app_name, repo = %repo, "installation token flow started");
    let bearer_token = match extract_bearer_token(headers) {
        Ok(token) => {
            debug!(github_app = %github_app_name, repo = %repo, "authorization bearer token found");
            Some(token)
        }
        Err(error) if !state.subject_validator.auth_enabled() => {
            debug!(
                github_app = %github_app_name,
                repo = %repo,
                error = %error,
                "authorization bearer token missing or invalid; continuing because auth is disabled"
            );
            None
        }
        Err(error) => return Err(error),
    };
    debug!(github_app = %github_app_name, repo = %repo, "selecting GitHub App config");
    let github_app = state.github_app(github_app_name)?;
    debug!(github_app = %github_app_name, repo = %repo, "selecting access policy");
    let access_policies = state.access_policies(github_app_name, repo)?;
    let mut source_claims = None;
    let mut last_authorization_error = None;
    for access_policy in access_policies {
        debug!(
            github_app = %github_app_name,
            repo = %repo,
            identity_provider = ?access_policy.identity_provider,
            "validating source token claims against access policy"
        );
        match state.subject_validator.validate(
            access_policy.identity_provider.as_deref(),
            bearer_token.as_deref(),
        ) {
            Ok(claims) => {
                let source_subject = claims.subject();
                debug!(github_app = %github_app_name, repo = %repo, subject = %source_subject, "source token claims accepted");
                match state.authorize_access_policy(github_app_name, repo, access_policy, &claims) {
                    Ok(()) => {
                        source_claims = Some(claims);
                        break;
                    }
                    Err(error) => {
                        debug!(github_app = %github_app_name, repo = %repo, error = %error, "access policy did not authorize source claims");
                        last_authorization_error = Some(error);
                    }
                }
            }
            Err(error) => {
                debug!(github_app = %github_app_name, repo = %repo, error = %error, "source token did not validate against access policy");
                last_authorization_error = Some(error);
            }
        }
    }
    let source_claims = source_claims.ok_or_else(|| match last_authorization_error {
        Some(AppError::Internal(error)) => AppError::Internal(error),
        Some(error) => AppError::Unauthorized(format!(
            "no access-policy authorized repo '{repo}' with github_app '{github_app_name}': {error}"
        )),
        None => AppError::Unauthorized(format!(
            "no access-policy authorized repo '{repo}' with github_app '{github_app_name}'"
        )),
    })?;
    let source_subject = source_claims.subject();
    debug!(
        github_app = %github_app_name,
        repo = %repo,
        subject = %source_subject,
        secret_key = %github_app.secret_key,
        "access policy selected"
    );
    debug!(github_app = %github_app_name, repo = %repo, secret_key = %github_app.secret_key, key_source = ?state.key_source, "preparing GitHub App signer");
    let signer = state.signer(&github_app.secret_key)?;
    debug!(github_app = %github_app_name, repo = %repo, "requesting GitHub installation access token");
    let token = state
        .github
        .create_installation_token(github_app, signer.as_ref(), repo)
        .await?;
    debug!(github_app = %github_app_name, repo = %repo, expires_at = %token.expires_at, "GitHub installation access token created");
    Ok(token)
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected a Bearer token".to_string()))?;
    if token.is_empty() {
        return Err(AppError::Unauthorized("empty bearer token".to_string()));
    }
    Ok(token.to_string())
}

fn should_return_proxy_header(name: &HeaderName) -> bool {
    !matches!(
        name,
        &header::CONNECTION
            | &header::PROXY_AUTHENTICATE
            | &header::PROXY_AUTHORIZATION
            | &header::TE
            | &header::TRAILER
            | &header::TRANSFER_ENCODING
            | &header::UPGRADE
    )
}

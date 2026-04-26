mod auth;
mod config;
mod error;
mod github;
mod jwt;
mod kubernetes;
mod secret;
mod service;

use crate::config::Config;
use crate::error::AppError;
use crate::github::InstallationTokenResponse;
use crate::service::{build_app_state, AppState};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "idcat=debug,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .init();

    if let Err(error) = run().await {
        error!("{error:#}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config_path)?;
    config.validate()?;
    let bind_address: SocketAddr = config.bind_address.parse()?;

    info!(
        version = VERSION,
        config_path = %cli.config_path,
        "starting idcat"
    );

    let state = build_app_state(&config)?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/installation-token/{owner}/{repo}",
            post(installation_token),
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
    Path((owner, repo)): Path<(String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InstallationTokenResponse>, AppError> {
    let bearer_token = extract_bearer_token(&headers)?;
    let source_subject = state.subject_validator.validate(&bearer_token)?;
    let repo = format!("{owner}/{repo}");
    let installation = state.installation(&repo, &source_subject)?;
    let private_key_pem = state
        .private_key_store
        .private_key_pem(&installation.secret_key)?;
    let token = state
        .github
        .create_installation_token(&private_key_pem, installation)
        .await?;
    Ok(Json(token))
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

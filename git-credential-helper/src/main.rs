mod config;
mod credential;
mod idcat;
mod token_source;

use crate::config::Config;
use crate::credential::{
    is_github_https_request, read_credential_from_stdin, repo_from_credential,
};
use crate::idcat::fetch_installation_token;
use crate::token_source::run_token_source;
use clap::Parser;
use std::env;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    if let Err(error) = run() {
        eprintln!("Fatal error, exiting: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    init_logging();

    let cli = Cli::parse();
    if !matches!(cli.action.as_deref(), Some("fill") | Some("get")) {
        info!(
            action = ?cli.action,
            "exiting without output because the credential helper action is not supported"
        );
        return Ok(());
    }

    let config = Config::load(cli.config_path)?;
    let credential = read_credential_from_stdin()?;
    if !is_github_https_request(&credential) {
        info!(
            protocol = ?credential.get("protocol"),
            host = ?credential.get("host"),
            "exiting without output because the request is not for https://github.com"
        );
        return Ok(());
    }

    let repo = match repo_from_credential(&credential) {
        Some(repo) => repo,
        None => {
            info!(
                path = ?credential.get("path"),
                "exiting without output because the GitHub HTTPS request did not include an owner/repo path"
            );
            return Ok(());
        }
    };

    info!(
        token_source = %config.token_source,
        "requesting bearer token from token-source"
    );
    let oidc_token = run_token_source(&config.token_source)?;
    info!("bearer token obtained from token-source");
    let installation_token = fetch_installation_token(&config, &repo, &oidc_token)?;

    println!("username=x-access-token");
    println!("password={installation_token}");
    println!();

    Ok(())
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long = "config", short = 'c')]
    config_path: Option<PathBuf>,

    #[arg()]
    action: Option<String>,
}

fn init_logging() {
    tracing_subscriber::registry()
        .with(EnvFilter::new(env::var("RUST_LOG").unwrap_or_else(|_| {
            "git_credential_helper_idcat=info".to_owned()
        })))
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(std::io::stderr),
        )
        .init();
}

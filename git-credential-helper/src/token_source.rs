use crate::config::TokenSource;
use anyhow::{Context, bail};
use std::path::Path;
use std::process::Command;

pub fn read_token(source: &TokenSource) -> anyhow::Result<String> {
    match source {
        TokenSource::Path(path) => read_token_path(path),
        TokenSource::Command(command) => run_token_command(command),
    }
}

fn read_token_path(path: &Path) -> anyhow::Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read token-path: {}", path.display()))?;
    trim_token(token, "token-path produced an empty token")
}

fn run_token_command(command: &str) -> anyhow::Result<String> {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("failed to execute token-command: {command}"))?;

    if !output.status.success() {
        bail!(
            "token-command exited with status {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
        );
    }

    let token = String::from_utf8(output.stdout).context("token-command output was not UTF-8")?;
    trim_token(token, "token-command produced an empty token")
}

fn trim_token(token: String, empty_message: &str) -> anyhow::Result<String> {
    let token = token.trim();
    if token.is_empty() {
        bail!("{empty_message}");
    }

    Ok(token.to_owned())
}

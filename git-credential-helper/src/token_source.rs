use anyhow::{Context, bail};
use std::process::Command;

pub fn run_token_source(command: &str) -> anyhow::Result<String> {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .with_context(|| format!("failed to execute token-source command: {command}"))?;

    if !output.status.success() {
        bail!(
            "token-source command exited with status {}",
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
        );
    }

    let token = String::from_utf8(output.stdout).context("token-source output was not UTF-8")?;
    let token = token.trim();
    if token.is_empty() {
        bail!("token-source produced an empty token");
    }

    Ok(token.to_owned())
}

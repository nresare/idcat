use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use std::env;
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub github_app: String,
    pub idcat_endpoint: String,
    pub token_source: String,
}

impl Config {
    pub fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let path = match path {
            Some(path) => path,
            None => default_config_path()?,
        };
        let config = match std::fs::read_to_string(&path) {
            Ok(config) => config,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                bail!("configuration file not found: {}", path.display());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        toml::from_str(&config).with_context(|| format!("failed to parse {}", path.display()))
    }
}

fn default_config_path() -> anyhow::Result<PathBuf> {
    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("idcat")
        .join("credential-helper.toml"))
}

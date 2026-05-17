use anyhow::{Context, anyhow, bail};
use serde::Deserialize;
use std::env;
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawConfig {
    github_app: String,
    idcat_endpoint: String,
    token_path: Option<PathBuf>,
    token_command: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub github_app: String,
    pub idcat_endpoint: String,
    pub token_source: TokenSource,
}

#[derive(Debug)]
pub enum TokenSource {
    Path(PathBuf),
    Command(String),
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
        let config: RawConfig = toml::from_str(&config)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        config.try_into()
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = anyhow::Error;

    fn try_from(config: RawConfig) -> Result<Self, Self::Error> {
        let token_source = match (config.token_path, config.token_command) {
            (Some(path), None) => TokenSource::Path(path),
            (None, Some(command)) => TokenSource::Command(command),
            (None, None) => bail!("configuration must set either token-path or token-command"),
            (Some(_), Some(_)) => {
                bail!("configuration must not set both token-path and token-command")
            }
        };

        Ok(Self {
            github_app: config.github_app,
            idcat_endpoint: config.idcat_endpoint,
            token_source,
        })
    }
}

fn default_config_path() -> anyhow::Result<PathBuf> {
    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("idcat")
        .join("credential-helper.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_config() -> RawConfig {
        RawConfig {
            github_app: "deployments".to_owned(),
            idcat_endpoint: "https://idcat.example.test".to_owned(),
            token_path: None,
            token_command: None,
        }
    }

    #[test]
    fn accepts_token_path() {
        let config = RawConfig {
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        assert!(matches!(config.token_source, TokenSource::Path(_)));
    }

    #[test]
    fn accepts_token_command() {
        let config = RawConfig {
            token_command: Some("cat /var/run/secrets/tokens/idcat".to_owned()),
            ..raw_config()
        };

        let config = Config::try_from(config).expect("config validates");

        assert!(matches!(config.token_source, TokenSource::Command(_)));
    }

    #[test]
    fn rejects_missing_token_source() {
        let error = Config::try_from(raw_config()).expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("must set either token-path or token-command")
        );
    }

    #[test]
    fn rejects_multiple_token_sources() {
        let config = RawConfig {
            token_path: Some("/var/run/secrets/tokens/idcat".into()),
            token_command: Some("cat /var/run/secrets/tokens/idcat".to_owned()),
            ..raw_config()
        };

        let error = Config::try_from(config).expect_err("config should be rejected");

        assert!(
            error
                .to_string()
                .contains("must not set both token-path and token-command")
        );
    }
}

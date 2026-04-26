use anyhow::Context;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct FilePrivateKeyStore {
    directory: PathBuf,
}

impl FilePrivateKeyStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn private_key_pem(&self, secret_key: &str) -> anyhow::Result<String> {
        let path = self.path_for_key(secret_key)?;
        fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read GitHub App private key from '{}'",
                path.display()
            )
        })
    }

    fn path_for_key(&self, secret_key: &str) -> anyhow::Result<PathBuf> {
        if Path::new(secret_key).is_absolute() || secret_key.contains("..") {
            anyhow::bail!("secret_key must be a relative file name");
        }
        Ok(self.directory.join(secret_key))
    }
}

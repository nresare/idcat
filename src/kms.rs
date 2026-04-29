// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::signer::Signer;
use anyhow::Context;
use aws_sdk_kms::{
    Client as KmsClient,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use std::future::Future;
use std::pin::Pin;

#[derive(Clone, Debug)]
pub struct KmsSignerFactory {
    client: KmsClient,
}

impl KmsSignerFactory {
    pub async fn from_env() -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: KmsClient::new(&config),
        }
    }

    pub fn signer_for_secret_key(&self, secret_key: &str) -> KmsSigner {
        KmsSigner::new(self.client.clone(), key_alias_for_secret_key(secret_key))
    }
}

#[derive(Clone, Debug)]
pub struct KmsSigner {
    client: KmsClient,
    key_id: String,
}

impl KmsSigner {
    pub fn new(client: KmsClient, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }
}

impl Signer for KmsSigner {
    fn sign<'a>(
        &'a self,
        message: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            let response = self
                .client
                .sign()
                .key_id(&self.key_id)
                .message(Blob::new(message))
                .message_type(MessageType::Raw)
                .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
                .send()
                .await
                .context("failed to sign message with AWS KMS")?;
            let signature = response.signature().ok_or_else(|| {
                anyhow::anyhow!("AWS KMS sign response did not include a signature")
            })?;

            Ok(signature.as_ref().to_vec())
        })
    }
}

fn key_alias_for_secret_key(secret_key: &str) -> String {
    if secret_key.starts_with("alias/") {
        secret_key.to_string()
    } else {
        format!("alias/{secret_key}")
    }
}

#[cfg(test)]
mod tests {
    use super::key_alias_for_secret_key;

    #[test]
    fn builds_kms_alias_from_secret_key() {
        assert_eq!(key_alias_for_secret_key("deployments"), "alias/deployments");
        assert_eq!(
            key_alias_for_secret_key("alias/deployments"),
            "alias/deployments"
        );
    }
}

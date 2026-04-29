// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use aws_sdk_kms::{
    Client,
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
struct TestClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key_id = std::env::args()
        .nth(1)
        .map(|alias| key_alias(&alias))
        .ok_or_else(|| {
            anyhow::anyhow!("usage: cargo run --features kms --example kms_sign_jwt -- <key-alias>")
        })?;

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let client = Client::new(&config);

    println!("KMS key: {key_id}");
    println!();
    println!("{}", public_key_pem(&client, &key_id).await?);

    let now = now()?;
    for claims in [
        TestClaims {
            iss: "idcat-kms-example",
            sub: "test-subject-one",
            aud: "idcat",
            iat: now,
            exp: now + 600,
        },
        TestClaims {
            iss: "idcat-kms-example",
            sub: "test-subject-two",
            aud: "idcat",
            iat: now,
            exp: now + 600,
        },
    ] {
        println!("{}", sign_jwt(&client, &key_id, &claims).await?);
    }

    Ok(())
}

async fn sign_jwt<T: Serialize>(
    client: &Client,
    key_id: &str,
    claims: &T,
) -> anyhow::Result<String> {
    let header = Header::new(Algorithm::RS256);
    let encoded_header = encode_jwt_part(&header).context("failed to encode JWT header")?;
    let encoded_claims = encode_jwt_part(claims).context("failed to encode JWT claims")?;
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let response = client
        .sign()
        .key_id(key_id)
        .message(Blob::new(signing_input.as_bytes()))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
        .send()
        .await
        .context("failed to sign JWT with AWS KMS")?;
    let signature = response
        .signature()
        .ok_or_else(|| anyhow::anyhow!("AWS KMS sign response did not include a signature"))?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature.as_ref());

    Ok(format!("{signing_input}.{encoded_signature}"))
}

async fn public_key_pem(client: &Client, key_id: &str) -> anyhow::Result<String> {
    let response = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .context("failed to get public key from AWS KMS")?;
    let public_key = response
        .public_key()
        .ok_or_else(|| anyhow::anyhow!("AWS KMS get-public-key response did not include a key"))?;

    Ok(pem("PUBLIC KEY", public_key.as_ref()))
}

fn encode_jwt_part<T: Serialize>(input: &T) -> anyhow::Result<String> {
    let json = serde_json::to_vec(input)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

fn key_alias(alias: &str) -> String {
    if alias.starts_with("alias/") {
        alias.to_string()
    } else {
        format!("alias/{alias}")
    }
}

fn now() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| anyhow::anyhow!("system time error: {error}"))
}

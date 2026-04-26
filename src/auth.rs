// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::AuthenticationConfig;
use crate::kubernetes;
use anyhow::Context;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, decode_header};
use reqwest::blocking::Client;
use serde::Deserialize;
use tracing::{debug, info};

pub fn algorithm(authentication: &AuthenticationConfig) -> anyhow::Result<Algorithm> {
    match authentication.algorithm.as_str() {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        other => anyhow::bail!(
            "unsupported authentication algorithm '{other}'; supported values are RS256, RS384, RS512, ES256 and ES384"
        ),
    }
}

pub fn decoding_key(authentication: &AuthenticationConfig) -> anyhow::Result<DecodingKey> {
    let validation_key = authentication.validation_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("authentication.validation_key is required to validate source tokens")
    })?;
    match algorithm(authentication)? {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            DecodingKey::from_rsa_pem(validation_key.as_bytes())
                .context("failed to parse RSA validation key")
        }
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(validation_key.as_bytes())
            .context("failed to parse EC validation key"),
        other => anyhow::bail!("unsupported authentication algorithm '{other:?}'"),
    }
}

pub fn resolving_decoding_key(
    authentication: &AuthenticationConfig,
    bearer_token: &str,
) -> anyhow::Result<DecodingKey> {
    match authentication.validation_key {
        Some(_) => decoding_key(authentication),
        None => {
            info!(
                issuer = %authentication.issuer,
                "authentication.validation_key not configured; attempting issuer-based validation key discovery"
            );
            discovery_decoding_key(authentication, bearer_token)
        }
    }
}

fn discovery_decoding_key(
    authentication: &AuthenticationConfig,
    bearer_token: &str,
) -> anyhow::Result<DecodingKey> {
    let openid_configuration_url = format!(
        "{}/.well-known/openid-configuration",
        authentication.issuer.trim_end_matches('/')
    );
    let client = discovery_client(authentication)?;

    let openid_configuration: OpenIdConfiguration = client
        .get(&openid_configuration_url)
        .send()
        .with_context(|| {
            format!("failed to fetch OpenID configuration from '{openid_configuration_url}'")
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "OpenID configuration request to '{openid_configuration_url}' returned an error status"
            )
        })?
        .json()
        .with_context(|| {
            format!("failed to parse OpenID configuration from '{openid_configuration_url}'")
        })?;

    let jwks: JwkSet = client
        .get(&openid_configuration.jwks_uri)
        .send()
        .with_context(|| {
            format!(
                "failed to fetch JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "JWKS request to '{}' returned an error status",
                openid_configuration.jwks_uri
            )
        })?
        .json()
        .with_context(|| {
            format!(
                "failed to parse JWKS from '{}'",
                openid_configuration.jwks_uri
            )
        })?;

    let header = decode_header(bearer_token)
        .context("failed to decode bearer token header for key discovery")?;
    debug!(token_kid = ?header.kid, "decoded bearer token header for validation key discovery");
    let jwk = select_jwk_for_token(&jwks, &header.kid, algorithm(authentication)?)?;

    DecodingKey::from_jwk(jwk).with_context(|| {
        let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
        format!("failed to construct decoding key from discovered JWK '{key_id}'")
    })
}

fn discovery_client(authentication: &AuthenticationConfig) -> anyhow::Result<Client> {
    let mut builder = Client::builder();

    if authentication.issuer == kubernetes::KUBERNETES_SERVICE_HOST {
        builder = kubernetes::configure_in_cluster_blocking_client(builder)?;
    }

    builder
        .build()
        .context("failed to build HTTP client for validation key discovery")
}

#[derive(Debug, Deserialize)]
struct OpenIdConfiguration {
    jwks_uri: String,
}

fn select_jwk_for_token<'a>(
    jwks: &'a JwkSet,
    kid: &Option<String>,
    algorithm: Algorithm,
) -> anyhow::Result<&'a Jwk> {
    if let Some(kid) = kid {
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| anyhow::anyhow!("no JWK found for token kid '{kid}'"))?;
        ensure_jwk_compatible(jwk, algorithm)?;
        return Ok(jwk);
    }

    let mut matching_keys = jwks
        .keys
        .iter()
        .filter(|jwk| jwk_matches_algorithm(jwk, algorithm));
    let jwk = matching_keys
        .next()
        .ok_or_else(|| anyhow::anyhow!("no compatible JWK found for algorithm '{algorithm:?}'"))?;
    if matching_keys.next().is_some() {
        anyhow::bail!(
            "multiple compatible JWKs found for algorithm '{algorithm:?}' but the token header did not include a kid"
        );
    }
    Ok(jwk)
}

fn ensure_jwk_compatible(jwk: &Jwk, algorithm: Algorithm) -> anyhow::Result<()> {
    if !jwk_matches_algorithm(jwk, algorithm) {
        let key_id = jwk.common.key_id.as_deref().unwrap_or("<no kid>");
        anyhow::bail!("discovered JWK '{key_id}' is not compatible with algorithm '{algorithm:?}'");
    }
    Ok(())
}

fn jwk_matches_algorithm(jwk: &Jwk, algorithm: Algorithm) -> bool {
    if let Some(public_key_use) = &jwk.common.public_key_use {
        if *public_key_use != PublicKeyUse::Signature {
            return false;
        }
    }

    match algorithm {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            matches!(
                jwk.common.key_algorithm,
                Some(KeyAlgorithm::RS256 | KeyAlgorithm::RS384 | KeyAlgorithm::RS512) | None
            ) && matches!(
                jwk.algorithm,
                jsonwebtoken::jwk::AlgorithmParameters::RSA(_)
            )
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            matches!(
                jwk.common.key_algorithm,
                Some(KeyAlgorithm::ES256 | KeyAlgorithm::ES384) | None
            ) && matches!(
                jwk.algorithm,
                jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(_)
            )
        }
        _ => false,
    }
}

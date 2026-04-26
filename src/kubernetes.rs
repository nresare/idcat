// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

pub const KUBERNETES_SERVICE_HOST: &str = "https://kubernetes.default.svc";
const KUBERNETES_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const KUBERNETES_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

pub fn configure_in_cluster_blocking_client(
    mut builder: reqwest::blocking::ClientBuilder,
) -> anyhow::Result<reqwest::blocking::ClientBuilder> {
    if let Ok(ca_cert_pem) = std::fs::read(KUBERNETES_CA_CERT_PATH) {
        let certificate = reqwest::Certificate::from_pem(&ca_cert_pem).with_context(|| {
            format!(
                "failed to parse Kubernetes CA certificate bundle at '{KUBERNETES_CA_CERT_PATH}'"
            )
        })?;
        builder = builder.add_root_certificate(certificate);
    }

    if let Ok(service_account_token) = std::fs::read_to_string(KUBERNETES_TOKEN_PATH) {
        let token = service_account_token.trim();
        if !token.is_empty() {
            let mut headers = HeaderMap::new();
            let header_value = HeaderValue::from_str(&format!("Bearer {token}")).with_context(|| {
                format!(
                    "failed to build Authorization header from Kubernetes token at '{KUBERNETES_TOKEN_PATH}'"
                )
            })?;
            headers.insert(AUTHORIZATION, header_value);
            builder = builder.default_headers(headers);
        }
    }

    Ok(builder)
}

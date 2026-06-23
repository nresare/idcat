// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::config::NatsConfig;
use axum::body::Bytes;
use axum::http::HeaderMap;
use std::io;
use tracing::info;

#[derive(Clone)]
pub struct WebhookPublisher {
    client: async_nats::Client,
    subject_base: String,
}

impl WebhookPublisher {
    pub async fn connect(config: &NatsConfig) -> anyhow::Result<Self> {
        let client = connect_options(config.token_path.clone())
            .connect(config.endpoint.as_str())
            .await?;
        info!(
            endpoint = %config.endpoint,
            subject_base = %config.subject_base,
            token_path = config.token_path.as_deref(),
            "connected to nats for webhook publishing"
        );
        Ok(Self {
            client,
            subject_base: config.subject_base.trim_end_matches('.').to_string(),
        })
    }

    pub async fn publish_github_webhook(
        &self,
        headers: &HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<String> {
        let subject = subject_for_github_webhook(&self.subject_base, headers, &body);
        self.client.publish(subject.clone(), body).await?;
        Ok(subject)
    }
}

fn connect_options(token_path: Option<String>) -> async_nats::ConnectOptions {
    match token_path {
        Some(token_path) => async_nats::ConnectOptions::with_auth_callback(move |_| {
            let token_path = token_path.clone();
            async move {
                let token = tokio::fs::read_to_string(&token_path)
                    .await
                    .map_err(async_nats::AuthError::new)?;
                let token = token.trim().to_string();
                if token.is_empty() {
                    return Err(async_nats::AuthError::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "nats token file is empty",
                    )));
                }
                let mut auth = async_nats::Auth::new();
                auth.token = Some(token);
                Ok(auth)
            }
        }),
        None => async_nats::ConnectOptions::new(),
    }
}

pub fn github_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn subject_for_github_webhook(subject_base: &str, headers: &HeaderMap, body: &Bytes) -> String {
    let event = github_header(headers, "x-github-event").unwrap_or("unknown");
    let mut segments = vec![
        subject_base.trim_end_matches('.').to_string(),
        subject_token(event),
    ];
    if let Some((owner, repo)) = repository_name(body) {
        segments.push(subject_token(&owner));
        segments.push(subject_token(&repo));
    }
    segments.join(".")
}

fn repository_name(body: &Bytes) -> Option<(String, String)> {
    let payload: serde_json::Value = serde_json::from_slice(body).ok()?;
    let repository = payload.get("repository")?;
    let owner = repository.get("owner")?.get("name")?.as_str()?;
    let repo = repository.get("name")?.as_str()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner.to_string(), repo.to_string()))
}

fn subject_token(value: &str) -> String {
    let token: String = value
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => character,
            _ => '_',
        })
        .collect();
    if token.is_empty() {
        "unknown".to_string()
    } else {
        token
    }
}

#[cfg(test)]
mod tests {
    use super::{repository_name, subject_for_github_webhook, subject_token};
    use axum::body::Bytes;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn subject_token_preserves_github_event_names() {
        assert_eq!(subject_token("pull_request"), "pull_request");
        assert_eq!(subject_token("workflow-run"), "workflow-run");
    }

    #[test]
    fn subject_token_replaces_nats_subject_special_characters() {
        assert_eq!(subject_token("bad.event > name"), "bad_event___name");
    }

    #[test]
    fn repository_name_reads_owner_and_repo() {
        let body =
            Bytes::from_static(br#"{"repository":{"owner":{"name":"nresare"},"name":"idcat"}}"#);

        assert_eq!(
            repository_name(&body),
            Some(("nresare".to_string(), "idcat".to_string()))
        );
    }

    #[test]
    fn subject_includes_github_event_owner_and_repo_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert("x-github-event", HeaderValue::from_static("push"));
        let body =
            Bytes::from_static(br#"{"repository":{"owner":{"name":"nresare"},"name":"idcat"}}"#);

        assert_eq!(
            subject_for_github_webhook("idcat.github.webhook", &headers, &body),
            "idcat.github.webhook.push.nresare.idcat"
        );
    }

    #[test]
    fn subject_omits_owner_and_repo_when_payload_has_no_full_name() {
        let mut headers = HeaderMap::new();
        headers.insert("x-github-event", HeaderValue::from_static("push"));
        let body = Bytes::from_static(br#"{"zen":"Keep it logically awesome."}"#);

        assert_eq!(
            subject_for_github_webhook("idcat.github.webhook", &headers, &body),
            "idcat.github.webhook.push"
        );
    }
}

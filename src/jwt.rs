// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use crate::signer::Signer;
use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

const GITHUB_APP_JWT_TTL_SECONDS: u64 = 9 * 60;
const CLOCK_SKEW_SECONDS: u64 = 60;

#[derive(Debug, Serialize)]
struct GithubAppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

pub async fn build_github_app_jwt(
    github_app_id: u64,
    signer: &dyn Signer,
) -> anyhow::Result<String> {
    build_github_app_jwt_at(github_app_id, signer, now()?).await
}

async fn build_github_app_jwt_at(
    github_app_id: u64,
    signer: &dyn Signer,
    now: u64,
) -> anyhow::Result<String> {
    let issued_at = now.saturating_sub(CLOCK_SKEW_SECONDS);
    let claims = GithubAppClaims {
        iat: issued_at,
        exp: issued_at + GITHUB_APP_JWT_TTL_SECONDS,
        iss: github_app_id.to_string(),
    };
    let header = Header::new(Algorithm::RS256);
    let encoded_header =
        encode_jwt_part(&header).context("failed to encode GitHub App JWT header")?;
    let encoded_claims =
        encode_jwt_part(&claims).context("failed to encode GitHub App JWT claims")?;
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .context("failed to sign GitHub App JWT")?;
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{signing_input}.{encoded_signature}"))
}

fn encode_jwt_part<T: Serialize>(input: &T) -> anyhow::Result<String> {
    let json = serde_json::to_vec(input)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

fn now() -> anyhow::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| anyhow::anyhow!("system time error: {error}"))
}

#[cfg(test)]
mod tests {
    use super::build_github_app_jwt_at;
    use crate::signer::{LocalSigner, Signer};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use serde_json::Value;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhTPJsY5BW6Omc
OftqnA1qKDVmifo0rOOws5g0/KBW7mmcQcoUuc0h0W668RXvG+Sm9XfCXp/jSkLN
ST3gQaIwj4lnzMyaoTFjxBWWaQuNhbaxlm1nL2j9U9eaCxw0iUex0KDfbNUfjVHu
KQwHkjHaUJ0ufQ/0xRScLtiCMLlcWjfbEFjoYhi69N1vekjboNL/ORAcbWAbsKGC
Az0b3xM6L4d5pyO7enyBJWw8z/lGkVNJNQi1r3Zgs/Wf9AflzacypjX2lGbPkWcg
kkyFmlHhk1MtzjlQoirIIt0N1PiRRD9HJJHuG4/ebPOJ7GndWapnKp8rngoZw7FH
j11eMX+JAgMBAAECggEAb5U2c2wULpcILDGjTTeghTUIzZIEc1Y1JmysM4Hyv1sw
vwzuUrl62Qbqundwj43W/sGP4JoQwfcjgpyFoq2e8EIGoXwS0XqIBYs1zdqUuDDD
PMztvi8C5oRBwa9C9toOwgg7xKwYGZpaO4Pky1MikadfUYjrACUjgf7JiCEtjIjM
KsmqJnzeIjHxtFyL/X2VNhmUWNQKPHYWe3zvBieshQPy7LLmYzzJGv7c9nyDJnPx
mM7Tm4UTkjW/KSoED0kbfXmcJRJRNWo9P+tZ1ABJAx0V0cipbI+NDXqMhPGfPfTi
08rJDae96+yPSu1c+cpFEFM7z2OMR403RouyVnMQoQKBgQD21y7eZmGqGrQ8O6wS
UWM3+Ox6xTx+NsVBzNK8ypDqxWeVB7l38Taomm3FTHeE80lcd728MAmd66tcGGdb
5SO5kgdvboLt9ZKvVBTMJbHVfXJHailZx2Qa5W8iigXfMIIQx3Xf0T5qauNb9mQj
w3Fyf/ANPA4AZoNDkU579SwHfQKBgQDpqSYSwm5vzPjHY62m+npIk0Be3nOxkuQQ
HUW+vlDFb5ZupW7CQGOQEuKvPcD6MZAddYvVbIObWnmkkHPhg6jZdp7bfXbd2yaf
HGHJwvAYzCC5Hb4eQrVJZ/M8UzUcEBqXC4YmOTAnVMIV9qcEwVc7DasSIMiHLPAl
oCVlE5vN/QKBgDiju69wkqxzoDPKBXvWjQvE5I5vP6g+bRjiJOEJIiOc1F3P/fDV
upMJjHKfTzWElarQFwtdgndoIlPpjZ36gC4OogIhu41asiPlCTim1Z2FQXm9lGtz
YzcAunWUcjB6cv3iptuKqeXFTRJHAUdri1aYoL6IrzXMUAZrCzVKVqYJAoGBALaA
e1BjtMZ2Hkn+PQAS27gb60cuEMc9qAw+EN+u3n+XbLP3Ws82Y42AcrXVUgkY9StN
SG7mVtTcke5LNXeK0jMoR2PAVztplHzqOibQr59usJBl/ry79cTkAEO56d2FZn9b
bOgl+sp9lSp6gHFiYbOqNVfvazDJlLiOoSaVbjgxAoGATUH1geYvMl8W93MmA9vf
bzyzl4KklDegSMtja84vVDt5nCYPO32q3VDbihuOAHKpEK+GWuGLRlNp0t8e1ih/
KMueZKFHEwc6u9xKIEY3csS4Pbom5m0IU89tiZ22SzvWvGoMuwtJbFiGdMWFbyG+
5XvOGTJeQmnvXyNmqhP9WSY=
-----END PRIVATE KEY-----"#;

    const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UzybGOQVujpnDn7apwN
aig1Zon6NKzjsLOYNPygVu5pnEHKFLnNIdFuuvEV7xvkpvV3wl6f40pCzUk94EGi
MI+JZ8zMmqExY8QVlmkLjYW2sZZtZy9o/VPXmgscNIlHsdCg32zVH41R7ikMB5Ix
2lCdLn0P9MUUnC7YgjC5XFo32xBY6GIYuvTdb3pI26DS/zkQHG1gG7ChggM9G98T
Oi+Heacju3p8gSVsPM/5RpFTSTUIta92YLP1n/QH5c2nMqY19pRmz5FnIJJMhZpR
4ZNTLc45UKIqyCLdDdT4kUQ/RySR7huP3mzziexp3VmqZyqfK54KGcOxR49dXjF/
iQIDAQAB
-----END PUBLIC KEY-----"#;

    #[tokio::test]
    async fn builds_rs256_github_app_jwt() {
        let signer = LocalSigner::from_rsa_pem(PRIVATE_KEY).unwrap();
        let token = build_github_app_jwt_at(42, &signer, 4_102_444_800)
            .await
            .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["42"]);
        validation.validate_exp = false;

        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_rsa_pem(PUBLIC_KEY.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.header.alg, Algorithm::RS256);
        assert_eq!(decoded.claims["iss"], "42");
        assert_eq!(decoded.claims["iat"], 4_102_444_740_u64);
        assert_eq!(decoded.claims["exp"], 4_102_445_280_u64);
    }

    #[tokio::test]
    async fn delegates_signature_to_signer() {
        let signer = RecordingSigner::new(vec![1, 2, 3]);
        let token = build_github_app_jwt_at(42, &signer, 4_102_444_800)
            .await
            .unwrap();
        let parts = token.split('.').collect::<Vec<_>>();

        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], "AQID");
        assert_eq!(
            signer.messages(),
            vec![format!("{}.{}", parts[0], parts[1]).into_bytes()]
        );
    }

    struct RecordingSigner {
        signature: Vec<u8>,
        messages: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl RecordingSigner {
        fn new(signature: Vec<u8>) -> Self {
            Self {
                signature,
                messages: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn messages(&self) -> Vec<Vec<u8>> {
            self.messages.lock().unwrap().clone()
        }
    }

    impl Signer for RecordingSigner {
        fn sign<'a>(
            &'a self,
            message: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                self.messages.lock().unwrap().push(message.to_vec());
                Ok(self.signature.clone())
            })
        }
    }
}

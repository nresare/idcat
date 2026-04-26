// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: The idcat contributors

use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
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

pub fn build_github_app_jwt(github_app_id: u64, private_key_pem: &str) -> anyhow::Result<String> {
    build_github_app_jwt_at(github_app_id, private_key_pem, now()?)
}

fn build_github_app_jwt_at(
    github_app_id: u64,
    private_key_pem: &str,
    now: u64,
) -> anyhow::Result<String> {
    let issued_at = now.saturating_sub(CLOCK_SKEW_SECONDS);
    let claims = GithubAppClaims {
        iat: issued_at,
        exp: issued_at + GITHUB_APP_JWT_TTL_SECONDS,
        iss: github_app_id.to_string(),
    };
    let header = Header::new(Algorithm::RS256);
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .context("failed to parse GitHub App RSA private key")?;
    encode(&header, &claims, &encoding_key)
        .map_err(|error| anyhow::anyhow!("failed to encode GitHub App JWT: {error}"))
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
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use serde_json::Value;

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

    #[test]
    fn builds_rs256_github_app_jwt() {
        let token = build_github_app_jwt_at(42, PRIVATE_KEY, 4_102_444_800).unwrap();
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
}

use anyhow::{Context, bail};
use std::collections::HashMap;
use std::io::{self, BufRead};
use url::Url;

#[derive(Debug, PartialEq, Eq)]
pub struct Repo {
    pub owner: String,
    pub name: String,
}

pub fn read_credential_from_stdin() -> anyhow::Result<HashMap<String, String>> {
    let stdin = io::stdin();
    read_credential(stdin.lock())
}

fn read_credential(mut reader: impl BufRead) -> anyhow::Result<HashMap<String, String>> {
    let mut credential_input = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read credential request from stdin")?;
        if bytes_read == 0 {
            break;
        }

        if line == "\n" || line == "\r\n" {
            break;
        }

        credential_input.push_str(&line);
    }

    parse_credential(&credential_input)
}

fn parse_credential(input: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut credential = HashMap::new();

    for line in input.lines() {
        if line.is_empty() {
            break;
        }

        let Some((key, value)) = line.split_once('=') else {
            bail!("credential line is missing '=': {line}");
        };

        if key.is_empty() {
            bail!("credential line has an empty key");
        }

        credential.insert(key.to_owned(), value.to_owned());
    }

    if let Some(url) = credential.get("url").cloned() {
        merge_url_credential(&mut credential, &url);
    }

    Ok(credential)
}

fn merge_url_credential(credential: &mut HashMap<String, String>, raw_url: &str) {
    let Ok(url) = Url::parse(raw_url) else {
        return;
    };

    credential
        .entry("protocol".to_owned())
        .or_insert_with(|| url.scheme().to_owned());

    if let Some(host) = url.host_str() {
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        credential.entry("host".to_owned()).or_insert(host);
    }

    let path = url.path().trim_start_matches('/');
    if !path.is_empty() {
        credential
            .entry("path".to_owned())
            .or_insert_with(|| path.to_owned());
    }
}

pub fn is_github_https_request(credential: &HashMap<String, String>) -> bool {
    credential
        .get("protocol")
        .is_some_and(|value| value == "https")
        && credential
            .get("host")
            .is_some_and(|value| value.eq_ignore_ascii_case("github.com"))
}

pub fn repo_from_credential(credential: &HashMap<String, String>) -> Option<Repo> {
    repo_from_path(credential.get("path")?)
}

fn repo_from_path(path: &str) -> Option<Repo> {
    let mut components = path
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty());

    let owner = components.next()?;
    let repo = components.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);

    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    Some(Repo {
        owner: owner.to_owned(),
        name: repo.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blank_line_terminated_credential() {
        let credential =
            parse_credential("protocol=https\nhost=github.com\npath=noa/idcat.git\n\n")
                .expect("credential parses");

        assert_eq!(credential.get("protocol"), Some(&"https".to_owned()));
        assert_eq!(credential.get("host"), Some(&"github.com".to_owned()));
        assert_eq!(credential.get("path"), Some(&"noa/idcat.git".to_owned()));
    }

    #[test]
    fn expands_url_attribute() {
        let credential = parse_credential("url=https://github.com/noa/idcat.git\n\n")
            .expect("credential parses");

        assert!(is_github_https_request(&credential));
        assert_eq!(
            repo_from_credential(&credential),
            Some(Repo {
                owner: "noa".to_owned(),
                name: "idcat".to_owned(),
            })
        );
    }

    #[test]
    fn ignores_non_github_https_requests() {
        let ssh = parse_credential("protocol=ssh\nhost=github.com\npath=noa/idcat.git\n\n")
            .expect("credential parses");
        let other_host =
            parse_credential("protocol=https\nhost=example.com\npath=noa/idcat.git\n\n")
                .expect("credential parses");

        assert!(!is_github_https_request(&ssh));
        assert!(!is_github_https_request(&other_host));
    }

    #[test]
    fn derives_owner_and_repo_from_path() {
        assert_eq!(
            repo_from_path("/noa/idcat.git/info/refs"),
            Some(Repo {
                owner: "noa".to_owned(),
                name: "idcat".to_owned(),
            })
        );
    }

    #[test]
    fn stops_reading_credential_at_blank_line() {
        let input = "protocol=https\nhost=github.com\n\nthis-is-not-a-credential-line\n";
        let credential = read_credential(input.as_bytes()).expect("credential parses");

        assert_eq!(credential.get("protocol"), Some(&"https".to_owned()));
        assert_eq!(credential.get("host"), Some(&"github.com".to_owned()));
    }
}

//! The access token for a hub: $HF_TOKEN, else the one "bomify login <hub
//! host> --verify=false" stored, else the one "hf auth login" stored, as
//! the Go plugin finds it. It's resolved here, rather than left to
//! hf-hub, because the plugin also makes requests of its own (see
//! Hub::list_repository), and hf-hub doesn't say which token it found.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;

use crate::log::Logger;

/// The environment variable hf reads an access token from.
const TOKEN_ENV: &str = "HF_TOKEN";

/// The token for the hub at host, or None for none.
pub fn token(host: &str, logger: &Logger) -> Result<Option<String>> {
    if let Some(token) = std::env::var(TOKEN_ENV)
        .ok()
        .filter(|token| !token.is_empty())
    {
        return Ok(Some(token));
    }
    let stored = lookup(host).with_context(|| format!("look up credentials for {host}"))?;
    if stored.is_some() {
        logger.info("using the token bomify login stored", &[("host", host)]);
        return Ok(stored);
    }
    let Some(path) = hf_login_token_path() else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(token) if !token.trim().is_empty() => {
            logger.info(
                "using the token hf auth login stored",
                &[("path", &path.display().to_string())],
            );
            Ok(Some(token.trim().to_string()))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read hf's token"),
    }
}

/// Where "hf auth login" stores its token, where hf itself looks for it:
/// $HF_TOKEN_PATH, else "token" under $HF_HOME, else under
/// $XDG_CACHE_HOME/huggingface or ~/.cache/huggingface.
fn hf_login_token_path() -> Option<PathBuf> {
    let set = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    if let Some(path) = set("HF_TOKEN_PATH") {
        return Some(path);
    }
    let home = match set("HF_HOME") {
        Some(home) => home,
        None => set("XDG_CACHE_HOME")
            .or_else(|| Some(home_dir()?.join(".cache")))?
            .join("huggingface"),
    };
    Some(home.join("token"))
}

/// A Docker-format credential config, as bomify's conf/auth.json and
/// Docker's config.json are.
#[derive(Deserialize, Default)]
struct Config {
    #[serde(default)]
    auths: HashMap<String, AuthEntry>,
    #[serde(default, rename = "credsStore")]
    creds_store: Option<String>,
    #[serde(default, rename = "credHelpers")]
    cred_helpers: HashMap<String, String>,
}

#[derive(Deserialize, Default)]
struct AuthEntry {
    #[serde(default)]
    auth: Option<String>,
    #[serde(default, rename = "identitytoken")]
    identity_token: Option<String>,
}

/// The secret stored for host: in bomify's credential store, then
/// Docker's, as bomify's own lookup reads them.
fn lookup(host: &str) -> Result<Option<String>> {
    for path in [bomify_auth_config(), docker_config()]
        .into_iter()
        .flatten()
    {
        let data = match std::fs::read(&path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let config: Config =
            serde_json::from_slice(&data).with_context(|| format!("parse {}", path.display()))?;
        if let Some(secret) = secret_in(&config, host)? {
            return Ok(Some(secret));
        }
    }
    Ok(None)
}

/// bomify's conf/auth.json: under $BOMIFY_DATA_DIR, else ~/.bomify.
fn bomify_auth_config() -> Option<PathBuf> {
    let data_dir = match std::env::var_os("BOMIFY_DATA_DIR").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".bomify"),
    };
    Some(data_dir.join("conf").join("auth.json"))
}

/// Docker's config.json: under $DOCKER_CONFIG, else ~/.docker.
fn docker_config() -> Option<PathBuf> {
    let dir = match std::env::var_os("DOCKER_CONFIG").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".docker"),
    };
    Some(dir.join("config.json"))
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The secret config stores for host: from a credential helper, if one
/// handles it, else from its auths entry.
fn secret_in(config: &Config, host: &str) -> Result<Option<String>> {
    if let Some(helper) = config
        .cred_helpers
        .get(host)
        .or(config.creds_store.as_ref())
    {
        return run_helper(helper, host);
    }
    let entry = config
        .auths
        .get(host)
        .or_else(|| config.auths.get(&format!("https://{host}")));
    let Some(entry) = entry else {
        return Ok(None);
    };
    if let Some(token) = entry
        .identity_token
        .as_ref()
        .filter(|token| !token.is_empty())
    {
        return Ok(Some(token.clone()));
    }
    let Some(auth) = entry.auth.as_ref().filter(|auth| !auth.is_empty()) else {
        return Ok(None);
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth)
        .context("decode a stored credential")?;
    let decoded = String::from_utf8(decoded).context("decode a stored credential")?;
    let Some((_, secret)) = decoded.split_once(':') else {
        bail!("a stored credential isn't <username>:<secret>");
    };
    Ok(Some(secret.to_string()).filter(|secret| !secret.is_empty()))
}

/// Asks the credential helper docker-credential-<helper> for host's
/// secret, by Docker's credential helper protocol: the server on stdin, a
/// JSON object with its Secret on stdout. None if it has none.
fn run_helper(helper: &str, host: &str) -> Result<Option<String>> {
    let program = format!("docker-credential-{helper}");
    let mut child = Command::new(&program)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {program}"))?;
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(host.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stdout);
        // The protocol's way of saying it has nothing for host.
        if message.contains("credentials not found") {
            return Ok(None);
        }
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    #[derive(Deserialize)]
    struct HelperAnswer {
        #[serde(rename = "Secret")]
        secret: String,
    }
    let answer: HelperAnswer = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse {program}'s answer"))?;
    Ok(Some(answer.secret).filter(|secret| !secret.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> Config {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn reads_plaintext_auths() {
        // "user:hf_secret"
        let stored = config(r#"{"auths": {"huggingface.co": {"auth": "dXNlcjpoZl9zZWNyZXQ="}}}"#);
        assert_eq!(
            secret_in(&stored, "huggingface.co").unwrap().as_deref(),
            Some("hf_secret")
        );
        assert_eq!(secret_in(&stored, "hub.example.com").unwrap(), None);

        let https =
            config(r#"{"auths": {"https://huggingface.co": {"auth": "dXNlcjpoZl9zZWNyZXQ="}}}"#);
        assert_eq!(
            secret_in(&https, "huggingface.co").unwrap().as_deref(),
            Some("hf_secret")
        );

        let identity = config(r#"{"auths": {"huggingface.co": {"identitytoken": "hf_identity"}}}"#);
        assert_eq!(
            secret_in(&identity, "huggingface.co").unwrap().as_deref(),
            Some("hf_identity")
        );
    }

    #[test]
    fn refuses_malformed_auths() {
        // "no-colon"
        let stored = config(r#"{"auths": {"huggingface.co": {"auth": "bm8tY29sb24="}}}"#);
        assert!(secret_in(&stored, "huggingface.co").is_err());
    }
}

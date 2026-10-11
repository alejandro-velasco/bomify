//! Purls, hub addresses, and remotes: what a component names, and where.

use std::str::FromStr;

use anyhow::{Context, Result, bail};
use packageurl::PackageUrl;
use url::Url;

/// The purl type this plugin handles.
pub const PURL_TYPE: &str = "huggingface";

/// The hub a purl without a repository_url qualifier names, and the one
/// used when none is given.
pub const DEFAULT_ENDPOINT: &str = "https://huggingface.co";

/// The branch a Hub repository starts with: push commits to it, and sbom
/// generate describes it unless given a revision.
pub const DEFAULT_BRANCH: &str = "main";

/// The environment variable hf reads another hub's address from.
const ENDPOINT_ENV: &str = "HF_ENDPOINT";

/// A model repository at a commit, as a pkg:huggingface purl names it.
#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    /// The repository's user or organization.
    pub namespace: String,
    /// The repository's name.
    pub name: String,
    /// The full commit hash.
    pub revision: String,
    /// The hub's base URL from the purl's repository_url qualifier, e.g.
    /// "https://hub.example.com", or None for hf's default.
    pub endpoint: Option<String>,
}

impl Ref {
    /// The repository's "<namespace>/<name>", as hf takes it.
    pub fn repo_id(&self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }

    /// Where the ref comes from: the hub's URL (its repository_url, else
    /// DEFAULT_ENDPOINT) and its namespace, e.g.
    /// "https://huggingface.co/meta-llama", in the shape push's --remote
    /// takes.
    pub fn remote(&self) -> String {
        let endpoint = self.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT);
        format!("{endpoint}/{}", self.namespace)
    }
}

/// Parses a pkg:huggingface purl, pinned to a full commit hash, with an
/// optional repository_url qualifier naming another hub.
pub fn resolve(purl: &str) -> Result<Ref> {
    let parsed = PackageUrl::from_str(purl).with_context(|| format!("parse purl {purl:?}"))?;
    if parsed.ty() != PURL_TYPE {
        bail!("purl {purl:?} isn't a {PURL_TYPE} purl");
    }
    let namespace = parsed.namespace().unwrap_or_default();
    let name = parsed.name();
    if namespace.is_empty() || namespace.contains('/') || name.is_empty() {
        bail!("purl {purl:?} isn't pkg:{PURL_TYPE}/<namespace>/<name>@<commit>");
    }
    if parsed.subpath().is_some_and(|subpath| !subpath.is_empty()) {
        bail!("purl {purl:?} has a subpath, but a pull is always the whole repository");
    }

    let revision = parsed.version().unwrap_or_default().to_lowercase();
    if !is_commit_hash(&revision) {
        bail!(
            "purl {purl:?} isn't pinned to a commit: its version must be the repository's full 40-character commit hash, so every pull gets the same files"
        );
    }

    let endpoint = match parsed
        .qualifiers()
        .iter()
        .find(|(key, _)| key.as_ref() == "repository_url")
    {
        Some((_, value)) => Some(endpoint_of(value).with_context(|| format!("purl {purl:?}"))?),
        None => None,
    };

    let reference = Ref {
        namespace: namespace.to_string(),
        name: name.to_string(),
        revision,
        endpoint,
    };
    Ok(reference)
}

/// Reports whether text is a full, lowercase Git commit hash.
pub fn is_commit_hash(text: &str) -> bool {
    text.len() == 40
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates a repository_url qualifier and returns it without a trailing
/// slash.
fn endpoint_of(repository_url: &str) -> Result<String> {
    let parsed = Url::parse(repository_url)
        .with_context(|| format!("parse repository_url {repository_url:?}"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("repository_url {repository_url:?} isn't an https:// hub address");
    }
    Ok(repository_url.trim_end_matches('/').to_string())
}

/// Splits push's --remote, "https://<host>[/<path>]/<namespace>", into the
/// hub's base URL and the namespace to upload into.
pub fn parse_remote(remote: &str) -> Result<(String, String)> {
    let trimmed = remote.trim_end_matches('/');
    let Some((endpoint, namespace)) = trimmed.rsplit_once('/') else {
        bail!("--remote {remote:?} isn't <hub URL>/<namespace>, e.g. {DEFAULT_ENDPOINT}/my-org");
    };
    if endpoint.is_empty() || namespace.is_empty() || endpoint_of(endpoint).is_err() {
        bail!("--remote {remote:?} isn't <hub URL>/<namespace>, e.g. {DEFAULT_ENDPOINT}/my-org");
    }
    Ok((endpoint.to_string(), namespace.to_string()))
}

/// The hub to use: endpoint, else $HF_ENDPOINT, else huggingface.co. It
/// must be an http or https URL with a host; it's returned without a
/// trailing slash.
pub fn resolve_endpoint(endpoint: Option<&str>) -> Result<String> {
    let chosen = match endpoint.filter(|endpoint| !endpoint.is_empty()) {
        Some(endpoint) => endpoint.to_string(),
        None => std::env::var(ENDPOINT_ENV)
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
    };
    let parsed = Url::parse(&chosen).map_err(|_| {
        anyhow::anyhow!(
            "hub address {chosen:?} isn't an http or https URL, e.g. {DEFAULT_ENDPOINT}"
        )
    })?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        bail!("hub address {chosen:?} isn't an http or https URL, e.g. {DEFAULT_ENDPOINT}");
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        bail!("hub address {chosen:?} has no host, e.g. {DEFAULT_ENDPOINT}");
    }
    Ok(chosen.trim_end_matches('/').to_string())
}

/// The web page of repo_id, "<namespace>/<name>", on the hub at endpoint.
pub fn repository_page(endpoint: &str, repo_id: &str) -> String {
    format!("{endpoint}/{repo_id}")
}

/// The host of a hub's base URL, which credentials are stored under.
pub fn host_of(endpoint: &str) -> Result<String> {
    let parsed = Url::parse(endpoint).with_context(|| format!("parse hub address {endpoint:?}"))?;
    let host = parsed.host_str().unwrap_or_default();
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "2db69c1c3e91a05d2c64a3185acfbaf36f744e25";

    #[test]
    fn resolves_purls() {
        let reference = resolve(&format!("pkg:huggingface/microsoft/phi-4@{COMMIT}")).unwrap();
        assert_eq!(reference.repo_id(), "microsoft/phi-4");
        assert_eq!(reference.revision, COMMIT);
        assert_eq!(reference.endpoint, None);
        assert_eq!(reference.remote(), "https://huggingface.co/microsoft");

        let mirrored = resolve(&format!(
            "pkg:huggingface/org/model@{COMMIT}?repository_url=https://hub.example.com/mirror/"
        ))
        .unwrap();
        assert_eq!(
            mirrored.endpoint.as_deref(),
            Some("https://hub.example.com/mirror")
        );
        assert_eq!(mirrored.remote(), "https://hub.example.com/mirror/org");
    }

    #[test]
    fn refuses_bad_purls() {
        for (purl, want) in [
            (
                format!("pkg:oci/org/model@{COMMIT}"),
                "isn't a huggingface purl",
            ),
            (
                format!("pkg:huggingface/model@{COMMIT}"),
                "<namespace>/<name>",
            ),
            (
                "pkg:huggingface/org/model@main".to_string(),
                "isn't pinned to a commit",
            ),
            (
                format!("pkg:huggingface/org/model@{COMMIT}#config.json"),
                "has a subpath",
            ),
            (
                format!("pkg:huggingface/org/model@{COMMIT}?repository_url=http://hub.example.com"),
                "isn't an https:// hub address",
            ),
        ] {
            let error = resolve(&purl).unwrap_err();
            assert!(
                format!("{error:#}").contains(want),
                "resolve({purl}) = {error:#}, want {want:?}"
            );
        }
    }

    #[test]
    fn parses_remotes() {
        assert_eq!(
            parse_remote("https://huggingface.co/my-org").unwrap(),
            ("https://huggingface.co".to_string(), "my-org".to_string())
        );
        assert_eq!(
            parse_remote("https://hub.example.com/mirror/my-org/").unwrap(),
            (
                "https://hub.example.com/mirror".to_string(),
                "my-org".to_string()
            )
        );
        for remote in [
            "my-org",
            "huggingface.co/my-org",
            "https://huggingface.co/",
            "https://my-org",
            "http://huggingface.co/my-org",
        ] {
            assert!(
                parse_remote(remote).is_err(),
                "parse_remote({remote}) succeeded"
            );
        }
        // What remote reports, push takes back.
        let reference = resolve(&format!(
            "pkg:huggingface/org/model@{COMMIT}?repository_url=https://hub.example.com"
        ))
        .unwrap();
        assert_eq!(
            parse_remote(&reference.remote()).unwrap(),
            ("https://hub.example.com".to_string(), "org".to_string())
        );
    }

    #[test]
    fn resolves_endpoints() {
        assert_eq!(
            resolve_endpoint(Some("https://hub.example.com/mirror/")).unwrap(),
            "https://hub.example.com/mirror"
        );
        assert_eq!(
            resolve_endpoint(Some("http://localhost:8080")).unwrap(),
            "http://localhost:8080"
        );
        for endpoint in ["huggingface.co", "ftp://hub.example.com", "https://"] {
            assert!(
                resolve_endpoint(Some(endpoint)).is_err(),
                "resolve_endpoint({endpoint}) succeeded"
            );
        }
        assert_eq!(
            host_of("https://hub.example.com:8443/mirror").unwrap(),
            "hub.example.com:8443"
        );
    }
}

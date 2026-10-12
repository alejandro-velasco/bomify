//! The Hub, through hf-hub, plus what bomify checks on top: each file's
//! hash, and the repository's tree hash.

use std::fs::File as FsFile;
use std::io::Read;
use std::path::{Component, Path};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hf_hub::repository::{RepoTreeEntry, RepoTypeModel};
use hf_hub::{HFClient, HFClientSync, HFRepositorySync};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use url::Url;

use crate::log::Logger;
use crate::refs::{Ref, host_of, resolve_endpoint};
use crate::token::token;

/// The answers worth retrying a request for: a timeout, rate limiting,
/// and server errors.
const RETRY_STATUSES: [u16; 6] = [408, 429, 500, 502, 503, 504];

/// How long to wait before each retry.
const RETRY_WAITS: [Duration; 4] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
];

/// A hub, with the token for it.
pub struct Hub {
    pub client: HFClientSync,
    /// The hub's base URL, e.g. "https://huggingface.co".
    pub endpoint: String,
    token: Option<String>,
    /// Makes the requests hf-hub can't (see lfs_sha256): it never follows
    /// redirects.
    http: reqwest::blocking::Client,
}

impl Hub {
    /// Connects to the hub at endpoint (see resolve_endpoint), with the
    /// token for it (see token).
    pub fn connect(endpoint: Option<&str>, logger: &Logger) -> Result<Hub> {
        let endpoint = resolve_endpoint(endpoint)?;
        let token = token(&host_of(&endpoint)?, logger)?;
        let mut builder = HFClient::builder().endpoint(endpoint.clone());
        if let Some(token) = &token {
            builder = builder.token(token.clone());
        }
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("set up an HTTP client")?;
        let hub = Hub {
            client: builder.build_sync().context("set up the Hub client")?,
            endpoint,
            token,
            http,
        };
        Ok(hub)
    }

    pub fn model(&self, namespace: &str, name: &str) -> HFRepositorySync<RepoTypeModel> {
        self.client.model(namespace, name)
    }

    /// Every file in reference's repository at its commit (see
    /// list_repository).
    pub fn list_files(&self, reference: &Ref) -> Result<Vec<File>> {
        self.list_repository(&reference.namespace, &reference.name, &reference.revision)
    }

    /// Every file in namespace/name at revision. Each path is checked to
    /// stay inside the directory it's written into, since the listing
    /// comes from the network.
    pub fn list_repository(
        &self,
        namespace: &str,
        name: &str,
        revision: &str,
    ) -> Result<Vec<File>> {
        let repo_id = format!("{namespace}/{name}");
        let entries = self
            .model(namespace, name)
            .list_tree()
            .revision(revision.to_string())
            .recursive(true)
            .send()
            .with_context(|| format!("list {repo_id}'s files"))?;
        let mut files = files_of(&repo_id, entries)?;
        for file in files
            .iter_mut()
            .filter(|file| file.lfs && file.sha256.is_none())
        {
            let sha256 = self
                .lfs_sha256(&repo_id, revision, &file.path)
                .with_context(|| format!("read {}'s SHA-256", file.path))?;
            file.sha256 = Some(sha256);
        }
        Ok(files)
    }

    /// An LFS file's SHA-256, from the X-Linked-ETag the Hub's resolve
    /// URL answers a HEAD with, as huggingface_hub reads it.
    ///
    /// hf-hub 1.0.0 can't give it: its tree listing reads an LFS file's
    /// SHA-256 from the key "sha256", but the Hub sends "oid"; and its
    /// get_file_metadata follows the resolve URL's redirect to the CDN,
    /// whose answer has no X-Linked-ETag.
    fn lfs_sha256(&self, repo_id: &str, revision: &str, path: &str) -> Result<String> {
        let mut url = Url::parse(&self.endpoint)?;
        url.path_segments_mut()
            .map_err(|()| anyhow::anyhow!("hub address {} can't take a path", self.endpoint))?
            .pop_if_empty()
            .extend(repo_id.split('/'))
            .push("resolve")
            .push(revision)
            .extend(path.split('/'));
        let response = self.head(&url)?;
        let etag = response
            .headers()
            .get("x-linked-etag")
            .and_then(|value| value.to_str().ok())
            .with_context(|| format!("HEAD {url}: no X-Linked-ETag"))?;
        let sha256 = etag
            .trim_start_matches("W/")
            .trim_matches('"')
            .to_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("HEAD {url}: X-Linked-ETag {etag:?} isn't a SHA-256");
        }
        Ok(sha256)
    }

    /// HEADs url with the token, retrying a dropped connection or a 408,
    /// 429, or 5xx, as hf-hub retries its own requests, and accepting a
    /// redirect as an answer.
    fn head(&self, url: &Url) -> Result<reqwest::blocking::Response> {
        let mut attempt = 0;
        loop {
            let mut request = self.http.head(url.clone());
            if let Some(token) = &self.token {
                request = request.bearer_auth(token);
            }
            let outcome = request.send();
            let retryable = match &outcome {
                Ok(response) => RETRY_STATUSES.contains(&response.status().as_u16()),
                Err(error) => error.is_connect() || error.is_timeout() || error.is_request(),
            };
            if !retryable || attempt >= RETRY_WAITS.len() {
                let response = outcome.with_context(|| format!("HEAD {url}"))?;
                if !response.status().is_success() && !response.status().is_redirection() {
                    bail!("HEAD {url}: {}", response.status());
                }
                return Ok(response);
            }
            std::thread::sleep(RETRY_WAITS[attempt]);
            attempt += 1;
        }
    }
}

/// One file of a repository at a commit, as the Hub lists it.
#[derive(Debug, Clone, PartialEq)]
pub struct File {
    /// Its "/"-separated path in the repository.
    pub path: String,
    pub size: u64,
    /// Whether it's stored in LFS (or Xet), rather than in Git.
    pub lfs: bool,
    /// An LFS file's SHA-256, or None for a file stored in Git.
    pub sha256: Option<String>,
    /// Its Git blob ID: the SHA-1 of "blob <size>\0" and its content.
    /// Only checked for a file stored in Git.
    pub blob_id: String,
}

/// The files among entries, refusing any outside the repository.
pub fn files_of(repo_id: &str, entries: Vec<RepoTreeEntry>) -> Result<Vec<File>> {
    let mut files = Vec::new();
    for entry in entries {
        let RepoTreeEntry::File {
            oid,
            size,
            path,
            lfs,
            ..
        } = entry
        else {
            continue;
        };
        if !is_safe_path(&path) {
            bail!("{repo_id} lists a file at {path:?}, outside the repository");
        }
        let file = File {
            path,
            size,
            lfs: lfs.is_some(),
            sha256: lfs.and_then(|lfs| lfs.sha256),
            blob_id: oid,
        };
        files.push(file);
    }
    Ok(files)
}

/// Reports whether path, "/"-separated, names a file inside the directory
/// it's joined to, and is one sha256sum would print as is: relative, with
/// no "..", backslash, newline, or NUL.
pub fn is_safe_path(path: &str) -> bool {
    if path.is_empty() || path.contains(['\\', '\0', '\n']) {
        return false;
    }
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

/// A file's hashes, from one read of it.
pub struct Hashes {
    pub size: u64,
    pub sha256: String,
    pub blob_id: String,
}

/// Hashes content: its size, SHA-256, and Git blob ID.
pub fn hash_content(mut content: impl Read, size: u64) -> Result<Hashes> {
    let mut sha256 = Sha256::new();
    let mut blob = Sha1::new();
    blob.update(format!("blob {size}\0").as_bytes());
    let mut buffer = vec![0u8; 1 << 20];
    let mut read = 0u64;
    loop {
        let count = content.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        blob.update(&buffer[..count]);
        read += count as u64;
    }
    if read != size {
        bail!("it's {read} bytes, but {size} were expected");
    }
    let hashes = Hashes {
        size,
        sha256: hex::encode(sha256.finalize()),
        blob_id: hex::encode(blob.finalize()),
    };
    Ok(hashes)
}

/// Hashes the file at path.
pub fn hash_file(path: &Path) -> Result<Hashes> {
    let file = FsFile::open(path).with_context(|| format!("hash {}", path.display()))?;
    let size = file.metadata()?.len();
    hash_content(file, size).with_context(|| format!("hash {}", path.display()))
}

/// Checks hashes against what the Hub lists for file: its SHA-256, for a
/// file in LFS, else its Git blob ID; and its size.
pub fn verify(file: &File, hashes: &Hashes) -> Result<()> {
    if hashes.size != file.size {
        bail!(
            "{}: got {} bytes, want {}",
            file.path,
            hashes.size,
            file.size
        );
    }
    let (got, want) = match &file.sha256 {
        Some(sha256) => (&hashes.sha256, sha256),
        None => (&hashes.blob_id, &file.blob_id),
    };
    if !got.eq_ignore_ascii_case(want) {
        bail!("{}: got content hashing to {got}, want {want}", file.path);
    }
    Ok(())
}

/// A pulled repository's SHA-256 and the paths of its files, sorted. The
/// hash is of the listing "sha256sum" prints for every file, sorted by
/// path, so anyone can reproduce it without bomify:
///
/// cd <dir> && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum --text | sha256sum
///
/// Pull computes it while verifying each file instead, reading each once.
#[cfg(test)]
pub fn tree_hash(dir: &Path) -> Result<(String, Vec<String>)> {
    let paths = local_paths(dir)?;
    let hash = hash_listing(&paths, |path| Ok(hash_file(&dir.join(path))?.sha256))?;
    Ok((hash, paths))
}

/// The tree hash of the files at paths, given each one's SHA-256 from
/// file_hash: from disk after a pull, or from the Hub's listing when
/// generating an SBOM.
pub fn hash_listing(
    paths: &[String],
    mut file_hash: impl FnMut(&str) -> Result<String>,
) -> Result<String> {
    let mut sorted: Vec<&String> = paths.iter().collect();
    sorted.sort();
    let mut listing = Sha256::new();
    for path in sorted {
        let hash = file_hash(path)?;
        listing.update(format!("{hash}  ./{path}\n").as_bytes());
    }
    Ok(hex::encode(listing.finalize()))
}

/// The "/"-separated paths of every file in dir, sorted, failing on
/// anything but regular files and directories, or a path sha256sum would
/// escape.
pub fn local_paths(dir: &Path) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    walk(dir, "", &mut paths).with_context(|| format!("list {}", dir.display()))?;
    paths.sort();
    Ok(paths)
}

fn walk(dir: &Path, prefix: &str, paths: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| anyhow::anyhow!("{name:?} isn't UTF-8"))?;
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = entry.file_type()?;
        if kind.is_dir() {
            walk(&entry.path(), &relative, paths)?;
            continue;
        }
        if !kind.is_file() {
            bail!("{relative} isn't a regular file");
        }
        if relative.contains(['\n', '\\']) {
            bail!("{relative:?} has a newline or backslash in its path");
        }
        paths.push(relative);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_like_git_and_sha256sum() {
        let hashes = hash_content(&b"hello\n"[..], 6).unwrap();
        // echo hello | sha256sum; echo hello | git hash-object --stdin
        assert_eq!(
            hashes.sha256,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        assert_eq!(hashes.blob_id, "ce013625030ba8dba906f756967f9e9ca394464a");
        assert!(hash_content(&b"hello\n"[..], 7).is_err());
    }

    #[test]
    fn tree_hash_matches_sha256sum() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("b.txt"), "b\n").unwrap();
        std::fs::write(dir.path().join("sub").join("a.txt"), "a\n").unwrap();

        let (hash, paths) = tree_hash(dir.path()).unwrap();
        assert_eq!(paths, ["b.txt", "sub/a.txt"]);
        // sha256sum's listing of the two files, hashed: computed outside
        // this code, with Python's hashlib.
        assert_eq!(
            hash,
            "19e35d7a6fd216e44331c175a72517d4eb7dd0dad65103a48c54eb6c660c30e9"
        );
        assert_eq!(
            hash_file(&dir.path().join("b.txt")).unwrap().sha256,
            "0263829989b6fd954f72baaf2fc64bc2e2f01d692d4de72986ea808f6e99813f"
        );
    }

    #[test]
    fn verifies_files() {
        let hashes = hash_content(&b"hello\n"[..], 6).unwrap();
        let in_git = File {
            path: "a".into(),
            size: 6,
            lfs: false,
            sha256: None,
            blob_id: "ce013625030ba8dba906f756967f9e9ca394464a".into(),
        };
        verify(&in_git, &hashes).unwrap();
        let in_lfs = File {
            lfs: true,
            sha256: Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".into()),
            ..in_git.clone()
        };
        verify(&in_lfs, &hashes).unwrap();
        let wrong = File {
            sha256: Some("00".into()),
            ..in_git
        };
        assert!(verify(&wrong, &hashes).is_err());
    }

    #[test]
    fn checks_paths() {
        for path in ["config.json", "onnx/model.bin"] {
            assert!(is_safe_path(path), "{path}");
        }
        for path in ["", "../x", "/etc/passwd", "a/../../b", "a\\b", "a\nb"] {
            assert!(!is_safe_path(path), "{path:?}");
        }
    }
}

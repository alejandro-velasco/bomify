//! The Hub, through hf-hub, plus the requests hf-hub can't make.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use hf_hub::repository::{RepoTreeEntry, RepoTypeModel};
use hf_hub::{HFClient, HFClientSync, HFRepositorySync};
use url::Url;

use crate::hash::is_safe_path;
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

    /// reference's repository.
    pub fn repository(&self, reference: &Ref) -> HFRepositorySync<RepoTypeModel> {
        self.model(&reference.namespace, &reference.name)
    }

    /// Every file in reference's repository at its commit (see
    /// list_repository).
    pub fn list_files(&self, reference: &Ref) -> Result<Vec<RepoFile>> {
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
    ) -> Result<Vec<RepoFile>> {
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
pub struct RepoFile {
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
pub fn files_of(repo_id: &str, entries: Vec<RepoTreeEntry>) -> Result<Vec<RepoFile>> {
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
        let file = RepoFile {
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

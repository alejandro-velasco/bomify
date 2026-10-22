//! component pull: a repository at a commit, to a directory.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::hash::{hash_file, hash_listing, local_paths, verify};
use crate::hub::{Hub, RepoFile};
use crate::log::Logger;
use crate::progress::Progress;
use crate::refs::{Ref, repository_page};

/// What pull prints, per the component contract.
#[derive(Serialize, Debug)]
pub struct PluginResult {
    #[serde(rename = "outputPath")]
    pub output_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<ResultHash>,
}

#[derive(Serialize, Debug)]
pub struct ResultHash {
    pub algorithm: &'static str,
    pub value: String,
}

/// Downloads every file of reference's repository at its commit into
/// output, each checked against the hash the Hub lists for it, and
/// returns their tree hash. Each file's download is reported to progress.
pub fn pull(
    hub: &Hub,
    reference: &Ref,
    output: &Path,
    progress: Option<Progress>,
    logger: &Logger,
) -> Result<PluginResult> {
    let files = hub.list_files(reference)?;
    logger.info(
        "downloading",
        &[
            ("repository", &reference.repo_id()),
            ("revision", &reference.revision),
            ("files", &files.len()),
        ],
    );

    hub.repository(reference)
        .snapshot_download()
        .revision(reference.revision.clone())
        .local_dir(output.to_path_buf())
        .maybe_progress(progress.map(hf_hub::progress::Progress::new))
        .send()
        .with_context(|| format!("download {}", reference.repo_id()))?;

    let paths = local_paths(output)?;
    let mut listed_paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
    listed_paths.sort_unstable();
    if paths != listed_paths {
        bail!(
            "{} has {} files on disk after the download, but the Hub lists {}",
            reference.repo_id(),
            paths.len(),
            listed_paths.len()
        );
    }

    let listed: HashMap<&str, &RepoFile> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let mut sha256s = HashMap::new();
    for path in &paths {
        let hashes = hash_file(&output.join(path))?;
        verify(listed[path.as_str()], &hashes).with_context(|| format!("download {path}"))?;
        sha256s.insert(path.clone(), hashes.sha256);
    }
    let hash = hash_listing(&paths, |path| Ok(sha256s[path].clone()))?;
    logger.info(
        "pulled",
        &[
            ("repository", &reference.repo_id()),
            ("revision", &reference.revision),
            ("files", &paths.len()),
            ("hash", &hash),
        ],
    );

    let result = PluginResult {
        output_path: output.display().to_string(),
        message: format!(
            "pulled {}@{} ({} files)",
            reference.repo_id(),
            reference.revision,
            paths.len()
        ),
        hash: Some(ResultHash {
            algorithm: "SHA-256",
            value: hash,
        }),
    };
    Ok(result)
}

/// Confirms reference's commit exists and its files can be downloaded, by
/// listing them and asking for one without downloading it. The hash needs
/// every file's content, so it isn't reported.
pub fn check_pull(hub: &Hub, reference: &Ref) -> Result<PluginResult> {
    let files = hub.list_files(reference)?;
    if let Some(file) = files.first() {
        hub.repository(reference)
            .get_file_metadata()
            .filepath(file.path.clone())
            .revision(&reference.revision)
            .send()
            .with_context(|| format!("check {} can be downloaded", file.path))?;
    }
    let result = PluginResult {
        output_path: format!(
            "{}@{}",
            repository_page(&hub.endpoint, &reference.repo_id()),
            reference.revision
        ),
        message: format!("{} files", files.len()),
        hash: None,
    };
    Ok(result)
}

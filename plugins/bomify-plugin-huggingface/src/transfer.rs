//! component pull and push: a repository at a commit, to a directory and
//! back to a hub.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context, Result, bail};
use hf_hub::repository::{CommitOperation, RepoTypeModel};
use serde::Serialize;

use crate::hub::{Hashes, Hub, hash_file, hash_listing, local_paths, verify};
use crate::log::Logger;
use crate::refs::{DEFAULT_BRANCH, Ref, is_commit_hash, parse_remote, repository_page};

/// What pull and push print, per the component contract.
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
/// returns their tree hash.
pub fn pull(hub: &Hub, reference: &Ref, output: &Path, logger: &Logger) -> Result<PluginResult> {
    let files = hub.list_files(reference)?;
    let count = files.len().to_string();
    logger.info(
        "downloading",
        &[
            ("repository", &reference.repo_id()),
            ("revision", &reference.revision),
            ("files", &count),
        ],
    );

    hub.model(&reference.namespace, &reference.name)
        .snapshot_download()
        .revision(reference.revision.clone())
        .local_dir(output.to_path_buf())
        .send()
        .with_context(|| format!("download {}", reference.repo_id()))?;

    let listed: HashMap<&str, _> = files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let paths = local_paths(output)?;
    let mut listed_paths: Vec<&str> = listed.keys().copied().collect();
    listed_paths.sort_unstable();
    if paths
        .iter()
        .map(String::as_str)
        .ne(listed_paths.iter().copied())
    {
        bail!(
            "{} has {} files on disk after the download, but the Hub lists {}",
            reference.repo_id(),
            paths.len(),
            listed.len()
        );
    }

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
            ("files", &count),
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
        hub.model(&reference.namespace, &reference.name)
            .get_file_metadata()
            .filepath(file.path.clone())
            .revision(&reference.revision)
            .send()
            .with_context(|| format!("check {} can be downloaded", file.path))?;
    }
    let result = PluginResult {
        output_path: format!(
            "{}/{}@{}",
            reference.remote(),
            reference.name,
            reference.revision
        ),
        message: format!("{} files", files.len()),
        hash: None,
    };
    Ok(result)
}

/// The most files one commit holds, as huggingface_hub's do.
const COMMIT_MAX_FILES: usize = 256;

/// The most inline content one commit holds: the Hub refuses a commit
/// whose body, holding small files base64-encoded, is too large.
const COMMIT_MAX_INLINE_BYTES: u64 = 100 << 20;

/// Files under this size are assumed to go inline, when splitting into
/// commits: the Hub sends larger ones, and binary ones, through Xet.
const INLINE_FILE_BYTES: u64 = 10 << 20;

/// Uploads input, a prior pull's output, to the main branch of the
/// repository named reference.name in remote's namespace (see
/// parse_remote), creating it, private, if it doesn't exist. Only files
/// main doesn't already hold go up, through Xet for large ones, so
/// pushing again after a failure resumes, and pushing the same files
/// twice commits nothing. Push refuses a repository holding files input
/// doesn't (other than the .gitattributes the Hub creates), since the
/// result wouldn't be the pulled model.
pub fn push(
    hub: &Hub,
    reference: &Ref,
    input: &Path,
    remote: &str,
    logger: &Logger,
) -> Result<PluginResult> {
    let (endpoint, namespace) = parse_remote(remote)?;
    let repo_id = format!("{namespace}/{}", reference.name);
    let published = repository_page(&endpoint, &repo_id);

    let mut local = BTreeMap::new();
    for path in local_paths(input)? {
        let hashes = hash_file(&input.join(&path))?;
        local.insert(path, hashes);
    }

    create_repository(hub, &namespace, &reference.name, logger)?;
    let repository = hub.model(&namespace, &reference.name);
    let info = repository
        .info()
        .revision(DEFAULT_BRANCH.to_string())
        .send()
        .with_context(|| format!("read {repo_id}'s {DEFAULT_BRANCH} branch"))?;
    let mut head = info
        .sha
        .filter(|sha| is_commit_hash(sha))
        .with_context(|| format!("{repo_id}'s {DEFAULT_BRANCH} branch names no commit"))?;
    let remote_files = hub.list_repository(&namespace, &reference.name, &head)?;

    let extra: Vec<&str> = remote_files
        .iter()
        .filter(|file| !local.contains_key(&file.path) && file.path != ".gitattributes")
        .map(|file| file.path.as_str())
        .collect();
    if !extra.is_empty() {
        bail!(
            "{repo_id} holds files the pulled model doesn't ({}): push into an empty repository, or one holding this model",
            extra.join(", ")
        );
    }
    let unchanged: Vec<&str> = remote_files
        .iter()
        .filter(|file| {
            local
                .get(&file.path)
                .is_some_and(|hashes| verify(file, hashes).is_ok())
        })
        .map(|file| file.path.as_str())
        .collect();
    let changed: Vec<(&String, &Hashes)> = local
        .iter()
        .filter(|(path, _)| !unchanged.contains(&path.as_str()))
        .collect();

    if changed.is_empty() {
        logger.info(
            "already up to date",
            &[("repository", &repo_id), ("commit", &head)],
        );
        let result = PluginResult {
            output_path: format!("{published}@{head}"),
            message: "already up to date".to_string(),
            hash: None,
        };
        return Ok(result);
    }

    let batches = commit_batches(&changed);
    let mut commit_url = String::new();
    for (index, batch) in batches.iter().enumerate() {
        let operations: Vec<CommitOperation> = batch
            .iter()
            .map(|(path, _)| CommitOperation::add_file(path.as_str(), input.join(path)))
            .collect();
        let mut message = format!("Upload {}@{}", reference.repo_id(), reference.revision);
        if batches.len() > 1 {
            message.push_str(&format!(" ({}/{})", index + 1, batches.len()));
        }
        let commit = repository
            .create_commit()
            .operations(operations)
            .commit_message(message)
            .revision(DEFAULT_BRANCH.to_string())
            .parent_commit(head.clone())
            .send()
            .with_context(|| format!("commit to {repo_id}"))?;
        head = commit.commit_oid.with_context(|| {
            format!("the Hub's answer to a commit to {repo_id} names no commit")
        })?;
        commit_url = commit
            .commit_url
            .unwrap_or_else(|| format!("{published}/commit/{head}"));
        let files = batch.len().to_string();
        logger.info(
            "committed",
            &[
                ("repository", &repo_id),
                ("commit", &commit_url),
                ("files", &files),
            ],
        );
    }

    let result = PluginResult {
        output_path: format!("{published}@{head}"),
        message: format!(
            "committed {commit_url} ({} of {} files changed, in {} commits)",
            changed.len(),
            local.len(),
            batches.len()
        ),
        hash: None,
    };
    Ok(result)
}

/// Creates repo_id, a private model repository, unless it exists. A token
/// allowed to write to it but not to create repositories is refused, so
/// then it only has to exist.
fn create_repository(hub: &Hub, namespace: &str, name: &str, logger: &Logger) -> Result<()> {
    let repo_id = format!("{namespace}/{name}");
    let created = hub
        .client
        .create_repository()
        .repo_id(&repo_id)
        .repo_type(RepoTypeModel)
        .private(true)
        .exist_ok(true)
        .send();
    match created {
        Ok(_) => Ok(()),
        Err(error) => {
            if hub.model(namespace, name).exists().send().unwrap_or(false) {
                logger.warn(
                    "couldn't create the repository, but it exists",
                    &[("repository", &repo_id), ("error", &error.to_string())],
                );
                return Ok(());
            }
            Err(error).with_context(|| format!("create {repo_id}"))
        }
    }
}

/// Splits files into commits of at most COMMIT_MAX_FILES files and
/// COMMIT_MAX_INLINE_BYTES of inline content.
fn commit_batches<'a>(files: &[(&'a String, &'a Hashes)]) -> Vec<Vec<(&'a String, &'a Hashes)>> {
    let mut batches = Vec::new();
    let mut batch: Vec<(&String, &Hashes)> = Vec::new();
    let mut inline = 0;
    for &(path, hashes) in files {
        let size = if hashes.size < INLINE_FILE_BYTES {
            hashes.size
        } else {
            0
        };
        if !batch.is_empty()
            && (batch.len() == COMMIT_MAX_FILES || inline + size > COMMIT_MAX_INLINE_BYTES)
        {
            batches.push(std::mem::take(&mut batch));
            inline = 0;
        }
        batch.push((path, hashes));
        inline += size;
    }
    if !batch.is_empty() {
        batches.push(batch);
    }
    batches
}

/// Confirms there's a valid token for remote's hub. Write access to the
/// namespace can't be checked without writing, so it isn't.
pub fn check_push(hub: &Hub, reference: &Ref, remote: &str) -> Result<PluginResult> {
    let (endpoint, namespace) = parse_remote(remote)?;
    let user = hub.client.whoami().send().context("check the token")?;
    let result = PluginResult {
        output_path: repository_page(&endpoint, &format!("{namespace}/{}", reference.name)),
        message: format!(
            "authenticated as {}; write access to {namespace} isn't checked",
            user.username
        ),
        hash: None,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hashes(size: u64) -> Hashes {
        Hashes {
            size,
            sha256: String::new(),
            blob_id: String::new(),
        }
    }

    #[test]
    fn splits_commits() {
        let paths: Vec<String> = (0..600).map(|index| format!("f{index}")).collect();
        let small = hashes(1);
        let files: Vec<(&String, &Hashes)> = paths.iter().map(|path| (path, &small)).collect();
        let sizes: Vec<usize> = commit_batches(&files).iter().map(Vec::len).collect();
        assert_eq!(sizes, [256, 256, 88]);

        // Large files go through Xet, so they don't count: 8 of 9 MiB
        // inline is 72 MiB, one commit.
        let medium = hashes(9 << 20);
        let large = hashes(5 << 30);
        let files: Vec<(&String, &Hashes)> = (0..15)
            .map(|index| (&paths[index], if index % 2 == 0 { &medium } else { &large }))
            .collect();
        let sizes: Vec<usize> = commit_batches(&files).iter().map(Vec::len).collect();
        assert_eq!(sizes, [15]);

        // 13 of 9 MiB is 117 MiB: the 12th would pass 100 MiB.
        let files: Vec<(&String, &Hashes)> =
            (0..13).map(|index| (&paths[index], &medium)).collect();
        let sizes: Vec<usize> = commit_batches(&files).iter().map(Vec::len).collect();
        assert_eq!(sizes, [11, 2]);
    }
}

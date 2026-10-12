//! component pull and push: a repository at a commit, to a directory and
//! back to a hub.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use hf_hub::HFRepositorySync;
use hf_hub::repository::{CommitOperation, RepoTypeModel};
use serde::Serialize;

use crate::hash::{Hashes, hash_file, hash_listing, local_paths, verify};
use crate::hub::{Hub, RepoFile};
use crate::log::Logger;
use crate::refs::{DEFAULT_BRANCH, Ref, Remote, is_commit_hash, repository_page};

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

/// A file of push's input, hashed.
struct LocalFile {
    /// Its "/"-separated path under the input directory.
    path: String,
    hashes: Hashes,
}

/// Uploads input, a prior pull's output, to the main branch of the
/// repository named reference.name in remote's namespace, creating it,
/// private, if it doesn't exist. Only files main doesn't already hold go
/// up (see changed_files), so pushing again after a failure resumes, and
/// pushing the same files twice commits nothing.
pub fn push(
    hub: &Hub,
    reference: &Ref,
    input: &Path,
    remote: &Remote,
    logger: &Logger,
) -> Result<PluginResult> {
    let repo_id = remote.repo_id(&reference.name);
    let published = repository_page(&remote.endpoint, &repo_id);
    let local = hash_local_files(input)?;
    let total = local.len();

    create_repository(hub, remote, &reference.name, logger)?;
    let repository = hub.model(&remote.namespace, &reference.name);
    let head = branch_head(&repository, &repo_id)?;
    let remote_files = hub.list_repository(&remote.namespace, &reference.name, &head)?;
    let changed = changed_files(&repo_id, local, &remote_files)?;

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

    let message = format!("Upload {}@{}", reference.repo_id(), reference.revision);
    let commits = commit(
        &repository,
        &repo_id,
        input,
        &changed,
        &message,
        head,
        logger,
    )?;
    let commit_url = commits
        .url
        .unwrap_or_else(|| format!("{published}/commit/{}", commits.head));

    let result = PluginResult {
        output_path: format!("{published}@{}", commits.head),
        message: format!(
            "committed {commit_url} ({} of {total} files changed, in {} commits)",
            changed.len(),
            commits.count
        ),
        hash: None,
    };
    Ok(result)
}

/// Every file under input, hashed, sorted by path.
fn hash_local_files(input: &Path) -> Result<Vec<LocalFile>> {
    let mut files = Vec::new();
    for path in local_paths(input)? {
        let hashes = hash_file(&input.join(&path))?;
        files.push(LocalFile { path, hashes });
    }
    Ok(files)
}

/// The commit repository's main branch points at.
fn branch_head(repository: &HFRepositorySync<RepoTypeModel>, repo_id: &str) -> Result<String> {
    let info = repository
        .info()
        .revision(DEFAULT_BRANCH.to_string())
        .send()
        .with_context(|| format!("read {repo_id}'s {DEFAULT_BRANCH} branch"))?;
    info.sha
        .filter(|sha| is_commit_hash(sha))
        .with_context(|| format!("{repo_id}'s {DEFAULT_BRANCH} branch names no commit"))
}

/// The files of local the repository, holding remote_files, doesn't
/// already hold. A repository holding files local doesn't (other than the
/// .gitattributes the Hub creates) is refused, since pushing into it
/// wouldn't make it the pulled model.
fn changed_files(
    repo_id: &str,
    local: Vec<LocalFile>,
    remote_files: &[RepoFile],
) -> Result<Vec<LocalFile>> {
    let local_paths: HashSet<&str> = local.iter().map(|file| file.path.as_str()).collect();
    let extra: Vec<&str> = remote_files
        .iter()
        .map(|file| file.path.as_str())
        .filter(|path| !local_paths.contains(path) && *path != ".gitattributes")
        .collect();
    if !extra.is_empty() {
        bail!(
            "{repo_id} holds files the pulled model doesn't ({}): push into an empty repository, or one holding this model",
            extra.join(", ")
        );
    }

    let remote_by_path: HashMap<&str, &RepoFile> = remote_files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let changed = local
        .into_iter()
        .filter(|file| {
            let held = remote_by_path.get(file.path.as_str());
            !held.is_some_and(|remote_file| verify(remote_file, &file.hashes).is_ok())
        })
        .collect();
    Ok(changed)
}

/// What commit made: the branch's new head, the last commit's page if the
/// Hub gave one, and how many commits it took.
struct Commits {
    head: String,
    url: Option<String>,
    count: usize,
}

/// Commits files, under input, to repository's main branch, on top of
/// head, in as many commits as commit_batches splits them into.
fn commit(
    repository: &HFRepositorySync<RepoTypeModel>,
    repo_id: &str,
    input: &Path,
    files: &[LocalFile],
    message: &str,
    mut head: String,
    logger: &Logger,
) -> Result<Commits> {
    let batches = commit_batches(files);
    let mut url = None;
    for (index, batch) in batches.iter().enumerate() {
        let operations: Vec<CommitOperation> = batch
            .iter()
            .map(|file| CommitOperation::add_file(file.path.as_str(), input.join(&file.path)))
            .collect();
        let mut batch_message = message.to_string();
        if batches.len() > 1 {
            batch_message.push_str(&format!(" ({}/{})", index + 1, batches.len()));
        }
        let commit = repository
            .create_commit()
            .operations(operations)
            .commit_message(batch_message)
            .revision(DEFAULT_BRANCH.to_string())
            .parent_commit(head.clone())
            .send()
            .with_context(|| format!("commit to {repo_id}"))?;
        head = commit.commit_oid.with_context(|| {
            format!("the Hub's answer to a commit to {repo_id} names no commit")
        })?;
        url = commit.commit_url;
        logger.info(
            "committed",
            &[
                ("repository", &repo_id),
                ("commit", &head),
                ("files", &batch.len()),
            ],
        );
    }
    let commits = Commits {
        head,
        url,
        count: batches.len(),
    };
    Ok(commits)
}

/// Creates name, a private model repository in remote's namespace, unless
/// it exists. A token allowed to write to it but not to create
/// repositories is refused, so then it only has to exist.
fn create_repository(hub: &Hub, remote: &Remote, name: &str, logger: &Logger) -> Result<()> {
    let repo_id = remote.repo_id(name);
    let created = hub
        .client
        .create_repository()
        .repo_id(&repo_id)
        .repo_type(RepoTypeModel)
        .private(true)
        .exist_ok(true)
        .send();
    let Err(error) = created else {
        return Ok(());
    };
    let exists = hub
        .model(&remote.namespace, name)
        .exists()
        .send()
        .unwrap_or(false);
    if !exists {
        return Err(error).with_context(|| format!("create {repo_id}"));
    }
    logger.warn(
        "couldn't create the repository, but it exists",
        &[("repository", &repo_id), ("error", &error)],
    );
    Ok(())
}

/// Splits files into runs of at most COMMIT_MAX_FILES files and
/// COMMIT_MAX_INLINE_BYTES of inline content, one per commit.
fn commit_batches(files: &[LocalFile]) -> Vec<&[LocalFile]> {
    let mut batches = Vec::new();
    let mut start = 0;
    let mut inline = 0;
    for (index, file) in files.iter().enumerate() {
        let size = if file.hashes.size < INLINE_FILE_BYTES {
            file.hashes.size
        } else {
            0
        };
        let full = index - start == COMMIT_MAX_FILES || inline + size > COMMIT_MAX_INLINE_BYTES;
        if index > start && full {
            batches.push(&files[start..index]);
            start = index;
            inline = 0;
        }
        inline += size;
    }
    if start < files.len() {
        batches.push(&files[start..]);
    }
    batches
}

/// Confirms there's a valid token for remote's hub. Write access to the
/// namespace can't be checked without writing, so it isn't.
pub fn check_push(hub: &Hub, reference: &Ref, remote: &Remote) -> Result<PluginResult> {
    let user = hub.client.whoami().send().context("check the token")?;
    let result = PluginResult {
        output_path: repository_page(&remote.endpoint, &remote.repo_id(&reference.name)),
        message: format!(
            "authenticated as {}; write access to {} isn't checked",
            user.username, remote.namespace
        ),
        hash: None,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_content;

    /// A local file of size bytes, its hashes otherwise empty.
    fn sized(path: &str, size: u64) -> LocalFile {
        let hashes = Hashes {
            size,
            sha256: String::new(),
            blob_id: String::new(),
        };
        LocalFile {
            path: path.to_string(),
            hashes,
        }
    }

    fn batch_sizes(files: &[LocalFile]) -> Vec<usize> {
        commit_batches(files)
            .iter()
            .map(|batch| batch.len())
            .collect()
    }

    #[test]
    fn splits_commits() {
        let small: Vec<LocalFile> = (0..600)
            .map(|index| sized(&format!("f{index}"), 1))
            .collect();
        assert_eq!(batch_sizes(&small), [256, 256, 88]);

        // Large files go through Xet, so they don't count: 8 of 9 MiB
        // inline is 72 MiB, one commit.
        let mixed: Vec<LocalFile> = (0..15)
            .map(|index| {
                let size = if index % 2 == 0 { 9 << 20 } else { 5 << 30 };
                sized(&format!("f{index}"), size)
            })
            .collect();
        assert_eq!(batch_sizes(&mixed), [15]);

        // 13 of 9 MiB is 117 MiB: the 12th would pass 100 MiB.
        let medium: Vec<LocalFile> = (0..13)
            .map(|index| sized(&format!("f{index}"), 9 << 20))
            .collect();
        assert_eq!(batch_sizes(&medium), [11, 2]);
    }

    /// A local file holding content, and the Hub's listing of it.
    fn file(path: &str, content: &str) -> (LocalFile, RepoFile) {
        let hashes = hash_content(content.as_bytes(), content.len() as u64).unwrap();
        let listed = RepoFile {
            path: path.to_string(),
            size: hashes.size,
            lfs: false,
            sha256: None,
            blob_id: hashes.blob_id.clone(),
        };
        let local = LocalFile {
            path: path.to_string(),
            hashes,
        };
        (local, listed)
    }

    #[test]
    fn finds_changed_files() {
        let (same, same_listed) = file("same.txt", "same\n");
        let (changed, _) = file("changed.txt", "new\n");
        let (_, changed_listed) = file("changed.txt", "old\n");
        let (new, _) = file("new.txt", "new\n");
        let (_, attributes) = file(".gitattributes", "*.bin filter=lfs\n");
        let remote_files = [same_listed, changed_listed, attributes];

        let found = changed_files("org/model", vec![same, changed, new], &remote_files).unwrap();
        let paths: Vec<&str> = found.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, ["changed.txt", "new.txt"]);

        let (_, extra) = file("extra.txt", "extra\n");
        let error = changed_files("org/model", Vec::new(), &[extra])
            .err()
            .unwrap();
        assert!(format!("{error}").contains("extra.txt"), "{error}");
    }
}

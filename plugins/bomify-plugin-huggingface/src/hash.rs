//! What bomify checks on top of the Hub: each file's hash, the
//! repository's tree hash, and that every path stays inside the directory
//! it's written into.

use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::hub::RepoFile;

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
    let file = File::open(path).with_context(|| format!("hash {}", path.display()))?;
    let size = file.metadata()?.len();
    hash_content(file, size).with_context(|| format!("hash {}", path.display()))
}

/// Checks hashes against what the Hub lists for file: its SHA-256, for a
/// file in LFS, else its Git blob ID; and its size.
pub fn verify(file: &RepoFile, hashes: &Hashes) -> Result<()> {
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
        let in_git = RepoFile {
            path: "a".into(),
            size: 6,
            lfs: false,
            sha256: None,
            blob_id: "ce013625030ba8dba906f756967f9e9ca394464a".into(),
        };
        verify(&in_git, &hashes).unwrap();
        let in_lfs = RepoFile {
            lfs: true,
            sha256: Some("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03".into()),
            ..in_git.clone()
        };
        verify(&in_lfs, &hashes).unwrap();
        let wrong = RepoFile {
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

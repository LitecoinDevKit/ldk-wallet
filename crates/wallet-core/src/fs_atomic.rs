//! Atomic file persistence via sibling temp-file, `sync_all`, and `rename`.
//!
//! Every wallet state file is written to `<name>.tmp.<pid>.<seq>` in the same
//! directory, flushed with `File::sync_all`, and renamed over the target path.
//! Secret and sealed files are created with mode `0600` on Unix before any
//! bytes are written. A hard kill mid-write leaves the previous target file
//! intact; leftover `*.tmp.*` files are swept on account load and wallet wipe.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(1);

/// Atomically replace `path` with `bytes` using default file permissions.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_inner(path, bytes, false)
}

/// Atomically replace `path` with `bytes`, creating the file with mode `0600` on Unix.
pub(crate) fn write_atomic_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_inner(path, bytes, true)
}

fn temp_path_for(path: &Path) -> io::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy();
    let seq = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    Ok(path.with_file_name(format!("{file_name}.tmp.{pid}.{seq}")))
}

fn write_atomic_inner(path: &Path, bytes: &[u8], mode_0600: bool) -> io::Result<()> {
    if path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("target path is a directory: {}", path.display()),
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = temp_path_for(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if mode_0600 {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp_path)?;
    let write_res = (|| -> io::Result<()> {
        #[cfg(unix)]
        if mode_0600 {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(e) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn is_temp_file_name(name: &str) -> bool {
    name.ends_with(".tmp") || name.contains(".tmp.")
}

/// Remove any leftover `*.tmp` / `*.tmp.*` files in `dir` from an interrupted write.
pub(crate) fn sweep_temp_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_temp_file_name(name) && path.is_file() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_atomic_replaces_file_and_cleans_up_on_error() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("sample.json");
        write_atomic(&target, b"first").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"first");
        write_atomic(&target, b"second").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second");

        // Directory blocker must fail without leaving a .tmp file behind.
        let dir_blocker = dir.path().join("blocker.json");
        fs::create_dir_all(&dir_blocker).unwrap();
        assert!(write_atomic(&dir_blocker, b"nope").is_err());
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| is_temp_file_name(n)),
            "stray temp files: {names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_0600_sets_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let target = dir.path().join("secret.enc");
        write_atomic_0600(&target, b"cipher").unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn sweep_removes_only_temp_files() {
        let dir = tempdir().unwrap();
        let keep = dir.path().join("wallet_meta.json");
        let tmp1 = dir.path().join("wallet_meta.json.tmp.123.1");
        let tmp2 = dir.path().join("mweb_broadcast_peers.json.tmp");
        fs::write(&keep, b"{}").unwrap();
        fs::write(&tmp1, b"partial").unwrap();
        fs::write(&tmp2, b"partial").unwrap();

        sweep_temp_files(dir.path());

        assert!(keep.exists());
        assert!(!tmp1.exists());
        assert!(!tmp2.exists());
    }
}

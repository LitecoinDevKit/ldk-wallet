//! Wipeable sidecar of transparent split txids (same privacy class as tx labels).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::WalletError;

pub const SPLIT_IDS_FILE: &str = "split_txids.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SplitIdsFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub txids: BTreeSet<String>,
}

fn default_version() -> u32 {
    1
}

pub fn split_ids_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SPLIT_IDS_FILE)
}

pub fn read_ids(data_dir: &Path) -> Result<SplitIdsFile, WalletError> {
    let path = split_ids_path(data_dir);
    if !path.is_file() {
        return Ok(SplitIdsFile {
            version: 1,
            txids: BTreeSet::new(),
        });
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_ids(data_dir: &Path, file: &SplitIdsFile) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    if file.txids.is_empty() {
        match fs::remove_file(split_ids_path(data_dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        }
    } else {
        let json =
            serde_json::to_string_pretty(file).map_err(|e| WalletError::Meta(e.to_string()))?;
        crate::fs_atomic::write_atomic(&split_ids_path(data_dir), json.as_bytes())?;
        Ok(())
    }
}

pub fn record_txid(data_dir: &Path, txid: &str) -> Result<(), WalletError> {
    let txid = txid.trim();
    if txid.is_empty() {
        return Err(WalletError::Meta("txid required for split record".into()));
    }
    let mut file = read_ids(data_dir)?;
    file.txids.insert(txid.to_string());
    write_ids(data_dir, &file)
}

#[allow(dead_code)]
pub fn contains(data_dir: &Path, txid: &str) -> bool {
    read_ids(data_dir)
        .map(|f| f.txids.contains(txid))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        record_txid(dir.path(), "abc").unwrap();
        assert!(contains(dir.path(), "abc"));
        assert!(!contains(dir.path(), "zzz"));
    }
}

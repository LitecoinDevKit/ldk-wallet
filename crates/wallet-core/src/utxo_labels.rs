//! Local UTXO labels (non-secret sidecar next to wallet meta).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::WalletError;
use crate::labels::normalize_label;

pub const UTXO_LABELS_FILE: &str = "utxo_labels.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UtxoLabelsFile {
    #[serde(default = "default_version")]
    pub version: u32,
    /// Keyed by `txid:vout` (public) or 64-char hex MWEB output id (private).
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

fn default_version() -> u32 {
    1
}

pub fn labels_path(data_dir: &Path) -> PathBuf {
    data_dir.join(UTXO_LABELS_FILE)
}

pub fn read_labels(data_dir: &Path) -> Result<UtxoLabelsFile, WalletError> {
    let path = labels_path(data_dir);
    if !path.is_file() {
        return Ok(UtxoLabelsFile {
            version: 1,
            labels: HashMap::new(),
        });
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_labels(data_dir: &Path, file: &UtxoLabelsFile) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    let json = serde_json::to_string_pretty(file).map_err(|e| WalletError::Meta(e.to_string()))?;
    fs::write(labels_path(data_dir), json)?;
    Ok(())
}

fn is_coin_id(key: &str) -> bool {
    if key.contains(':') {
        let (txid, vout) = key.split_once(':').unwrap_or(("", ""));
        return !txid.is_empty() && !vout.is_empty();
    }
    crate::mweb_frozen::is_output_id_hex(key)
}

/// Set or clear a label. Empty `label` deletes the entry.
///
/// `outpoint` is a public `txid:vout` or a 64-character MWEB output-id hex.
pub fn set_label(data_dir: &Path, outpoint: &str, label: &str) -> Result<(), WalletError> {
    let outpoint = outpoint.trim();
    if outpoint.is_empty() {
        return Err(WalletError::Meta("outpoint required for label".into()));
    }
    if !is_coin_id(outpoint) {
        return Err(WalletError::Meta(
            "coin id must look like txid:vout or a 32-byte hex MWEB output id".into(),
        ));
    }
    let mut file = read_labels(data_dir)?;
    let note = normalize_label(label);
    if note.is_empty() {
        file.labels.remove(outpoint);
    } else {
        file.labels.insert(outpoint.to_string(), note);
    }
    if file.labels.is_empty() {
        let path = labels_path(data_dir);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        }
    } else {
        write_labels(data_dir, &file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        set_label(dir.path(), "abcd:0", "  Exchange  ").unwrap();
        let file = read_labels(dir.path()).unwrap();
        assert_eq!(
            file.labels.get("abcd:0").map(String::as_str),
            Some("Exchange")
        );
        set_label(dir.path(), "abcd:0", "").unwrap();
        assert!(!labels_path(dir.path()).is_file());
    }

    #[test]
    fn mweb_output_id_round_trip() {
        let dir = tempdir().unwrap();
        let id = "cd".repeat(32);
        set_label(dir.path(), &id, " peg-out prep ").unwrap();
        let file = read_labels(dir.path()).unwrap();
        assert_eq!(
            file.labels.get(&id).map(String::as_str),
            Some("peg-out prep")
        );
        set_label(dir.path(), &id, "").unwrap();
        assert!(!labels_path(dir.path()).is_file());
    }
}

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
    persist(data_dir, &file)
}

/// Move a private-coin label onto the output a self-spend created.
///
/// No label on `from` leaves the file unchanged.
pub fn move_label(data_dir: &Path, from: &str, to: &str) -> Result<(), WalletError> {
    let from_id = crate::mweb_frozen::normalize_output_id(from)?;
    let to_id = crate::mweb_frozen::normalize_output_id(to)?;
    if from_id == to_id {
        return Ok(());
    }
    let mut file = read_labels(data_dir)?;
    let Some(note) = remove_label_ignore_case(&mut file, &from_id) else {
        return Ok(());
    };
    remove_label_ignore_case(&mut file, &to_id);
    file.labels.insert(to_id, note);
    persist(data_dir, &file)
}

fn remove_label_ignore_case(file: &mut UtxoLabelsFile, id: &str) -> Option<String> {
    if let Some(note) = file.labels.remove(id) {
        return Some(note);
    }
    let key = file
        .labels
        .keys()
        .find(|key| key.eq_ignore_ascii_case(id))
        .cloned()?;
    file.labels.remove(&key)
}

fn persist(data_dir: &Path, file: &UtxoLabelsFile) -> Result<(), WalletError> {
    if file.labels.is_empty() {
        let path = labels_path(data_dir);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        }
    } else {
        write_labels(data_dir, file)
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

    #[test]
    fn move_label_renames_and_missing_is_noop() {
        let dir = tempdir().unwrap();
        let from = "ab".repeat(32);
        let to = "cd".repeat(32);
        let missing = "ef".repeat(32);

        move_label(dir.path(), &from, &to).unwrap();
        assert!(!labels_path(dir.path()).is_file());

        set_label(dir.path(), &from, "savings").unwrap();
        move_label(dir.path(), &from, &to).unwrap();
        let file = read_labels(dir.path()).unwrap();
        assert_eq!(file.labels.get(&to).map(String::as_str), Some("savings"));
        assert!(!file.labels.contains_key(&from));

        move_label(dir.path(), &missing, &to).unwrap();
        let file = read_labels(dir.path()).unwrap();
        assert_eq!(file.labels.get(&to).map(String::as_str), Some("savings"));
    }
}

//! Versioned export/import of non-secret wallet metadata (contacts + labels).

use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::churn;
use crate::contacts::{self, ContactsFile};
use crate::dto::ChurnDepthRecord;
use crate::dto::ContactRecord;
use crate::error::WalletError;
use crate::labels::{self, TxLabelsFile};
use crate::mweb_frozen::{self, MwebFrozenFile};
use crate::split_ids::{self, SplitIdsFile};
use crate::utxo_labels::{self, UtxoLabelsFile};

pub const METADATA_BUNDLE_VERSION: u32 = 1;

/// Portable JSON bundle — never includes mnemonic or passphrase material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataBundle {
    pub version: u32,
    /// Unix seconds when exported (informational).
    #[serde(default)]
    pub exported_at: Option<u64>,
    #[serde(default)]
    pub contacts: Vec<ContactRecord>,
    #[serde(default)]
    pub tx_labels: HashMap<String, String>,
    #[serde(default)]
    pub utxo_labels: HashMap<String, String>,
    /// Transparent split txids (History kind `split`).
    #[serde(default)]
    pub split_txids: Vec<String>,
    /// Frozen MWEB output ids (hex).
    #[serde(default)]
    pub mweb_frozen: Vec<String>,
    /// Per-coin self-spend depth. Without this, a restore shows the count as unknown.
    #[serde(default)]
    pub churn_depth: Vec<ChurnDepthRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataImportResult {
    pub contacts_upserted: usize,
    pub tx_labels_upserted: usize,
    pub utxo_labels_upserted: usize,
    pub split_txids_upserted: usize,
    #[serde(default)]
    pub mweb_frozen_upserted: usize,
    #[serde(default)]
    pub churn_depth_upserted: usize,
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn export_bundle(data_dir: &Path) -> Result<MetadataBundle, WalletError> {
    let contacts = contacts::read_contacts(data_dir)?.contacts;
    let tx_labels = labels::read_labels(data_dir)?.labels;
    let utxo_labels = utxo_labels::read_labels(data_dir)?.labels;
    let split_txids = split_ids::read_ids(data_dir)?.txids.into_iter().collect();
    let mweb_frozen = mweb_frozen::read_ids(data_dir)?.ids.into_iter().collect();
    let churn_depth = churn::list_depth(data_dir)?;
    Ok(MetadataBundle {
        version: METADATA_BUNDLE_VERSION,
        exported_at: Some(now_ts()),
        contacts,
        tx_labels,
        utxo_labels,
        split_txids,
        mweb_frozen,
        churn_depth,
    })
}

pub fn export_json(data_dir: &Path) -> Result<String, WalletError> {
    let bundle = export_bundle(data_dir)?;
    serde_json::to_string_pretty(&bundle).map_err(|e| WalletError::Meta(e.to_string()))
}

/// Merge imported metadata into local sidecars (import overlays; does not delete
/// local entries that are absent from the file).
pub fn import_json(data_dir: &Path, json: &str) -> Result<MetadataImportResult, WalletError> {
    let bundle: MetadataBundle = serde_json::from_str(json)
        .map_err(|e| WalletError::Meta(format!("invalid metadata JSON: {e}")))?;
    if bundle.version == 0 || bundle.version > METADATA_BUNDLE_VERSION {
        return Err(WalletError::Meta(format!(
            "unsupported metadata bundle version {}",
            bundle.version
        )));
    }

    let mut contacts_file = contacts::read_contacts(data_dir)?;
    let mut contacts_upserted = 0usize;
    for contact in bundle.contacts {
        if contact.id.trim().is_empty() || contact.address.trim().is_empty() {
            continue;
        }
        if let Some(existing) = contacts_file
            .contacts
            .iter_mut()
            .find(|c| c.id == contact.id)
        {
            *existing = contact;
        } else if let Some(existing) = contacts_file
            .contacts
            .iter_mut()
            .find(|c| c.address == contact.address && c.kind == contact.kind)
        {
            existing.name = contact.name;
            existing.id = contact.id;
        } else {
            contacts_file.contacts.push(contact);
        }
        contacts_upserted += 1;
    }
    if contacts_file.contacts.is_empty() {
        let _ = contacts_file;
    } else {
        contacts::write_contacts(
            data_dir,
            &ContactsFile {
                version: 1,
                contacts: contacts_file.contacts,
            },
        )?;
    }

    let mut tx_file = labels::read_labels(data_dir)?;
    let mut tx_labels_upserted = 0usize;
    for (txid, label) in bundle.tx_labels {
        let note = labels::normalize_label(&label);
        if txid.trim().is_empty() || note.is_empty() {
            continue;
        }
        tx_file.labels.insert(txid.trim().to_string(), note);
        tx_labels_upserted += 1;
    }
    if !tx_file.labels.is_empty() {
        labels::write_labels(
            data_dir,
            &TxLabelsFile {
                version: 1,
                labels: tx_file.labels,
            },
        )?;
    }

    let mut utxo_file = utxo_labels::read_labels(data_dir)?;
    let mut utxo_labels_upserted = 0usize;
    for (outpoint, label) in bundle.utxo_labels {
        let note = labels::normalize_label(&label);
        if outpoint.trim().is_empty() || note.is_empty() {
            continue;
        }
        utxo_file.labels.insert(outpoint.trim().to_string(), note);
        utxo_labels_upserted += 1;
    }
    if !utxo_file.labels.is_empty() {
        utxo_labels::write_labels(
            data_dir,
            &UtxoLabelsFile {
                version: 1,
                labels: utxo_file.labels,
            },
        )?;
    }

    let mut split_file = split_ids::read_ids(data_dir)?;
    let mut split_txids_upserted = 0usize;
    for txid in bundle.split_txids {
        let id = txid.trim();
        if id.is_empty() {
            continue;
        }
        if split_file.txids.insert(id.to_string()) {
            split_txids_upserted += 1;
        }
    }
    if !split_file.txids.is_empty() {
        split_ids::write_ids(
            data_dir,
            &SplitIdsFile {
                version: 1,
                txids: split_file.txids,
            },
        )?;
    }

    let mut frozen_file = mweb_frozen::read_ids(data_dir)?;
    let mut mweb_frozen_upserted = 0usize;
    for id in bundle.mweb_frozen {
        let Ok(id) = mweb_frozen::normalize_output_id(&id) else {
            continue;
        };
        if frozen_file.ids.insert(id) {
            mweb_frozen_upserted += 1;
        }
    }
    if !frozen_file.ids.is_empty() {
        mweb_frozen::write_ids(
            data_dir,
            &MwebFrozenFile {
                version: 1,
                ids: frozen_file.ids,
            },
        )?;
    }

    let churn_depth_upserted = churn::upsert_depth(data_dir, &bundle.churn_depth)?;

    Ok(MetadataImportResult {
        contacts_upserted,
        tx_labels_upserted,
        utxo_labels_upserted,
        split_txids_upserted,
        mweb_frozen_upserted,
        churn_depth_upserted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn export_import_merge() {
        let dir = tempdir().unwrap();
        labels::set_label(dir.path(), "aaa", "note-a").unwrap();
        utxo_labels::set_label(dir.path(), "bbb:0", "coin-b").unwrap();
        let id = "ab".repeat(32);
        mweb_frozen::set_locked(dir.path(), &id, true).unwrap();

        let json = export_json(dir.path()).unwrap();
        let _ = std::fs::remove_file(labels::labels_path(dir.path()));
        let _ = std::fs::remove_file(mweb_frozen::frozen_path(dir.path()));
        labels::set_label(dir.path(), "keep", "local").unwrap();
        let result = import_json(dir.path(), &json).unwrap();
        assert_eq!(result.tx_labels_upserted, 1);
        assert_eq!(result.utxo_labels_upserted, 1);
        assert_eq!(result.mweb_frozen_upserted, 1);
        let labels = labels::read_labels(dir.path()).unwrap().labels;
        assert_eq!(labels.get("aaa").map(String::as_str), Some("note-a"));
        assert_eq!(labels.get("keep").map(String::as_str), Some("local"));
        assert!(mweb_frozen::contains(dir.path(), &id));
    }

    #[test]
    fn churn_depth_round_trip() {
        let dir = tempdir().unwrap();
        let output_id = "cd".repeat(32);
        churn::upsert_depth(
            dir.path(),
            &[ChurnDepthRecord {
                output_id: output_id.clone(),
                non_solo_blocks: 2,
                last_other_kernels: Some(3),
                last_other_outputs: Some(4),
                from_pegin: true,
            }],
        )
        .unwrap();
        let json = export_json(dir.path()).unwrap();
        let _ = std::fs::remove_file(churn::depth_path(dir.path()));
        let result = import_json(dir.path(), &json).unwrap();
        assert_eq!(result.churn_depth_upserted, 1);
        let restored = churn::depth_of(dir.path(), &output_id).unwrap().unwrap();
        assert_eq!(restored.non_solo_blocks, 2);
        assert_eq!(restored.last_other_kernels, Some(3));
        assert_eq!(restored.last_other_outputs, Some(4));
        assert!(restored.from_pegin);
    }
}

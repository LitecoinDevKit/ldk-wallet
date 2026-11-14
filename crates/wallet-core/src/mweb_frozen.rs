//! Wipeable sidecar of frozen MWEB output ids (same privacy class as UTXO labels).
//!
//! `ids` are the user's freezes. `reserved` are private coins a send, peg-out,
//! split or transfer has signed and is still broadcasting; `public_reserved` are
//! the same for public coins (`txid:vout`) a split or transfer is broadcasting.
//! Only the spend that reserved a coin releases it; the user's Freeze and
//! Unfreeze never touch either map. Public freezes live in the BDK wallet DB.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use bdk_wallet::bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

use crate::error::WalletError;

pub const MWEB_FROZEN_FILE: &str = "mweb_frozen.json";

pub const RESERVED_MESSAGE: &str = "A send is already using this coin.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MwebFrozenFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reserved: BTreeMap<String, Reservation>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub public_reserved: BTreeMap<String, Reservation>,
}

/// A hold taken by one process. A different `session` means that process is gone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    pub session: String,
    pub since_unix: u64,
}

fn default_version() -> u32 {
    1
}

pub fn frozen_path(data_dir: &Path) -> PathBuf {
    data_dir.join(MWEB_FROZEN_FILE)
}

pub fn is_output_id_hex(raw: &str) -> bool {
    let s = raw.trim();
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn normalize_output_id(raw: &str) -> Result<String, WalletError> {
    let s = raw.trim().to_ascii_lowercase();
    if !is_output_id_hex(&s) {
        return Err(WalletError::Meta(
            "MWEB output id must be 32-byte hex (64 characters)".into(),
        ));
    }
    Ok(s)
}

pub fn read_ids(data_dir: &Path) -> Result<MwebFrozenFile, WalletError> {
    let path = frozen_path(data_dir);
    if !path.is_file() {
        return Ok(MwebFrozenFile {
            version: 1,
            ..Default::default()
        });
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_ids(data_dir: &Path, file: &MwebFrozenFile) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    if file.ids.is_empty() && file.reserved.is_empty() && file.public_reserved.is_empty() {
        match fs::remove_file(frozen_path(data_dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        }
    } else {
        let json =
            serde_json::to_string_pretty(file).map_err(|e| WalletError::Meta(e.to_string()))?;
        fs::write(frozen_path(data_dir), json)?;
        Ok(())
    }
}

/// Serializes read-modify-write of the file. A spend releases its hold without
/// the wallet mutex, so a Freeze click could otherwise overwrite the release.
static EDIT: Mutex<()> = Mutex::new(());

/// Apply `f` and write the file when it returns true.
fn edit(
    data_dir: &Path,
    f: impl FnOnce(&mut MwebFrozenFile) -> Result<bool, WalletError>,
) -> Result<(), WalletError> {
    let _edit = EDIT.lock().unwrap_or_else(|e| e.into_inner());
    let mut file = read_ids(data_dir)?;
    if f(&mut file)? {
        write_ids(data_dir, &file)?;
    }
    Ok(())
}

pub fn set_locked(data_dir: &Path, output_id: &str, locked: bool) -> Result<(), WalletError> {
    let id = normalize_output_id(output_id)?;
    edit(data_dir, |file| {
        if locked {
            file.ids.insert(id);
        } else {
            file.ids.remove(&id);
        }
        Ok(true)
    })
}

/// Add user freezes, skipping malformed ids. Returns how many were new.
pub fn add_ids(data_dir: &Path, output_ids: &[String]) -> Result<usize, WalletError> {
    let mut added = 0usize;
    edit(data_dir, |file| {
        for id in output_ids {
            if let Ok(id) = normalize_output_id(id) {
                if file.ids.insert(id) {
                    added += 1;
                }
            }
        }
        Ok(added > 0)
    })?;
    Ok(added)
}

/// Hold `output_ids` for a spend in flight. Refuses, writing nothing, if any is
/// frozen or already reserved.
pub fn reserve(data_dir: &Path, output_ids: &[String], session: &str) -> Result<(), WalletError> {
    let ids = output_ids
        .iter()
        .map(|id| normalize_output_id(id))
        .collect::<Result<Vec<_>, _>>()?;
    edit(data_dir, |file| {
        for id in &ids {
            if file.reserved.contains_key(id) {
                return Err(WalletError::Mweb(RESERVED_MESSAGE.into()));
            }
            if file.ids.contains(id) {
                return Err(WalletError::Mweb(
                    "selected private coin is frozen — unfreeze it first".into(),
                ));
            }
        }
        let since_unix = crate::mweb_history::now_ts();
        for id in ids {
            file.reserved.insert(
                id,
                Reservation {
                    session: session.to_string(),
                    since_unix,
                },
            );
        }
        Ok(true)
    })
}

pub fn release(data_dir: &Path, output_ids: &[String]) -> Result<(), WalletError> {
    edit(data_dir, |file| {
        let before = file.reserved.len();
        for id in output_ids {
            if let Ok(id) = normalize_output_id(id) {
                file.reserved.remove(&id);
            }
        }
        Ok(file.reserved.len() != before)
    })
}

/// Hold public `outpoints` for a split or transfer in flight. Refuses, writing
/// nothing, if any is already reserved. The caller checks the user's freeze,
/// which lives in the BDK wallet.
pub fn reserve_public(
    data_dir: &Path,
    outpoints: &[OutPoint],
    session: &str,
) -> Result<(), WalletError> {
    edit(data_dir, |file| {
        if outpoints
            .iter()
            .any(|op| file.public_reserved.contains_key(&op.to_string()))
        {
            return Err(WalletError::BuildTx(RESERVED_MESSAGE.into()));
        }
        let since_unix = crate::mweb_history::now_ts();
        for op in outpoints {
            file.public_reserved.insert(
                op.to_string(),
                Reservation {
                    session: session.to_string(),
                    since_unix,
                },
            );
        }
        Ok(true)
    })
}

pub fn release_public(data_dir: &Path, outpoints: &[OutPoint]) -> Result<(), WalletError> {
    edit(data_dir, |file| {
        let before = file.public_reserved.len();
        for op in outpoints {
            file.public_reserved.remove(&op.to_string());
        }
        Ok(file.public_reserved.len() != before)
    })
}

/// Public coins held by a split or transfer in flight.
pub fn public_reserved_outpoints(data_dir: &Path) -> Result<BTreeSet<OutPoint>, WalletError> {
    Ok(read_ids(data_dir)?
        .public_reserved
        .keys()
        .filter_map(|k| OutPoint::from_str(k).ok())
        .collect())
}

/// Drop holds left by an earlier process, which can no longer be broadcasting.
pub fn clear_stale(data_dir: &Path, session: &str) -> Result<(), WalletError> {
    edit(data_dir, |file| {
        let before = file.reserved.len() + file.public_reserved.len();
        file.reserved.retain(|_, r| r.session == session);
        file.public_reserved.retain(|_, r| r.session == session);
        Ok(file.reserved.len() + file.public_reserved.len() != before)
    })
}

/// Coins no spend may select: the user's freezes and the holds of spends in flight.
pub fn unavailable_ids(data_dir: &Path) -> Result<BTreeSet<String>, WalletError> {
    let file = read_ids(data_dir)?;
    let mut ids = file.ids;
    ids.extend(file.reserved.into_keys());
    Ok(ids)
}

#[allow(dead_code)]
pub fn contains(data_dir: &Path, output_id: &str) -> bool {
    let Ok(id) = normalize_output_id(output_id) else {
        return false;
    };
    read_ids(data_dir)
        .map(|f| f.ids.contains(&id))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        let id = "ab".repeat(32);
        set_locked(dir.path(), &id, true).unwrap();
        assert!(contains(dir.path(), &id));
        assert!(contains(dir.path(), &id.to_uppercase()));
        set_locked(dir.path(), &id, false).unwrap();
        assert!(!contains(dir.path(), &id));
        assert!(!frozen_path(dir.path()).is_file());
    }

    #[test]
    fn reserve_refuses_frozen_and_reserved_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        set_locked(dir.path(), &b, true).unwrap();
        reserve(dir.path(), std::slice::from_ref(&a), "s1").unwrap();

        let err = reserve(dir.path(), &[c.clone(), a.clone()], "s1").unwrap_err();
        assert!(err.to_string().contains(RESERVED_MESSAGE), "{err}");
        let err = reserve(dir.path(), &[c.clone(), b.clone()], "s1").unwrap_err();
        assert!(err.to_string().contains("frozen"), "{err}");

        let file = read_ids(dir.path()).unwrap();
        assert_eq!(
            file.reserved.keys().cloned().collect::<Vec<_>>(),
            vec![a.clone()]
        );
        assert_eq!(unavailable_ids(dir.path()).unwrap(), BTreeSet::from([a, b]));
    }

    #[test]
    fn release_and_stale_clear_leave_user_freezes() {
        let dir = tempdir().unwrap();
        let frozen = "aa".repeat(32);
        let live = "bb".repeat(32);
        let stale = "cc".repeat(32);
        set_locked(dir.path(), &frozen, true).unwrap();
        reserve(dir.path(), std::slice::from_ref(&live), "now").unwrap();
        reserve(dir.path(), std::slice::from_ref(&stale), "crashed").unwrap();

        clear_stale(dir.path(), "now").unwrap();
        let file = read_ids(dir.path()).unwrap();
        assert!(file.reserved.contains_key(&live));
        assert!(!file.reserved.contains_key(&stale));

        release(dir.path(), &[live]).unwrap();
        let file = read_ids(dir.path()).unwrap();
        assert!(file.reserved.is_empty());
        assert_eq!(file.ids, BTreeSet::from([frozen.clone()]));

        set_locked(dir.path(), &frozen, false).unwrap();
        assert!(!frozen_path(dir.path()).is_file());
    }

    fn op(n: u8) -> OutPoint {
        OutPoint::from_str(&format!("{}:{n}", "ab".repeat(32))).unwrap()
    }

    #[test]
    fn public_reserve_refuses_reserved_and_writes_nothing() {
        let dir = tempdir().unwrap();
        reserve_public(dir.path(), &[op(0)], "s1").unwrap();

        let err = reserve_public(dir.path(), &[op(1), op(0)], "s1").unwrap_err();
        assert!(err.to_string().contains(RESERVED_MESSAGE), "{err}");
        assert_eq!(
            public_reserved_outpoints(dir.path()).unwrap(),
            BTreeSet::from([op(0)])
        );
    }

    #[test]
    fn public_release_and_stale_clear_leave_user_freezes() {
        let dir = tempdir().unwrap();
        let frozen = "aa".repeat(32);
        set_locked(dir.path(), &frozen, true).unwrap();
        reserve(dir.path(), &["bb".repeat(32)], "now").unwrap();
        reserve_public(dir.path(), &[op(0)], "now").unwrap();
        reserve_public(dir.path(), &[op(1)], "crashed").unwrap();

        clear_stale(dir.path(), "now").unwrap();
        assert_eq!(
            public_reserved_outpoints(dir.path()).unwrap(),
            BTreeSet::from([op(0)])
        );

        release_public(dir.path(), &[op(0)]).unwrap();
        let file = read_ids(dir.path()).unwrap();
        assert!(file.public_reserved.is_empty());
        assert_eq!(file.reserved.len(), 1, "private holds stay");
        assert_eq!(file.ids, BTreeSet::from([frozen.clone()]));

        release(dir.path(), &["bb".repeat(32)]).unwrap();
        set_locked(dir.path(), &frozen, false).unwrap();
        assert!(!frozen_path(dir.path()).is_file());
    }

    #[test]
    fn only_public_hold_keeps_the_file() {
        let dir = tempdir().unwrap();
        reserve_public(dir.path(), &[op(0)], "s1").unwrap();
        assert!(frozen_path(dir.path()).is_file());
        release_public(dir.path(), &[op(0)]).unwrap();
        assert!(!frozen_path(dir.path()).is_file());
    }

    #[test]
    fn add_ids_keeps_holds_and_counts_new() {
        let dir = tempdir().unwrap();
        let a = "aa".repeat(32);
        set_locked(dir.path(), &a, true).unwrap();
        reserve_public(dir.path(), &[op(0)], "s1").unwrap();

        let added = add_ids(dir.path(), &[a.clone(), "cc".repeat(32), "bad".into()]).unwrap();
        assert_eq!(added, 1);
        let file = read_ids(dir.path()).unwrap();
        assert_eq!(file.ids.len(), 2);
        assert_eq!(file.public_reserved.len(), 1);
    }

    #[test]
    fn old_file_without_reserved_loads() {
        let dir = tempdir().unwrap();
        let id = "ab".repeat(32);
        fs::write(
            frozen_path(dir.path()),
            format!(r#"{{"version":1,"ids":["{id}"]}}"#),
        )
        .unwrap();
        let file = read_ids(dir.path()).unwrap();
        assert!(file.ids.contains(&id));
        assert!(file.reserved.is_empty());
        assert!(file.public_reserved.is_empty());
    }

    #[test]
    fn rejects_bad_id() {
        let dir = tempdir().unwrap();
        let err = set_locked(dir.path(), "not-hex", true).unwrap_err();
        assert!(err.to_string().contains("32-byte hex"));
    }
}

//! Multi-wallet registry: one seed at the data-dir root, per-account state dirs.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::WalletError;
use crate::meta::{self, WalletMeta};
use crate::{MNEMONIC_ENC_FILE, MNEMONIC_FILE};

pub const ACCOUNTS_FILE: &str = "accounts.json";
pub const ACCOUNTS_DIR: &str = "accounts";

/// Default display name for BIP84 account 0 after create/restore/migration.
pub const DEFAULT_ACCOUNT_0_NAME: &str = "Personal";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountEntry {
    pub index: u32,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountsRegistry {
    pub active_index: u32,
    pub accounts: Vec<AccountEntry>,
}

impl AccountsRegistry {
    pub fn single(index: u32, name: &str) -> Self {
        Self {
            active_index: index,
            accounts: vec![AccountEntry {
                index,
                name: name.to_string(),
            }],
        }
    }

    pub fn get(&self, index: u32) -> Option<&AccountEntry> {
        self.accounts.iter().find(|a| a.index == index)
    }

    pub fn next_free_index(&self) -> u32 {
        let mut used: Vec<u32> = self.accounts.iter().map(|a| a.index).collect();
        used.sort_unstable();
        let mut n = 0;
        for &u in &used {
            if u == n {
                n += 1;
            } else if u > n {
                break;
            }
        }
        n
    }
}

pub fn accounts_path(root: &Path) -> PathBuf {
    root.join(ACCOUNTS_FILE)
}

pub fn accounts_dir(root: &Path) -> PathBuf {
    root.join(ACCOUNTS_DIR)
}

pub fn account_dir(root: &Path, index: u32) -> PathBuf {
    accounts_dir(root).join(index.to_string())
}

pub fn read_registry(root: &Path) -> Result<AccountsRegistry, WalletError> {
    let path = accounts_path(root);
    let bytes = fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            WalletError::NotFound
        } else {
            WalletError::Io(e)
        }
    })?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_registry(root: &Path, registry: &AccountsRegistry) -> Result<(), WalletError> {
    fs::create_dir_all(root)?;
    let json =
        serde_json::to_string_pretty(registry).map_err(|e| WalletError::Meta(e.to_string()))?;
    fs::write(accounts_path(root), json)?;
    Ok(())
}

/// Flat layout files that move into `accounts/0/` on migration (mnemonic stays at root).
fn flat_state_filenames() -> &'static [&'static str] {
    &[
        meta::WALLET_DB_FILE,
        meta::WALLET_META_FILE,
        meta::MWEB_DB_FILE,
        meta::MWEB_SYNC_FILE,
        meta::MWEB_INDEX_FILE,
        meta::MWEB_HISTORY_FILE,
        meta::MWEB_COINS_ENC_FILE,
        meta::MWEB_SYNC_ENC_FILE,
        meta::MWEB_INDEX_ENC_FILE,
        meta::MWEB_HISTORY_ENC_FILE,
        meta::MWEB_SEAL_COUNTER_FILE,
        meta::TX_LABELS_FILE,
        meta::UTXO_LABELS_FILE,
        meta::SPLIT_IDS_FILE,
        meta::MWEB_FROZEN_FILE,
        meta::CHURN_JOB_FILE,
        meta::CHURN_DEPTH_FILE,
        crate::churn::CHURN_ARMED_FILE,
        meta::CONTACTS_FILE,
        "insights_llm_key.enc",
        "litvm.json",
    ]
}

fn sqlite_sidecars(db_name: &str) -> [String; 2] {
    [format!("{db_name}-wal"), format!("{db_name}-shm")]
}

/// Move legacy flat wallet files into `accounts/0/` and write a registry.
/// No-op when `accounts/` already exists or there is no root `wallet.sqlite`.
pub fn migrate_flat_layout(root: &Path) -> Result<bool, WalletError> {
    let legacy_db = meta::db_path(root);
    let accounts = accounts_dir(root);
    if accounts.is_dir() {
        return Ok(false);
    }
    if !legacy_db.is_file() {
        return Ok(false);
    }

    let dest = account_dir(root, 0);
    fs::create_dir_all(&dest)?;

    for name in flat_state_filenames() {
        let src = root.join(name);
        if src.is_file() {
            let target = dest.join(name);
            fs::rename(&src, &target).map_err(WalletError::Io)?;
        }
    }
    for name in flat_state_filenames() {
        if name.ends_with(".sqlite") {
            for side in sqlite_sidecars(name) {
                let src = root.join(&side);
                if src.is_file() {
                    fs::rename(&src, dest.join(&side)).map_err(WalletError::Io)?;
                }
            }
        }
    }

    // Ensure meta records account 0.
    if meta::meta_path(&dest).is_file() {
        let mut m = meta::read_meta(&dest)?;
        m.account_index = 0;
        meta::write_meta(&dest, &m)?;
    }

    write_registry(root, &AccountsRegistry::single(0, DEFAULT_ACCOUNT_0_NAME))?;
    Ok(true)
}

/// Ensure registry + active account dir exist after migration. Creates a default
/// registry pointing at 0 when `accounts/0` already has a DB but registry is missing.
pub fn ensure_layout(root: &Path) -> Result<(), WalletError> {
    migrate_flat_layout(root)?;
    if accounts_path(root).is_file() {
        return Ok(());
    }
    let zero = account_dir(root, 0);
    if meta::db_path(&zero).is_file() {
        write_registry(root, &AccountsRegistry::single(0, DEFAULT_ACCOUNT_0_NAME))?;
    }
    Ok(())
}

pub fn active_account_dir(root: &Path) -> Result<PathBuf, WalletError> {
    ensure_layout(root)?;
    let reg = read_registry(root)?;
    Ok(account_dir(root, reg.active_index))
}

/// True when any wallet DB or mnemonic is present (post- or pre-migration).
pub fn wallet_exists(root: &Path) -> bool {
    if root.join(MNEMONIC_ENC_FILE).is_file() || root.join(MNEMONIC_FILE).is_file() {
        return true;
    }
    if meta::db_path(root).is_file() {
        return true;
    }
    let accounts = accounts_dir(root);
    if !accounts.is_dir() {
        return false;
    }
    match fs::read_dir(&accounts) {
        Ok(entries) => entries.filter_map(|e| e.ok()).any(|e| {
            let p = e.path();
            p.is_dir() && meta::wallet_files_exist(&p)
        }),
        Err(_) => false,
    }
}

/// Remove one account directory (sqlite sidecars included via [`meta::remove_wallet_files`]).
pub fn remove_account_dir(root: &Path, index: u32) -> Result<(), WalletError> {
    let dir = account_dir(root, index);
    if dir.is_dir() {
        meta::remove_wallet_files(&dir)?;
        // remove_wallet_files only deletes known files; drop the directory if empty-ish.
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(())
}

/// Wipe every account, the registry, leftover flat state, and (caller's job) the mnemonic.
pub fn remove_all_accounts(root: &Path) -> Result<(), WalletError> {
    // Legacy flat files at root.
    meta::remove_wallet_files(root)?;
    let accounts = accounts_dir(root);
    if accounts.is_dir() {
        let _ = fs::remove_dir_all(&accounts);
    }
    match fs::remove_file(accounts_path(root)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(WalletError::Io(e)),
    }
    Ok(())
}

/// Initialize registry for a fresh create/restore (wallet 0 only).
pub fn init_registry_account0(root: &Path) -> Result<PathBuf, WalletError> {
    let dir = account_dir(root, 0);
    fs::create_dir_all(&dir)?;
    write_registry(root, &AccountsRegistry::single(0, DEFAULT_ACCOUNT_0_NAME))?;
    Ok(dir)
}

/// Copy network/settings defaults when creating a new account from an existing meta.
pub fn meta_for_new_account(template: &WalletMeta, account_index: u32) -> WalletMeta {
    let mut m = template.clone();
    m.account_index = account_index;
    m.needs_full_scan = true;
    m.needs_mweb_scan = true;
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn next_free_index_fills_gaps() {
        let reg = AccountsRegistry {
            active_index: 0,
            accounts: vec![
                AccountEntry {
                    index: 0,
                    name: "A".into(),
                },
                AccountEntry {
                    index: 2,
                    name: "C".into(),
                },
            ],
        };
        assert_eq!(reg.next_free_index(), 1);
    }

    #[test]
    fn migrate_moves_flat_db() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join(meta::WALLET_DB_FILE), b"db").unwrap();
        fs::write(
            root.join(meta::WALLET_META_FILE),
            r#"{"network":"testnet","electrum_url":"ssl://x:1"}"#,
        )
        .unwrap();
        assert!(migrate_flat_layout(root).unwrap());
        assert!(!meta::db_path(root).is_file());
        assert!(meta::db_path(&account_dir(root, 0)).is_file());
        let reg = read_registry(root).unwrap();
        assert_eq!(reg.active_index, 0);
        assert_eq!(reg.accounts.len(), 1);
    }
}

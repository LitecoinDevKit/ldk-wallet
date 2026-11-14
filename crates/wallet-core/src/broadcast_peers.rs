//! Public MWEB peers that recently confirmed one of our broadcasts.
//!
//! Tried right after the user's own peers so a broadcast does not wait out a
//! poll deadline on every discovered peer. The file holds addresses only, at
//! most [`MAX_PEERS`] of them: no timestamps, txids or counts, so it says as
//! little as possible about what this wallet sent.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::WalletError;

pub const BROADCAST_PEERS_FILE: &str = "mweb_broadcast_peers.json";

const MAX_PEERS: usize = 3;

/// Serializes read-modify-write: broadcasts run outside the wallet lock.
static WRITE: Mutex<()> = Mutex::new(());

#[derive(Debug, Default, Serialize, Deserialize)]
struct PeersFile {
    #[serde(default)]
    peers: Vec<String>,
}

/// What one broadcast learned about the peers it tried.
#[derive(Debug, Default)]
pub struct Outcome<'a> {
    pub confirmed: Option<SocketAddr>,
    pub failed: &'a [SocketAddr],
    /// The user's own `mweb_peers`, which Settings already stores.
    pub configured: &'a [SocketAddr],
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(BROADCAST_PEERS_FILE)
}

/// Remembered peers, best first. Missing or corrupt files read as empty.
pub fn load(data_dir: &Path) -> Vec<SocketAddr> {
    let Ok(text) = fs::read_to_string(path(data_dir)) else {
        return Vec::new();
    };
    let file: PeersFile = serde_json::from_str(&text).unwrap_or_default();
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in file.peers.iter().filter_map(|s| s.parse().ok()) {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out.truncate(MAX_PEERS);
    out
}

/// Move a confirming peer to the front and forget peers that failed.
/// A bare `Sent` is not evidence either way, so it changes nothing.
pub fn record(data_dir: &Path, outcome: &Outcome<'_>) -> Result<(), WalletError> {
    let _guard = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let before = load(data_dir);
    let mut peers = before.clone();
    peers.retain(|addr| !outcome.failed.contains(addr) && !outcome.configured.contains(addr));
    if let Some(addr) = outcome.confirmed {
        if !outcome.configured.contains(&addr) {
            peers.retain(|a| *a != addr);
            peers.insert(0, addr);
        }
    }
    peers.truncate(MAX_PEERS);
    if peers == before {
        return Ok(());
    }
    write(data_dir, &peers)
}

fn write(data_dir: &Path, peers: &[SocketAddr]) -> Result<(), WalletError> {
    if peers.is_empty() {
        return match fs::remove_file(path(data_dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        };
    }
    fs::create_dir_all(data_dir)?;
    let file = PeersFile {
        peers: peers.iter().map(SocketAddr::to_string).collect(),
    };
    let json = serde_json::to_string(&file).map_err(|e| WalletError::Meta(e.to_string()))?;
    let tmp = data_dir.join(format!("{BROADCAST_PEERS_FILE}.tmp"));
    fs::write(&tmp, json)?;
    fs::rename(&tmp, path(data_dir))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 9333))
    }

    fn confirm(dir: &Path, a: SocketAddr) {
        record(
            dir,
            &Outcome {
                confirmed: Some(a),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn round_trips_newest_first_and_caps_at_three() {
        let dir = tempdir().unwrap();
        for n in 1..=4 {
            confirm(dir.path(), addr(n));
        }
        assert_eq!(load(dir.path()), vec![addr(4), addr(3), addr(2)]);
        confirm(dir.path(), addr(2));
        assert_eq!(load(dir.path()), vec![addr(2), addr(4), addr(3)]);
    }

    #[test]
    fn file_holds_addresses_only() {
        let dir = tempdir().unwrap();
        confirm(dir.path(), addr(1));
        let text = fs::read_to_string(path(dir.path())).unwrap();
        assert_eq!(text, r#"{"peers":["10.0.0.1:9333"]}"#);
    }

    #[test]
    fn failure_forgets_a_peer_and_sent_changes_nothing() {
        let dir = tempdir().unwrap();
        confirm(dir.path(), addr(1));
        confirm(dir.path(), addr(2));
        // Only Sent answers: no confirmed peer, no failures.
        record(dir.path(), &Outcome::default()).unwrap();
        assert_eq!(load(dir.path()), vec![addr(2), addr(1)]);
        record(
            dir.path(),
            &Outcome {
                failed: &[addr(2)],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(load(dir.path()), vec![addr(1)]);
        record(
            dir.path(),
            &Outcome {
                failed: &[addr(1)],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(load(dir.path()).is_empty());
        assert!(!path(dir.path()).exists());
    }

    #[test]
    fn configured_peers_are_never_written() {
        let dir = tempdir().unwrap();
        record(
            dir.path(),
            &Outcome {
                confirmed: Some(addr(7)),
                configured: &[addr(7)],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(load(dir.path()).is_empty());
        assert!(!path(dir.path()).exists());
    }

    #[test]
    fn corrupt_file_reads_as_empty_and_is_replaced() {
        let dir = tempdir().unwrap();
        fs::write(path(dir.path()), "not json").unwrap();
        assert!(load(dir.path()).is_empty());
        confirm(dir.path(), addr(1));
        assert_eq!(load(dir.path()), vec![addr(1)]);
    }
}

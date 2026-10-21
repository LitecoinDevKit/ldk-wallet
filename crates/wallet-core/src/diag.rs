//! In-memory diagnostic log (no secrets). Shared by the GUI export and stderr.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 200;

static LOG: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append a line to the ring buffer and mirror to stderr.
pub fn log(message: impl AsRef<str>) {
    let message = message.as_ref();
    eprintln!("{message}");
    let line = format!("{} {message}", now_secs());
    if let Ok(mut q) = LOG.lock() {
        if q.len() >= CAPACITY {
            q.pop_front();
        }
        q.push_back(line);
    }
}

/// Snapshot of recent diagnostic lines (oldest first).
pub fn snapshot() -> Vec<String> {
    LOG.lock()
        .map(|q| q.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_recent_lines() {
        // Don't clear the global — just push and ensure snapshot is non-empty after log.
        log("diag-test-line");
        let snap = snapshot();
        assert!(snap.iter().any(|l| l.contains("diag-test-line")));
    }
}

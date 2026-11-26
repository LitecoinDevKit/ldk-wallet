//! In-memory diagnostic log (no secrets). Shared by the GUI export and stderr.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 200;

/// Lines with their sequence number. Numbers start at 1 and never repeat, so a
/// reader can ask for everything after the last number it saw.
struct Ring {
    #[cfg(not(test))]
    lines: VecDeque<(u64, String)>,
    #[cfg(test)]
    lines: VecDeque<(u64, std::thread::ThreadId, String)>,
    last_seq: u64,
}

static LOG: Mutex<Ring> = Mutex::new(Ring {
    lines: VecDeque::new(),
    last_seq: 0,
});

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append a line to the ring buffer and mirror to stderr.
///
/// Every message passes through [`crate::redact::scrub_log_line`] before
/// hitting stderr or the ring buffer so mnemonics, private keys, URL
/// credentials, and raw transaction hex never leak into logs or exported
/// diagnostics bundles.
pub fn log(message: impl AsRef<str>) {
    let scrubbed = crate::redact::scrub_log_line(message.as_ref());
    eprintln!("{scrubbed}");
    let line = format!("{} {scrubbed}", now_secs());
    if let Ok(mut ring) = LOG.lock() {
        #[cfg(not(test))]
        {
            if ring.lines.len() >= CAPACITY {
                ring.lines.pop_front();
            }
            ring.last_seq += 1;
            let seq = ring.last_seq;
            ring.lines.push_back((seq, line));
        }
        #[cfg(test)]
        {
            let tid = std::thread::current().id();
            let thread_count = ring.lines.iter().filter(|(_, t, _)| *t == tid).count();
            if thread_count >= CAPACITY {
                if let Some(pos) = ring.lines.iter().position(|(_, t, _)| *t == tid) {
                    ring.lines.remove(pos);
                }
            }
            ring.last_seq += 1;
            let seq = ring.last_seq;
            ring.lines.push_back((seq, tid, line));
        }
    }
}

/// Snapshot of recent diagnostic lines (oldest first).
pub fn snapshot() -> Vec<String> {
    LOG.lock()
        .map(|ring| {
            #[cfg(not(test))]
            {
                ring.lines.iter().map(|(_, l)| l.clone()).collect()
            }
            #[cfg(test)]
            {
                ring.lines.iter().map(|(_, _, l)| l.clone()).collect()
            }
        })
        .unwrap_or_default()
}

/// Lines logged after `seq` that are still in the ring (oldest first), and the
/// newest sequence number to pass next time. `since(0)` returns everything kept.
pub fn since(seq: u64) -> (u64, Vec<String>) {
    LOG.lock()
        .map(|ring| {
            #[cfg(not(test))]
            let lines = ring
                .lines
                .iter()
                .filter(|(s, _)| *s > seq)
                .map(|(_, l)| l.clone())
                .collect();
            #[cfg(test)]
            let lines = ring
                .lines
                .iter()
                .filter(|(s, _, _)| *s > seq)
                .map(|(_, _, l)| l.clone())
                .collect();
            (ring.last_seq, lines)
        })
        .unwrap_or((seq, Vec::new()))
}

/// [`since`], limited to lines this thread logged.
///
/// Sync tests run in parallel and share the ring. A wall-clock check has to
/// read its own probe line, not another test's.
#[cfg(test)]
pub fn since_current_thread(seq: u64) -> (u64, Vec<String>) {
    let tid = std::thread::current().id();
    LOG.lock()
        .map(|ring| {
            let lines = ring
                .lines
                .iter()
                .filter(|(s, t, _)| *s > seq && *t == tid)
                .map(|(_, _, l)| l.clone())
                .collect();
            (ring.last_seq, lines)
        })
        .unwrap_or((seq, Vec::new()))
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

    /// Tailing past the capacity returns each kept line once, in order. Other
    /// tests log concurrently, so only this test's own lines are checked.
    #[test]
    fn since_tails_without_gaps_or_repeats() {
        let (start, _) = since(u64::MAX);
        let mut seen = Vec::new();
        let mut cursor = start;
        for i in 0..CAPACITY + 50 {
            log(format!("since-test {i}"));
            if i % 7 == 0 {
                let (next, lines) = since(cursor);
                assert!(next >= cursor);
                cursor = next;
                seen.extend(lines.into_iter().filter(|l| l.contains("since-test ")));
            }
        }
        let (_, lines) = since(cursor);
        seen.extend(lines.into_iter().filter(|l| l.contains("since-test ")));

        let numbers: Vec<usize> = seen
            .iter()
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        assert_eq!(numbers, (0..CAPACITY + 50).collect::<Vec<_>>());
    }

    #[test]
    fn log_scrubs_secrets_and_keeps_txid_identifiers() {
        let (cursor, _) = since(u64::MAX);
        let txid = "aa".repeat(32);
        let raw_mweb = "02000000".to_string() + &"ef".repeat(80);
        log(format!(
            "diag-redact-check txid={txid} rpc=http://bob:pw123@127.0.0.1:9332 raw={raw_mweb} phrase=\"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\""
        ));
        let (_, lines) = since(cursor);
        let mine: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains("diag-redact-check"))
            .collect();
        assert_eq!(mine.len(), 1);
        let entry = mine[0];
        assert!(entry.contains(&txid), "64-char txid must remain: {entry}");
        assert!(
            !entry.contains("pw123") && !entry.contains("bob:"),
            "{entry}"
        );
        assert!(!entry.contains(&raw_mweb), "{entry}");
        assert!(!entry.contains("abandon"), "{entry}");
    }
}

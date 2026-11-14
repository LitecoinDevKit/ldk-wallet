//! In-memory diagnostic log (no secrets). Shared by the GUI export and stderr.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 200;

/// Lines with their sequence number. Numbers start at 1 and never repeat, so a
/// reader can ask for everything after the last number it saw.
struct Ring {
    lines: VecDeque<(u64, String)>,
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
pub fn log(message: impl AsRef<str>) {
    let message = message.as_ref();
    eprintln!("{message}");
    let line = format!("{} {message}", now_secs());
    if let Ok(mut ring) = LOG.lock() {
        if ring.lines.len() >= CAPACITY {
            ring.lines.pop_front();
        }
        ring.last_seq += 1;
        let seq = ring.last_seq;
        ring.lines.push_back((seq, line));
    }
}

/// Snapshot of recent diagnostic lines (oldest first).
pub fn snapshot() -> Vec<String> {
    LOG.lock()
        .map(|ring| ring.lines.iter().map(|(_, l)| l.clone()).collect())
        .unwrap_or_default()
}

/// Lines logged after `seq` that are still in the ring (oldest first), and the
/// newest sequence number to pass next time. `since(0)` returns everything kept.
pub fn since(seq: u64) -> (u64, Vec<String>) {
    LOG.lock()
        .map(|ring| {
            let lines = ring
                .lines
                .iter()
                .filter(|(s, _)| *s > seq)
                .map(|(_, l)| l.clone())
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
}

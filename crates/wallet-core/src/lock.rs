//! The lock lifecycle as a table. The state is not stored; it is read from the
//! secrets lock, `pending_lock`, and whether wallet state is loaded.
//! `app::lock_lifecycle_tests::lock_table_matches_behavior` drives a real
//! `WalletApp` through every row, and `docs/LOCK_LIFECYCLE.md` draws it.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockState {
    /// Mnemonic encrypted, no signer or wallet in memory.
    Locked,
    /// Mnemonic decrypted, wallet not loaded yet.
    UnlockedEmpty,
    /// Signer and wallet in memory.
    Loaded,
    /// Lock pressed while a holder has the state mutex. Mnemonic already wiped.
    LockPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LockEvent {
    Unlock,
    Load,
    /// `lock()` with the state mutex free.
    Lock,
    /// `lock()` while a `StateGuard` is held.
    LockWhileHeld,
    /// The holder calls `StateGuard::check_lock`.
    CheckLock,
    /// The holder releases its `StateGuard` without checking.
    ReleaseGuard,
}

use LockEvent::*;
use LockState::*;

pub(crate) const LOCK_TRANSITIONS: &[(LockState, LockEvent, LockState)] = &[
    (Locked, Unlock, UnlockedEmpty),
    (UnlockedEmpty, Load, Loaded),
    (UnlockedEmpty, Lock, Locked),
    (Loaded, Lock, Locked),
    (Loaded, LockWhileHeld, LockPending),
    (LockPending, CheckLock, Locked),
    (LockPending, ReleaseGuard, Locked),
];

/// Nothing leaves a pending lock except finishing it, and every finished lock
/// is `Locked`.
#[test]
fn every_lock_ends_locked() {
    for (from, event, to) in LOCK_TRANSITIONS {
        if *from == LockPending || matches!(event, Lock | CheckLock | ReleaseGuard) {
            assert_eq!(*to, Locked, "{event:?} from {from:?}");
        }
    }
}

/// Every `(from, event)` key appears at most once, and every `LockState` is
/// reachable from `Locked`.
#[test]
fn lock_table_has_unique_keys_and_every_state_is_reachable() {
    const ALL_STATES: [LockState; 4] = [Locked, UnlockedEmpty, Loaded, LockPending];
    // Fails to compile if a new state is added without updating ALL_STATES.
    for state in ALL_STATES {
        match state {
            Locked | UnlockedEmpty | Loaded | LockPending => {}
        }
    }

    for (i, (from, event, _)) in LOCK_TRANSITIONS.iter().enumerate() {
        assert!(
            !LOCK_TRANSITIONS[i + 1..]
                .iter()
                .any(|(f, e, _)| f == from && e == event),
            "duplicate row for {event:?} from {from:?}"
        );
    }

    let mut reached = vec![Locked];
    let mut cursor = 0;
    while cursor < reached.len() {
        let current = reached[cursor];
        cursor += 1;
        for (from, _, to) in LOCK_TRANSITIONS {
            if *from == current && !reached.contains(to) {
                reached.push(*to);
            }
        }
    }
    for state in ALL_STATES {
        assert!(
            reached.contains(&state),
            "{state:?} is not reachable from Locked"
        );
    }
}

/// The diagram in `docs/LOCK_LIFECYCLE.md` is generated. Refresh it with
/// `UPDATE_DIAGRAMS=1 cargo test -p wallet-core lock_table_matches_docs`.
#[test]
fn lock_table_matches_docs() {
    let diagram = crate::diagram::mermaid((Locked, "app start"), LOCK_TRANSITIONS, &[]);
    crate::diagram::check_doc(
        "docs/LOCK_LIFECYCLE.md",
        "lock-transitions",
        &diagram,
        "UPDATE_DIAGRAMS=1 cargo test -p wallet-core lock_table_matches_docs",
    );
}

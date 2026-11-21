# Hardening checklist

The one living checklist for hardening this wallet, which is an unaudited prototype. Update it in the same PR as the work. Rules for doing the work are in `AGENTS.md`.

## Next up

1. Error-path integration tests (item 5).
2. UI action-flag consistency checks (item 6).

## Status

| # | Task | Priority | Status | PR | Notes |
|---|------|----------|--------|----|-------|
| 1 | Tighten `AGENTS.md` | Planned | Done | [#24](https://github.com/LitecoinDevKit/ldk-wallet/pull/24) | Also adds this file. |
| 2 | `SyncPass` guard for `sync_phase` | Planned | Done | [#25](https://github.com/LitecoinDevKit/ldk-wallet/pull/25) | |
| 3 | Property tests on transition tables | High | Done | [#26](https://github.com/LitecoinDevKit/ldk-wallet/pull/26), [#27](https://github.com/LitecoinDevKit/ldk-wallet/pull/27), [#28](https://github.com/LitecoinDevKit/ldk-wallet/pull/28) | churn (500×30), lock (5×8), UI (500×30). |
| 4 | Coin-status tests | High | Done | [#29](https://github.com/LitecoinDevKit/ldk-wallet/pull/29) | Exhaustive fact combinations, hold vs freeze, and freeze commands that follow the flags. |
| 5 | Error-path integration tests | High | Not started | | #25 adds the first one. |
| 6 | UI action-flag consistency checks | High | Not started | | |
| 7 | Diagram and table checks on every PR | CI | Mostly done | | Confirm and record. |
| 8 | Screenshot regression in CI | CI | Not started | | |
| 9 | `cargo miri` on pure logic | CI | Not started | | |
| 10 | Fuzz or property tests on transitions and parsers | Fuzzing | Not started | | |
| 11 | Chaos tests for lock and failure mid-pass | Fuzzing | Not started | | |
| 12 | `docs/MWEB_E2E.md` as a pre-release gate | Process | Not started | | |
| 13 | Review notes for holds vs freezes and the lock lifecycle | Process | Not started | | |
| 14 | Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current | Process | Ongoing | | Never claim the wallet is audited. |
| 15 | Logging for phase changes, holds and rejections | Observability | Not started | | The reported sync phase is now trustworthy (#25). |

## Already planned

**1. Tighten `AGENTS.md`.** Corrects the terminal-state rule (only churn's `Done` and `Cancelled` are terminal; lock's `Locked` is left by Unlock), removes the repeated churn rules, and adds a common-mistakes list, a checklist for adding a flow with a table, and a list of the flows without a table (peg-in, peg-out and send; sync phase; LitVM).

**2. `SyncPass` guard.** `sync_phase` could stay at a step such as `MwebDownload` after an early `?` return, so the UI kept showing that step. `SyncPass` in `app.rs` becomes the only writer and resets to Idle unless `finish` is called. `set_sync_phase` is removed. Failing test: `failed_resync_leaves_the_sync_phase_idle`. It uses `discovery::go_offline_for_test()` so it needs no network.

## High-value automated checks

**3. Property tests on transition tables.** For `churn::TRANSITIONS`, `lock::LOCK_TRANSITIONS` and `PHASE_FROM` in `ui/src/phases.ts`: every phase and event gives either a legal next phase or a clean rejection, and terminal states have no exits. Uses seeded random walks with no new dependencies (existing `rand` crate in Rust, mulberry32 in Node). If a walk finds a real bug, report it with the failing seed instead of fixing the table or code in the test PR.
- Churn (`churn_random_walks_hold_all_invariants` in `crates/wallet-core/src/churn.rs`): 500 seeds × 30 steps. Replay with `cargo test -p wallet-core churn_random_walks_hold_all_invariants` (or call `walk_churn(seed)` to isolate one seed).
- Lock (`lock_random_walks_match_table_and_cover_all_rows` in `crates/wallet-core/src/app.rs` and `lock_table_has_unique_keys_and_every_state_is_reachable` in `crates/wallet-core/src/lock.rs`): 5 seeds × 8 steps on a real `WalletApp` with an explicit mutex-holder model, covering every row of `LOCK_TRANSITIONS`. Replay with `cargo test -p wallet-core lock_random_walks_match_table_and_cover_all_rows` (or call `walk_lock(&app, dir.path(), seed, start, 8, &mut hits)` to isolate one seed).
- UI (`scripts/phase-table.test.mjs` testing `canEnter` and `PHASE_FROM` in `ui/src/phases.ts`): 500 seeds × 30 steps plus reachability, `fatal` exit, and self-loop checks, run in CI via `npm run test:ui` (or call `walkUi(seed)` to isolate one seed).

**4. Coin-status tests.** `coin_status_holds_for_every_fact_combination` and `public_coin_status_holds_for_every_fact_combination` (in `crates/wallet-core/src/mweb.rs`) walk every fact combination against the documented priority order. Buttons come only from the returned flags: the spend buttons are on exactly when nothing blocks the coin, a hold turns every button off, and a user freeze stays undoable. `user_freeze_and_in_flight_hold_stay_separate` and `public_user_freeze_and_in_flight_hold_stay_separate` keep a user freeze and an in-flight hold on different coins. `listed_rows_carry_exactly_the_status_function_output` checks each listed row equals the status function. `select_flag_matches_spend_resolution` checks private and public spend selection against `select` (an unconfirmed public coin stays selectable). `private_freeze_command_follows_the_flags` and `public_freeze_command_follows_the_flags` make `set_mweb_utxo_locked` and `set_utxo_locked` succeed only when the listed coin's `freeze` or `unfreeze` flag is set.

Those command tests found the mismatch: Freeze was accepted on a pending or maturing private coin, on a coin a self-spend holds, and as a no-op when the coin was already in that state (public coins included). The commands now refuse, with the blocked reason's sentence, unless the flag is set. A coin missing from the listing still follows the old path, so a stale freeze can be cleared. `ChurnPhase::ALL` is the shared phase list.

**5. Error-path integration tests.** Lock races, persist failures, bad peers, foreign spend and early returns. Assert the final phase, holds and coin status. Reuse `app_with_job`, `app_with_foreign_spent_job`, `app_with_private_coins` and `discovery::go_offline_for_test()`; no network.

**6. UI action-flag consistency.** Check that backend flags map to the expected buttons and that `ui/src/main.ts` never infers an action from a phase. The known exception is LitVM's Speed up (see `AGENTS.md`).

## CI and regression

**7. Diagram and table checks on every PR.** `ci.yml` runs on every PR. `transition_table_matches_docs` and `lock_table_matches_docs` run inside `cargo test --workspace --locked`, and `npm run check:diagrams` runs after `npm run build`.

**8. Screenshot regression.** Run `npm run screenshots` in CI for the coins scenes that show status chips and churn cards (`?cover=` values in `ui/src/shots-fixture.ts`).

**9. `cargo miri`.** On the pure state-machine, hold and status logic, where it can run without I/O.

## Fuzzing and chaos

**10. Fuzz or structure-aware property tests** on `churn::transition`, the coin status functions, and pure parsers used by holds and phases.

**11. Chaos tests.** Inject a lock or a failure mid-sync and mid-churn, then check that no phase is stuck and no reserved hold is orphaned.

## Process and audit readiness

**12.** Turn `docs/MWEB_E2E.md` into a repeatable pre-release gate, including how to record the run.

**13.** Review notes for reserved holds vs user freezes and for the lock lifecycle, pointing at the tests that pin them.

**14.** Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current with new findings and residual risks.

## Observability

**15.** Log phase changes, hold take and release, and transition rejections with the job or coin id, from and to, and the reason, so support bundles and post-mortems are useful.

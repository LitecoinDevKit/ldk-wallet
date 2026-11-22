# Hardening checklist

The one living checklist for hardening this wallet, which is an unaudited prototype. Update it in the same PR as the work. Rules for doing the work are in `AGENTS.md`.

## Next up

1. Single-instance directory lock (item 32). A second process runs `clear_stale` and drops the first process's live holds. This is ahead of item 19 for that reason.
2. `churn_armed.json` at rest (item 35). The file is plaintext JSON, mode `0600`, and the locked pump reads `spend_key`, `blind`, `shared_secret`, and `raw_hex` from it. This is ahead of item 19 for that reason.
3. Untrusted input bounds (item 19).
4. Backup and restore round-trips (item 20). Item 20 stays ahead of items 27 and 28 so the frozen depth fixture captures today's `churn_depth.json` before item 28's per-hop ledger. Item 20 needs a second fixture after that ledger lands. Its stale-hold fixture is an old session, not a second live process (item 32).
5. Auto-lock wake race (item 31). It sits after item 20 and before the High fund-safety tail. It does not jump ahead of items 32, 35, or 19.
6. After item 31: SPV checkpoints (item 33), LitVM send invariants (item 34), adversarial MWEB peers (item 27), and cross-layer reorg unwind (item 28). Dropped unconfirmed transparent spends (item 29) follows those. macOS full-disk flush (item 30) stays lower. Core dumps and backup exclusion (item 36) wait for release.

## Status

| # | Task | Priority | Status | PR | Notes |
|---|------|----------|--------|----|-------|
| 1 | Tighten `AGENTS.md` | Planned | Done | [#24](https://github.com/LitecoinDevKit/ldk-wallet/pull/24) | Also adds this file. |
| 2 | `SyncPass` guard for `sync_phase` | Planned | Done | [#25](https://github.com/LitecoinDevKit/ldk-wallet/pull/25) | |
| 3 | Property tests on transition tables | High | Done | [#26](https://github.com/LitecoinDevKit/ldk-wallet/pull/26), [#27](https://github.com/LitecoinDevKit/ldk-wallet/pull/27), [#28](https://github.com/LitecoinDevKit/ldk-wallet/pull/28) | churn (500×30), lock (5×8), UI (500×30). |
| 4 | Coin-status tests | High | Done | [#29](https://github.com/LitecoinDevKit/ldk-wallet/pull/29) | Exhaustive fact combinations, hold vs freeze, and freeze commands that follow the flags. |
| 5 | Error-path integration tests | High | Done | [#30](https://github.com/LitecoinDevKit/ldk-wallet/pull/30) | Offline lock races, persist failures, bad peers, foreign spend, and rejected commands. Three state-cleanup bugs fixed. |
| 6 | UI action-flag consistency checks | High | Done | [#31](https://github.com/LitecoinDevKit/ldk-wallet/pull/31) | Pure flag-to-button mapping in `ui/src/actions.ts` and static checks in `scripts/action-flags.test.mjs`. |
| 7 | Diagram and table checks on every PR | CI | Done | [#35](https://github.com/LitecoinDevKit/ldk-wallet/pull/35) | Churn and lock diagram tests run in both Rust jobs; the frontend job checks the UI diagram and the phase table. |
| 8 | Screenshot regression in CI | CI | Not started | | |
| 9 | `cargo miri` on pure logic | CI | Not started | | |
| 10 | Fuzz or property tests on transitions and parsers | Fuzzing | Not started | | Coverage-guided targets on the state machines and the hold and phase parsers. Parser bounds are item 19. |
| 11 | Chaos tests for lock and failure mid-pass | Fuzzing | Not started | | |
| 12 | `docs/MWEB_E2E.md` as a pre-release gate | Process | Not started | | |
| 13 | Review notes for holds vs freezes and the lock lifecycle | Process | Not started | | |
| 14 | Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current | Process | Ongoing | | Through PR #38. Records the auto-lock wake race (item 31, O15), below-window SPV anchors (item 33, O13), and plaintext `churn_armed.json` (item 35, O16). Never claim the wallet is audited. |
| 15 | Logging for phase changes, holds and rejections | Observability | Done | [#36](https://github.com/LitecoinDevKit/ldk-wallet/pull/36) | `churn::transition`, `SyncPass`, `WalletApp` lock lifecycle, `mweb_frozen` holds, and freeze/churn command rejections log job/coin IDs, `from`/`to`, and `reason` via `diag::log` (`redact::scrub_log_line`). |
| 16 | Secret hygiene and zeroization | High | Done | [#32](https://github.com/LitecoinDevKit/ldk-wallet/pull/32) | `Zeroizing` and `Drop` across secrets, signers, sealing keys, and armed hops; `redact::scrub_log_line` on `diag::log` and errors; redacted `Debug` and source guard in `secret_hygiene.rs` + `scripts/secret-hygiene.test.mjs`. |
| 17 | Persistence atomicity and crash recovery | High | Done | [#33](https://github.com/LitecoinDevKit/ldk-wallet/pull/33) | Temp-file + `sync_all` + rename across secret, sealed, churn, hold, metadata, sidecar, LitVM, and CLI writers; v2 seal-counter enforcement and fail-closed `MwebRuntime::open`; `db.restore_spent` fix on recalled coins; `reconcile_churn_on_load` and reorg/resync recovery pinned by `crash_recovery_tests.rs` and `tests/crash_recovery.rs`. Windows CI already runs these tests; macOS `F_FULLFSYNC` is item 30. |
| 18 | Transaction construction and value invariants | High | Done | [#34](https://github.com/LitecoinDevKit/ldk-wallet/pull/34) | `tx_invariants.rs` (`MAX_MONEY` checked math, `LitecoinDustCoinSelection` at 30 sat/vB, public/MWEB recipient script guards, coin-ID deduplication, post-build shape/conservation verifiers); direct peg-in PSBT construction without temporary `lock_outpoint`; post-sign index persistence; LitVM replacement target verifier; `ui/src/amounts.ts` + `scripts/amounts.test.mjs`; MWEB commitment/stealth/bulletproof/rewind verifier and seeded property tests. |
| 19 | Untrusted input bounds | Medium | Not started | | Size, whole-call deadline, and structure limits on Electrum, MWEB peers, LitVM HTTP, and local JSON. Argon2 parameters come from the version magic, not the file. Refines item 10. Merkle and header validity are item 25. |
| 20 | Backup and restore round-trips | Medium | Not started | | Seed-only restores gap and scan keys and resets freezes, labels, and depth. Seed plus metadata restores the spendable set. v1 seal opens without a v2 counter and fails closed with one. A restored stale hold sweeps on load and keeps user freezes (ids). Frozen `churn_depth.json` before item 28, and again after. |
| 21 | Static analysis expansion | Medium | Not started | | Unsafe surface, and optionally mutation testing of the tables. CI pins the Tauri CSP, `capabilities/default.json`, and rejection of locked or out-of-phase commands. |
| 22 | Error-message sanitization | Lower | Not started | | UI and logs omit stack traces and extra address or amount detail. |
| 23 | Lookalike addresses and confirmations | Lower | Not started | | Beyond the existing wipe phrase. Also confirm or refuse when `estimatefee`, already clamped to `1..=100,000` sat/vB, makes the total fee or the fee-to-amount ratio cross a stated threshold. |
| 24 | Release SBOM | Lower | Not started | | On top of the supply-chain CI already in place. |
| 25 | SPV acceptance of Electrum data | High | Done | [#37](https://github.com/LitecoinDevKit/ldk-wallet/pull/37) | `spv.rs` verifies scrypt proof-of-work, targets and retargets, header links, and fork work, plus hardened merkle proofs and raw-tx txids, before an Electrum update is applied. Mock-server tests in `app/tests/spv_tests.rs`. `cross_check_tip` stays a warning. |
| 26 | Peg-out maturity on public coins | High | Done | [#38](https://github.com/LitecoinDevKit/ldk-wallet/pull/38) | `public_coin_status` and `collect_unspent` enforce `CanonicalTxOut::is_mature` (6 confirmations on HogEx peg-outs, 100 on coinbase), marking immature coins `Maturing` with `maturity_blocks_left` and blocking spend/split/transfer/peg-in/freeze while keeping ordinary unconfirmed public coins selectable. |
| 27 | Adversarial MWEB peer | High | Not started | | Local monotonicity rejects a shrinking `output_mmr_size` unless `disconnect_from` ran. Second-peer disagreement sets `cross_check_warning` and a stale balance and does not block spends or churn. HogEx anchors to the SPV checkpoint. LIP-0006 stays in `bdk_mweb`. |
| 28 | Cross-layer reorg unwind | High | Not started | | A mempool peg-in keeps the public input spent; an invalidated peg-in releases it. A reorged peg-out leaves the private input an unconfirmed spend. Per-hop ledger unwinds depth, clears ``last_other_*``, and reconciles the job. Stage, then rename. Does not close O12. |
| 29 | Dropped unconfirmed transparent spends | Medium | Not started | | Release on own-node absence, or an SPV-verified conflict, or 48h and ~1,152 blocks since `broadcast_height` with the Electrum server omitting it. Peg-ins and ordinary public spends store that height. Own-node absence is not required for the timeout. RBF is out of scope. |
| 30 | macOS full-disk flush | Lower | Not started | | The same `F_FULLFSYNC` helper on `write_atomic` and `write_atomic_0600`, file and parent. A failed parent flush fails the write. `#[cfg(unix)]` / `#[cfg(target_os = "macos")]`. Same parent flush in LitVM settings and the CLI env writer. No new CI job. |
| 31 | Auto-lock wake race | High | Not started | | Activity and focus handlers test the idle deadline before refreshing `lastActivityTs`. `WalletApp` enforces the same deadline. Background polls do not refresh it. Sits after item 20. Item 16 stays zeroization. |
| 32 | Single-instance directory lock | High | Not started | | `flock` or a lockfile so the app and `wallet-cli` cannot open one directory together. A second process must not run `clear_stale` against a live hold. |
| 33 | SPV checkpoints and work floor | High | Not started | | O13. A fresh or far-behind wallet does not accept an invented chain on PoW and `powLimit` alone. Anchors below the 2016 window need more than an isolated header. |
| 34 | LitVM send and RPC invariants | High | Not started | | Re-check `eth_chainId` inside send, not only in `probe`. A normal send refuses non-empty calldata. Existing gas, max-fee, and 0.05 zkLTC total-fee caps stay. |
| 35 | `churn_armed.json` at rest | High | Not started | | Plaintext `0600` JSON holds `raw_hex` and the created coin's `spend_key`, `blind`, and `shared_secret` so the locked pump can broadcast. Mode `0600` is not encryption. O1 does not cover this file. |
| 36 | Core dumps, backup exclusion, updater | Lower | Not started | | No updater exists. Do this with the release work in item 24, not ahead of items 32–35. |

## Model and effort

How to staff items 6–36. Planning is Cursor chat or plan mode. Implementation is agent mode that writes the tests and code.

- **Carbon:** Gemini 4 Carbon, or an equivalent high-reasoning model.
- **Argon:** Gemini 4 Argon, or another strong coding model.
- **Light:** a faster model, including the default Cursor model.

Effort is Low, Medium, or High, relative to the size of the change and the reasoning it needs.

| # | Item | Planning | Implementation | Notes |
|---|------|----------|----------------|-------|
| 6 | UI action-flag consistency | Argon · Low–Medium | Argon · Medium | Map flags to buttons, and a static check that `main.ts` does not infer an action from a phase. A light model covers most of it. |
| 7 | Diagram and table checks | Light · Low | Light · Low | Confirm the existing CI checks and record them. |
| 8 | Screenshot regression in CI | Light · Low | Light · Low–Medium | Wire `npm run screenshots` into CI and cover the fixture scenes. |
| 9 | `cargo miri` on pure logic | Argon · Low | Argon · Low–Medium | Name the pure modules, add the CI job, and fix whatever Miri reports. |
| 10 | Fuzz and structure-aware property tests | Argon · Medium | Argon · Medium–High | Coverage-guided targets on the state machines and the hold and phase parsers. Parser bounds and structure-aware parser fuzz are item 19. |
| 11 | Chaos tests (lock or failure mid-pass) | Carbon · Medium | Argon · Medium–High | Planning lists the failure cases. Implementation follows that list. |
| 12 | `MWEB_E2E.md` as a pre-release gate | Light · Low | Light · Low | Process and documentation. |
| 13 | Review notes (holds vs freezes, lock lifecycle) | Argon · Low–Medium | Light · Low | Write the notes and link the tests that already pin the behavior. |
| 14 | Keep `AUDIT_NOTES.md` and `SECURITY.md` current | Light · Low | Light · Low | Ongoing documentation. |
| 15 | Logging for phase, holds, and rejections | Argon · Low–Medium | Argon · Medium | Follows once the redaction rules in item 16 are set. |
| 16 | Secret hygiene and zeroization | Carbon · Medium | Argon · Medium–High | Enumerate every lock, wipe, error path, and buffer. Implementation is tests plus careful `zeroize` use. |
| 17 | Persistence atomicity and crash recovery | Carbon · Medium–High | Argon · High | Plan the kill points and the residual risk, then test kill, restart, and consistency. |
| 18 | Transaction construction and value invariants | Carbon · Medium | Argon · Medium–High | Checked arithmetic, dust, change, and peg-in/peg-out shape. Carbon finds the edge cases; Argon writes the property tests. |
| 19 | Untrusted input bounds | Carbon · Medium | Argon · Medium | Size, whole-call deadline, and structure limits, plus structure-aware fuzz of those parsers. LitVM HTTP, local JSON size and nesting, and Electrum notification spam are named cases. Argon2 cost comes from the version magic. Merkle proofs are item 25. |
| 20 | Backup and restore round-trips | Argon · Medium | Argon · Medium–High | Seed-only versus seed plus metadata, one frozen file per generation, both v1 seal cases, and a stale-hold sweep that keeps user freezes (ids). |
| 21 | Static analysis expansion | Light–Argon · Low | Light · Low–Medium | `cargo-geiger` and optional mutants. CI pins the Tauri CSP, capabilities, and locked or out-of-phase command rejection. |
| 22 | Error-message sanitization | Light · Low | Light · Low–Medium | Redaction rules and a few tests. |
| 23 | Lookalike addresses and confirmations | Argon · Low–Medium | Argon · Medium | UI warnings, extra confirmation flows, and a threshold on total fee and fee-to-amount ratio above the `100,000` sat/vB clamp. |
| 24 | Release SBOM | Light · Low | Light · Low | On top of the supply-chain CI already in place. |
| 25 | SPV acceptance of Electrum data | Carbon · Medium | Argon · Medium–High | Plan the proof and header cases. Implementation is failing tests, then a verifier that rejects them before a coin is confirmed. |
| 26 | Peg-out maturity on public coins | Argon · Low–Medium | Argon · Medium | Failing test first. Status flags gain maturing. The 6-block boundary is the off-by-one to get right. |
| 27 | Adversarial MWEB peer | Carbon · Medium | Argon · Medium–High | Separate local MMR monotonicity from the second-peer warning. The warning does not block spends or churn. HogEx anchors to the SPV checkpoint. LIP-0006 stays in `bdk_mweb`. |
| 28 | Cross-layer reorg unwind | Carbon · Medium–High | Argon · High | Failing tests first for a mempool peg-in, an invalidated peg-in, a reorged peg-out, and a scored hop. Per-hop ledger, rescore, and job reconcile. Stage, then rename. |
| 29 | Dropped unconfirmed transparent spends | Carbon · Medium | Argon · Medium–High | Three release triggers: own-node absence, an SPV-verified conflict, or 48h and ~1,152 blocks with the Electrum server omitting it. RBF is out of scope. |
| 30 | macOS full-disk flush | Light · Low | Argon · Low–Medium | One `F_FULLFSYNC` helper for `write_atomic` and `write_atomic_0600`, file and parent. Parent flush failure fails the write. Keep the unix and macOS cfgs. No new CI job. |
| 31 | Auto-lock wake race | Argon · Low–Medium | Argon · Medium | Check the deadline before refreshing activity. `WalletApp` enforces the same deadline, and background polls do not refresh it. |
| 32 | Single-instance directory lock | Carbon · Medium | Argon · Medium | Fail closed before `clear_stale` when another live process holds the directory. A crash must still sweep a dead session. |
| 33 | SPV checkpoints and work floor | Carbon · Medium | Argon · Medium–High | O13. Checkpoints or a work floor for the first header in the window, and for anchors below it. |
| 34 | LitVM send and RPC invariants | Argon · Medium | Argon · Medium | Re-check chain id before signing. Empty calldata on a normal send. Keep the existing fee and gas caps. |
| 35 | `churn_armed.json` at rest | Carbon · Medium | Argon · Medium–High | Spend secrets stay out of plaintext JSON. The locked pump can still broadcast. |
| 36 | Core dumps, backup exclusion, updater | Light · Low | Light · Low | With item 24, when a release is near. No updater today. |

Plan items 16, 17, 18, 25, 27, 28, 32, 33, and 35 with Carbon. Items 11, 19, and 29 also benefit from Carbon when the failure cases or the threat model are the hard part. Use Argon for almost all implementation, and for planning the rest. Use a light model for process, CI wiring, and documentation. Carbon stays on the fund-safety items, where multi-step adversarial reasoning pays off. A strong coding model writes the PRs.

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

**5. Error-path integration tests.** Offline tests in `app::tests::error_path_tests` (`crates/wallet-core/src/app/tests/error_path_tests.rs`). They reuse `app_with_job`, `app_with_private_coins`, `app_with_public_coins`, and `discovery::go_offline_for_test()`. Dead peers are `127.0.0.1:9` or a loopback listener the test owns. Each one checks the phase (`ChurnPhase`, `LockState`, `SyncPhase`), the holds (`reserved`, `public_reserved`, user freezes), and the coin row (`CoinStatus`, `CoinActions`).

- Lock during a private send, a public split, and an MWEB resync. The spend returns an error, the state is dropped, and the in-flight hold is released. A bystander freeze stays. Resync ends at `SyncPhase::Idle` with `needs_mweb_scan` still set.
- A locked pump that expires a hop is reconciled by `load` and by `retry_churn` before anything is signed again. A hop broadcast while locked is applied on `load`.
- Persist failures (the seal-counter path replaced with a directory): `start_churn` leaves no job, `retry_churn` keeps the paused job, a private split takes no hold, and `set_mweb_scheme` leaves sync idle with the scan flag set.
- Private send, peg-out, split, and transfer, and public send, transfer, and peg-in, against a dead peer or Electrum. Holds and the peg-in's temporary outpoint mask are released. A dead Electrum `sync` stays `Idle` and keeps `needs_full_scan`. Unreachable MWEB peers make `resync_mweb` finish `Done` and stale.
- A failed churn broadcast pauses at `WaitingToBroadcast` until Retry. Unread headers leave `WaitingConfirm` waiting. `PausedUnscored` inside the inclusion grace returns to `WaitingConfirm`. After the grace, `NotIncluded` restores the original coin and sets `needs_resign`.
- A foreign spend drops the phantom, refuses Retry, and `cancel_churn` removes `mweb_frozen.json`. Rejected `retry_churn` and `cancel_churn`, and the spend validations that return before signing, leave the job files and coins unchanged.

Those tests fixed three cleanup bugs. `cancel_churn` now checks `ChurnEvent::Cancel` before it recalls an unbroadcast hop. `load` and `retry_churn` run `undo_expired_local` and `apply_pending_local`, so a hop that expired or was broadcast while locked is applied before the next command. `note_foreign_spend` and a broadcast of hop 0 clear the `spent_output_id` freeze, which `apply_pending_local` only cleared for later hops. A process killed mid-write is item 17.

**6. UI action-flag consistency.** `ui/src/actions.ts` maps `ChurnActions` and `CoinActions` to the buttons and checkboxes rendered in `ui/src/main.ts` (`churnActionButtons`, `privateCoinActionState`, `publicCoinActionState`, `freezeTargetLocked`). `scripts/action-flags.test.mjs` (run by `npm run test:ui` in CI) checks every flag combination and statically checks `ui/src/main.ts` and `ui/src/shots-fixture.ts`: no `.locked` or `.mature` reads on coins, coin `.confirmations` read only for the `"N conf"` label, `churn_phase` read only in allowlisted status/copy functions (never in `.churn-status-actions` or coin button builders), and LitVM's Speed up (`tx.pending && !tx.failed && !tx.incoming` in `renderLitvmHistory`) pinned as the sole remaining UI-inferred action button. Fixed two gaps found during the check: `toggleUtxoLocked` and `toggleMwebLocked` now derive the target `locked` boolean from `actions.freeze` / `actions.unfreeze` instead of `!utxo.locked` / `!coin.locked`, and `renderMwebControlList` now prunes `panel.selected` when `!coin.actions.select` (matching `renderUtxoList`).

## CI and regression

**7. Diagram and table checks on every PR.** `.github/workflows/ci.yml` runs on every `pull_request` and on pushes to `main`, with no path filter. The weekly schedule skips only the Rust jobs.

- `transition_table_matches_docs` and `lock_table_matches_docs` run inside `cargo test --workspace --locked` on the Ubuntu `rust` job and the Windows `rust-windows` job. They compare `churn::TRANSITIONS` and `lock::LOCK_TRANSITIONS` with the generated blocks in `docs/CHURN.md` and `docs/LOCK_LIFECYCLE.md`. `diagram::check_doc` reads those paths from `CARGO_MANIFEST_DIR`. A stale block or a missing marker fails the job. `UPDATE_DIAGRAMS` rewrites the block for a local refresh; with it unset, the test asserts the committed block.
- The same `cargo test` runs the table checks from item 3: `table_has_one_row_per_key_and_no_exit_from_finished`, `lock_table_matches_behavior`, `lock_table_has_unique_keys_and_every_state_is_reachable`, and the churn and lock random walks.
- The frontend job runs `npm run check:diagrams` after `npm run build`. That compares `PHASE_FROM` in `ui/src/phases.ts` with `docs/UI_PHASES.md` and exits non-zero when the block is stale. `npm run test:ui` in the same job runs the phase-table walks in `scripts/phase-table.test.mjs`.

These are the only three generated diagrams (`churn-transitions`, `lock-transitions`, `ui-phases`). A changed line in any of them fails the job that owns it.

**8. Screenshot regression.** Run `npm run screenshots` in CI for the coins scenes that show status chips and churn cards (`?cover=` values in `ui/src/shots-fixture.ts`).

**9. `cargo miri`.** On the pure state-machine, hold and status logic, where it can run without I/O.

## Fuzzing and chaos

**10. Fuzz or structure-aware property tests** on `churn::transition`, the coin status functions, and the pure parsers used by holds and phases. Coverage-guided `cargo-fuzz` or proptest targets. Size, timeout, and structure limits on Electrum responses, MWEB peer messages, address and seed parsers, and local job and settings files, and structure-aware fuzz of those parsers, are item 19.

**11. Chaos tests.** Inject a lock or a failure mid-sync and mid-churn, then check that no phase is stuck and no reserved hold is orphaned. Restart after a kill mid-persist is item 17.

## Process and audit readiness

**12.** Turn `docs/MWEB_E2E.md` into a repeatable pre-release gate, including how to record the run.

**13.** Review notes for reserved holds vs user freezes and for the lock lifecycle, pointing at the tests that pin them.

**14.** Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current with new findings and residual risks.

## Observability

**15.** Log phase changes, hold take and release, and transition rejections with the job or coin id, from and to, and the reason, so support bundles and post-mortems are useful. Those logs follow the redaction rules in item 16.
- `churn::transition` (`crates/wallet-core/src/churn.rs`) logs every accepted self-spend phase change (`self-spend: phase <from> -> <to> job=<origin_id> coin=<current_id> event=<kind> reason=<reason>`) and every rejected transition (`self-spend: rejected <kind> job=<origin_id> coin=<current_id> from=<from> reason=<err>`), and `start_churn`, `retry_churn`, and `cancel_churn` log pre-transition command rejections.
- `mweb_frozen` (`crates/wallet-core/src/mweb_frozen.rs`) logs private and public in-flight hold takes (`coin-hold: take`), releases (`coin-hold: release`), stale-session sweeps (`reason=stale session`), and double-reserve/frozen-coin rejections (`coin-hold: rejected reserve`) with the coin or outpoint ID, session, `from`/`to`, and reason.
- `SyncPass`, `WalletApp` lock lifecycle (`unlock`, `load_locked`, `create_or_restore`, `activate_parked`, `lock`, `StateGuard::check_lock`, `StateGuard::drop`), and `set_private_freeze` / `set_public_freeze` (`crates/wallet-core/src/app.rs`) log sync-phase transitions (including early-drop resets to `Idle`), lock-state transitions and rejections, and user freeze/unfreeze changes and rejections, all routed through `diag::log` (`redact::scrub_log_line`) and pinned by tests in `churn.rs`, `mweb_frozen.rs`, `error_path_tests.rs`, and `tests/secret_hygiene.rs`.

## Secrets, persistence, and value

**16. Secret hygiene and zeroization.** Done. Lock, auto-lock, wipe, and error returns clear the decrypted seed, the MWEB sealing key, and intermediate buffers. `Debug`, error strings, and the logs from item 15 carry no mnemonic, private key, raw MWEB payload, or full sensitive buffer.
- `Zeroizing` and `Drop` cover secrets, signers, sealing keys, and armed hops.
- `redact::scrub_log_line` runs on `diag::log` and on errors.
- Redacted `Debug` and a source guard live in `crates/wallet-core/tests/secret_hygiene.rs` and `scripts/secret-hygiene.test.mjs`.

The idle timer that decides when auto-lock fires is item 31. This item is the wipe.

**17. Persistence atomicity and crash recovery.** Kill the process mid-sync, mid-churn, and mid-persist, then restart. Holds are not orphaned, phases are not stuck, and coin status matches the recovered files. Job and sealed files use a temp file and rename where they do not already. Whole-directory rollback stays the residual recorded in `docs/AUDIT_NOTES.md`.
- `fs_atomic` (`write_atomic`, `write_atomic_0600`, `sweep_temp_files` in `crates/wallet-core/src/fs_atomic.rs`), plus atomic `0600` temp-file + `sync_all` + rename in `crates/wallet-litvm/src/settings.rs` and `crates/wallet-cli/src/main.rs`, replace in-place truncation across `wallet.mnemonic.enc`, `mweb_*.enc`, `mweb_seal_counter.txt`, `churn_job.json`, `churn_armed.json`, `churn_depth.json`, `mweb_frozen.json`, `wallet_meta.json`, `accounts.json`, and metadata sidecars. Leftover `*.tmp.*` files are swept on `load` and `wipe`.
- `MwebRuntime::open` enforces `mweb_seal_counter.txt` (`open_changeset_with_context` and `open_with_context_at_least`), rejects legacy v1 downgrades once upgraded, and rejects a `>1` counter spread across the four sealed blobs while recovering cleanly from a `{C, C+1}` mid-persist cut (`Index -> Coins -> History -> SyncState -> save_seal_counter`). `open_wallet_state` and `create_or_restore` propagate `MwebRuntime::open` errors instead of silently loading with `mweb: None`.
- Fixed a persistence bug in `mweb::recall_unlanded_spend` and `mweb::restore_stale_unconfirmed_inputs`: both called `db.insert(coin)` instead of `db.restore_spent(&id)`, which omitted `id` from `ChangeSet.restored` so `ChangeSet::merge` discarded the recall on `persist` and left cancelled, expired, or dropped-spend coins marked spent in `mweb_coins.enc` after restart.
- `reconcile_churn_on_load` (plus idempotent `churn::inherit_depth`, `churn::revert_depth`, and `churn::commit_score`), `reconcile_mweb_chain_with_wallet`, `resync_mweb` pre-wipe `needs_mweb_scan` persistence, and cross-account stale-hold cleanup recover cleanly from process aborts and `SIGKILL` across `crash_recovery_tests.rs` and `crates/wallet-core/tests/crash_recovery.rs`. Windows CI already runs these tests; macOS `F_FULLFSYNC` is item 30.

**18. Transaction construction and value invariants.** Checked arithmetic on amounts and fees, dust limits, and change selection. Constructed transactions, especially peg-in and peg-out, meet the expected shape and do not leave a stuck or attacker-spendable output when the path returns an error. MWEB commitment and kernel balance sit here, beside the coin-status tests.
- `tx_invariants` (`crates/wallet-core/src/tx_invariants.rs`) enforces `MAX_MONEY` (`84,000,000` LTC) checked addition/summation, fee-rate bounds (`1..=100,000` sat/vB), deduplicating coin-control normalizers, `validate_public_recipient` (rejecting MWEB stealth addresses whose `script_pubkey()` is empty and witness v8/v9 bridge scripts on both normal and `drain` sends), `validate_mweb_recipient`, and post-construction shape/conservation verifiers (`verify_transparent_psbt`, `verify_pegin_tx`, `verify_mweb_spend_tx`).
- `LitecoinDustCoinSelection` enforces Litecoin Core's 30 sat/vB dust floor (`2,940` litoshis on P2WPKH, `3,300` on witness-v9 peg-ins) on change and drain outputs instead of `rust-litecoin`'s inherited 3 sat/vB (`294` litoshis) constant, pulling in an optional UTXO when doing so rescues sub-dust change for less input fee than forfeiting the leftover.
- `mweb::prepare_pegin` builds peg-in PSBTs with `LitecoinDustCoinSelection` and `unspendable(held)` directly instead of temporarily calling `wallet.lock_outpoint` on `public_reserved` coins; `resolve_pegin_request` filters out user-frozen UTXOs, enforces `PEGIN_V9_DUST_SATS` (`3,300`) and MWEB weight minimum fees, and sizes multi-input miner fees.
- `split::plan_split` enforces `bdk_mweb::policy::min_mweb_fee` across 2–50 private outputs and replaces saturating addition with checked arithmetic; `build_public_split_psbt`, `sign_pegout`, `prepare_transfer_broadcast`, `sign_mweb_split`, and `sign_self_spend_hops` defer external/MWEB receive-index persistence until building, signing, and invariant checks succeed.
- `wallet-litvm` (`verify_replacement_target` in `crates/wallet-litvm/src/client.rs`) verifies sender, recipient, value, nonce, and empty calldata on RPC-fetched pending transactions before signing an EIP-1559 replacement; `ui/src/amounts.ts` + `scripts/amounts.test.mjs` bound UI LTC/litoshi parsing to `MAX_MONEY_SATS` and reject malformed comma placements.
- `assert_mweb_tx_consensus_and_balance` and `mweb_constructed_spends_balance_commitments_stealth_and_rangeproofs` (beside the coin-status tests in `crates/wallet-core/src/mweb.rs`), plus seeded property tests across `split.rs`, `mweb.rs`, `tx_invariants_tests.rs`, `wallet-litvm`, and `scripts/amounts.test.mjs`, pin Pedersen commitment balance, stealth excess balance, Bulletproof rangeproofs, and value conservation.

## Untrusted input, restore, and static analysis

**19. Untrusted input bounds.** Size, timeout, and structure limits on Electrum responses, MWEB peer messages, address and seed parsers, and local job and settings files. Structure-aware fuzz or property tests on those parsers stay here. Item 10 covers coverage-guided targets on the state machines and the hold and phase parsers. This is defense in depth on the kind of validation mismatch seen in the 2026 MWEB incident. Named Electrum cases, from `ltc-electrum/electrum-ltc` `tests/test_interface.py` and `tests/test_jsondb.py`: disconnect on notification spam, disconnect on a server-initiated request, and a truncated or garbage local JSON file must not panic or load a partial wallet. Whether a merkle proof or a header is allowed to confirm a coin is item 25.

- LitVM HTTP (`ProviderBuilder::connect_http` in `crates/wallet-litvm/src/client.rs`): a response body cap, a deadline for the whole call, and a redirect limit.
- Local files: a size cap and a JSON nesting cap before `read_to_string` or `serde_json` runs (`churn.rs`, `mweb_frozen.rs`, `spv.rs`, `mweb.rs`, and the mnemonic file).
- Electrum and MWEB sockets: a deadline for the whole call, in addition to any per-read socket timeout.
- `wallet.mnemonic.enc` selects fixed Argon2 parameters from the version magic in `crates/wallet-core/src/secrets.rs` (v1: 19 MiB, `t=2`; v2: 64 MiB, `t=3`). A tampered header cannot raise `m_cost`. The size cap above still applies to that file.

**20. Backup and restore round-trips.** Seed-only restore recovers the BIP84 gap and the MWEB scan keys and lookahead, and resets user freezes, labels, and churn depth. Seed plus metadata restores the same spendable transparent and MWEB coins, including after an interrupted operation and more than one account under one seed. Also open a frozen file from each on-disk generation this wallet has shipped (plaintext MWEB files, v1 Argon2 secrets, v1 seal envelopes) and still spend. The pattern is Electrum-LTC `tests/test_storage_upgrade.py`: one fixture per format, opened by current code.

The v1 seal-envelope fixture pairs with item 17. A v1 envelope opens and upgrades when no v2 seal counter exists, and it fails closed when `mweb_seal_counter.txt` is present.

`clear_stale` in `crates/wallet-core/src/mweb_frozen.rs` drops `reserved` and `public_reserved` whose `session` is not this process, and it leaves `ids` alone. Public user freezes live in the BDK wallet DB, not in that file. The fixture restores an `mweb_frozen.json` that contains an old session's in-flight hold, and load sweeps that hold and keeps `ids`. A second live process is not that old session: opening one sweeps the first process's holds, which is item 32.

Capture today's `churn_depth.json` in this item, before item 28's per-hop ledger changes that file. After item 28 lands, add a second frozen fixture for the ledger format.

**21. Static analysis.** `cargo-geiger`, or the same kind of check, on the unsafe surface, and optionally `cargo-mutants` on the transition tables and status functions. Record that constant-time behavior comes from the crypto crates, or add a light test where this repo owns the comparison.

The same item pins the Tauri surface in CI, beside the diagram checks in items 7 and 8. `src-tauri/capabilities/default.json` stays `core:default` and `core:window:allow-start-dragging`. The CSP in `src-tauri/tauri.conf.json` stays `script-src 'self'` with no remote script and no `eval` (the dev CSP may keep the localhost websocket). Sensitive commands reject a UI-forged call while the wallet is locked or the phase table rejects the event.

## Further surfaces

**22. Error-message sanitization.** UI text and logs omit stack traces and extra address or amount detail.

**23. Lookalike addresses and confirmations.** Warn on address lookalikes, and confirm high-value or irreversible actions beyond the existing wipe phrase. `estimate_fee_rate_sat_vb` clamps Electrum `blockchain.estimatefee` to `1..=100,000` sat/vB (`MAX_FEE_RATE_SAT_VB`). At that cap a 250 vB transaction pays 0.25 LTC. Confirm, or refuse, when the total fee or the fee-to-amount ratio crosses a stated threshold. The rate clamp stays.

**24. Release SBOM.** Attach an SBOM, or an explicit check of the pinned dependencies, to releases. The supply-chain CI already in place stays as it is.

## Electrum trust and peg-out maturity

Taken from Electrum-LTC (`ltc-electrum/electrum-ltc`, branch `mweb`). That suite is upstream Electrum with Litecoin addresses swapped in. It has no MWEB tests. These two items are the gaps it still exposed. Coin selection, dust, change, and derivation vectors are already items 18 and the frozen vectors in `crates/wallet-core/tests/recovery.rs`. Their regtest workflow is Lightning, so it is not a suite to copy. Item 12 stays the MWEB gate.

**25. SPV acceptance of Electrum data.** A server must not be able to mark a coin confirmed with a forged proof or a header that does not meet Litecoin proof-of-work. `bdk_electrum` confirms via `electrum_client::utils::validate_merkle_proof` (pin `6ffa5afa` in `LitecoinDevKit/rust-electrum-client`). That function only recomputes the merkle root and checks it against the header that same server returned. Electrum rejects two proofs this accepts, in `tests/test_verifier.py`:

- CVE-2017-12842: a 64-byte transaction used as an inner merkle node (`InnerNodeOfSpvProofIsValidTx`).
- CVE-2012-2459: a duplicated left sibling forging extra leaf positions (`LeftSiblingDuplicate`). A legitimate duplicate is only a right sibling.

`tests/test_blockchain.py` (`TestVerifyHeader`, `TestHeaderChainResolution`) rejects a prev-hash mismatch, a target mismatch, insufficient proof-of-work, a lagging server, and a fork. This wallet's `apply_electrum_chain_update` applies the server's update as given. `cross_check_tip` compares header hashes with a second server and warns. It does not check scrypt proof-of-work, and it does not fail the sync. That warning stays. It does not replace a local check. Audit note O11 (a server hiding mempool transactions) is a different residual.

A transaction the server claims is mined is not confirmed until the proof passes. An invalid transaction is rejected. Switching servers drops unconfirmed state that was cached only because of the previous server (`tests/test_address_synchronizer.py`). Item 5 covers a dead peer, not a lying one.

Done. `crates/wallet-core/src/spv.rs` replaces `bdk_electrum`'s `full_scan` and `sync` with a driver that verifies everything before `wallet.apply_update`:

- Headers: genesis per network, Litecoin scrypt(1024, 1, 1) proof of work, compact targets decoded as Core's `SetCompact` and capped at `powLimit`, the 2016-block retarget (Litecoin's 2015-block first lookback and the one-bit shift near `powLimit`), Testnet4 min-difficulty blocks, and `prev_blockhash` links. The window is the last 2016 headers, or back to the fork point.
- Chain choice: a server behind the local tip is refused as lagging. A fork up to 2160 blocks deep is accepted only with strictly more cumulative work than the local branch.
- Proofs: a merkle branch is checked against the verified header and refuses a 64-byte inner node that parses as a transaction (CVE-2017-12842), a duplicated left sibling, a duplicate off the right edge (CVE-2012-2459), and a position outside the tree. A failing branch fails the sync. A server that has no branch leaves the transaction unconfirmed.
- Transactions: raw bytes must hash to the requested txid. Duplicate inputs, `MAX_MONEY` overflow, and 64-byte transactions are refused. Peg-in repair checks every source the same way and moves on to the next one when the check fails.
- Server switch: `electrum_spv.json` records which unconfirmed transactions only the last server reported. `update_settings` evicts them on a server change, keeping peg-ins and transactions that spend our own coins. A server that fails verification is forgotten, not tried first again.
- `probe_tip` (Settings, Test connection) checks genesis and the tip header's proof of work. Churn scoring's `block_hash_at` uses only local, stored-verified, or proof-of-work-checked headers.

Tests use a thread-local regtest proof-of-work override (`spv::easy_pow_for_test`) so mock chains mine in a hash or two. Residuals are in `docs/AUDIT_NOTES.md`. The below-window anchor residual (O13) is item 33.

**26. Peg-out maturity on public coins.** Done. Litecoin consensus will not spend a HogEx peg-out until 6 confirmations (`PEGOUT_MATURITY` in Electrum-LTC `electrum/bitcoin.py`, and `CanonicalTxOut::is_mature` in `bdk`). `public_coin_status` and `collect_unspent` read `is_mature`. A peg-out at 1–5 confirmations is `Maturing`, with spend buttons off through the same flag path private maturing coins already use. `AGENTS.md` lists maturing on the public status list. An ordinary unconfirmed public coin stays selectable, as item 4 pinned. Coinbase outputs follow the same `is_mature` check (100 confirmations). The boundary is `tip - confirmation_height + 1 >= maturity`.
- `public_utxo_maturity` and `collect_unspent` in `crates/wallet-core/src/app.rs` read `CanonicalTxOut::is_mature(tip)` and compute `maturity_blocks_left` (`PEGOUT_MATURITY` = 6 on HogEx peg-outs, `COINBASE_MATURITY` = 100 on coinbase outputs, `0` on ordinary outputs).
- `mweb::public_coin_status` in `crates/wallet-core/src/mweb.rs` adds `Maturing` (`status` priority: `Sending -> Pending -> Maturing -> Frozen -> Ready`; `blocked` priority: `Sending -> Frozen -> Unconfirmed -> Maturing`), turning `select`, `freeze`, `split`, and `transfer` off while `!mature` and keeping ordinary unconfirmed public coins selectable (`Pending`, `select: true`, `freeze: true`).
- `build_send_psbt`, `public_split_utxo`, `resolve_pegin_request`, and `selectable_public_utxo_amounts` reject or exclude immature HogEx and coinbase UTXOs, `ui/src/main.ts` renders the `Maturing` chip and remaining block count on public rows, and `hogex_pegout_and_coinbase_maturity_boundaries_in_public_coins` pins the 6-block and 100-block boundaries.

## MWEB peers, reorgs, and dropped spends

These follow items 19, 20, and 31. Item 31 sits after item 20 and before items 27 and 28. Item 20 stays ahead of items 27 and 28 so its frozen fixture captures today's `churn_depth.json` before the per-hop ledger. Item 19 still owns size, timeout, and structure limits on MWEB peer messages. HogEx anchoring and peer frame caps stay in `bdk_mweb` (`VerifyMode::Anchored`, audit notes in `docs/AUDIT_NOTES.md`). This repo does not reimplement LIP-0006 verification.

**27. Adversarial MWEB peer.** The MWEB analogue of item 25. Item 5 covers a dead or unreachable peer. HogEx anchoring binds the peer's MWEB header to the SPV-verified transparent tip: `WalletApp::sync` passes `wallet.latest_checkpoint()` into `FixedHeaderProvider` after the item 25 update has been applied. The anchor is that checkpoint hash, not a block header fetched from the MWEB peer. A sync that fails HogEx anchoring leaves the coin store and history unchanged and marks MWEB stale.

Two checks, kept separate:

- Local monotonicity. Reject a sync peer that reports a smaller `output_mmr_size` at a height at or above the persisted MWEB tip unless `disconnect_from` already ran for a transparent reorg.
- Second-peer cross-check. `MwebRuntime::cross_check_leafset` compares `leafset_root` and `output_mmr_size` at that same SPV tip hash. Disagreement sets `cross_check_warning` and a stale balance. It leaves spend and churn flags as they are, so a lying second peer cannot freeze the wallet. Agreement, or no second peer, only appends to `last_status`. Withheld UTXO leaves are audit note O2: omission is a warning, including the path where the second peer is unreachable (`cross-check unavailable`).

There is no test today. LIP-0006 proofs, Bulletproofs, and HogEx commitment checks stay in `bdk_mweb`.

**28. Cross-layer reorg unwind.** Item 17's `crash_mid_reorg_sync_and_resync_mweb_and_cross_account_holds_recover_on_restart` checks that MWEB history confirmed above the wallet tip is unconfirmed on load and that stale holds are swept. `WalletApp::sync` calls `mweb.disconnect_from` when the tip height falls, and `reconcile_mweb_chain_with_wallet` when the MWEB tip hash disagrees with the wallet chain. `disconnect_from` rewinds the MWEB store, drops the leafset, and clears `confirmed_height`. `churn::commit_score` only increases `non_solo_blocks`, and only while `last_other_kernels` is empty. `inherit_depth` copies that scalar onto the next output and clears ``last_other_*``. `revert_depth` moves the record back and does not subtract. `ChurnHop` stores `other_kernels` and `other_outputs` only. A reorg that un-mines a scored hop leaves that depth counted, and a re-mine in a different block is not scored again.

Failing tests first. A confirmed peg-in that leaves the chain has two outcomes:

- The peg-in is still valid and back in the mempool. The private peg-in coin is gone or pending, the history row is unconfirmed, and the public input stays spent by that unconfirmed peg-in.
- The peg-in is invalidated, by a confirmed conflicting spend or by item 29's release rule. The peg-in no longer holds the public input. A foreign conflict means the input is spent by that conflict.

A confirmed peg-out that leaves the chain drops the HogEx output. When the peg-out kernel can still be in the MWEB mempool, the private input stays an unconfirmed spend under `UNCONFIRMED_MWEB_REVERT_SECS`, not `Ready`.

A scored churn hop that leaves the chain unwinds depth, in-flight holds, and the churn phase with the chain. Depth lives in a persisted per-hop ledger: hop index, `output_id`, `confirmed_height`, `block_hash`, and `score_delta`. Unwind drops every row confirmed above the fork height and recomputes `non_solo_blocks` from the rows that remain. Dropping those rows also clears `last_other_kernels` and `last_other_outputs` on the unwound outputs, so `commit_score` scores the hop again when it confirms in a different block. Later hops spend earlier ones, so the same drop reconciles the active job's `current_id` and phase when an intermediate hop was un-mined.

Transparent state, MWEB state, and churn depth move together. The pass stages every cross-layer change and validates it before any rename. A pass that cannot move them together fails closed and persists nothing from that pass. That is stricter than item 17, whose writers are atomic per file and whose load path repairs a kill. It does not close audit note O12.

**29. Dropped unconfirmed transparent spends.** Item 18 pins dust and the minimum fee. LitVM EIP-1559 replacement is separate. An unconfirmed MWEB spend reverts after 48 hours (`UNCONFIRMED_MWEB_REVERT_SECS` in `crates/wallet-core/src/mweb.rs`). Transparent peg-ins are kept on purpose: `pegin_txids` in `crates/wallet-core/src/app.rs` and `merge_protected` in `crates/wallet-core/src/spv.rs` are never evicted, and a spend of our own outputs stays when the server omits it. That stops a server from resurrecting inputs by hiding a peg-in before a release trigger has fired. Audit note O14 (a kept spend with an invalid signature) stays that finding.

The gap is a peg-in or public spend that has left the mempool, after a fee spike or a long unconfirmed window, and remains spent in the local graph. Any one of these releases it:

1. The wallet's own node reports the tx absent from its mempool. This is the fast path when a node is configured. An Electrum-only wallet has no own node, so this trigger is not required for it.
2. An SPV-verified conflicting spend of an input confirms.
3. At least 48 hours and at least ~1,152 blocks have elapsed since the persisted `broadcast_height`, and the current Electrum server omits the tx.

Own-node absence is not required on the timeout path. Peg-ins and ordinary transparent spends (send, public split, and transfer) each persist `broadcast_height`. Churn jobs already have one. A spend that is already unconfirmed when this ships takes the tip height at first sight as that height, so trigger 3 can run. Fee bumping and RBF are out of scope.

**30. macOS full-disk flush.** `fs_atomic` (`crates/wallet-core/src/fs_atomic.rs`) flushes the temp file with `File::sync_all`, which is `fsync`. On macOS that returns before the drive cache is flushed. After `rename` it already opens the parent directory and calls `sync_all`, and it discards that error. One helper runs `F_FULLFSYNC` after `sync_all` on the file and on the parent directory, and both `write_atomic` and `write_atomic_0600` call it. That keeps `mweb_*.enc` and `mweb_seal_counter.txt` on the same tier, and it covers `churn_job.json`, `mweb_frozen.json`, and `electrum_spv.json` with them. The LitVM settings writer (`crates/wallet-litvm/src/settings.rs`) and the coinswapd env writer in `crates/wallet-cli/src/main.rs` today only `sync_all` the file; they call that same helper, under the same cfgs. A failed parent flush fails the secret write. `#[cfg(unix)]` gates the directory `fsync`. `#[cfg(target_os = "macos")]` gates `F_FULLFSYNC`. Windows does not open a directory handle to sync it. A rename onto a path another handle holds open fails closed and leaves the previous bytes in place, which is the Windows sharing and antivirus case. The Windows `rust-windows` job already runs `crash_recovery_tests.rs` and `tests/crash_recovery.rs`. No new CI job.

## Auto-lock

**31. Auto-lock wake race.** The idle check in `ui/src/main.ts` stores `lastActivityTs = Date.now()` and compares it on a 30-second `setInterval`. The `pointerdown`, `keydown`, `wheel`, and `mousemove` listeners refresh `lastActivityTs` immediately, so input on wake resets the idle clock before the interval observes the sleep. Those handlers, plus `visibilitychange` and `focus`, test `Date.now() - lastActivityTs` against the timeout before they refresh the timestamp. `WalletApp` enforces the same deadline, so a throttled webview or a forged UI call locks at the same boundary as `NotLoaded` and the `DELETE WALLET` phrase. Background polls (`pump_churn`, and status or sync polls) do not refresh that idle timestamp, so an open window polling every few seconds cannot keep the deadline alive. Item 16 stays the zeroization work. This sits after item 20 and before items 33, 34, 27, and 28. Audit note O15.

## One directory, one process

**32. Single-instance directory lock.** Item 17 makes each file write atomic. Item 30 makes a rename onto an open handle fail closed. Neither stops `ldk-wallet` and `wallet-cli`, or two app launches, from opening the same directory. `clear_stale` drops every `reserved` and `public_reserved` hold whose `session` is not this process, so the second open does not only race `mweb_seal_counter.txt`. It releases the first process's live in-flight holds. Take an exclusive lock (`flock` or a lockfile) before open, in the app and in `wallet-cli`. A second process fails closed and does not call `clear_stale`. A crash still leaves a dead session, and the next open of a directory with no live holder still sweeps that session. Item 20's fixture is that dead session, not a second live process.

## SPV anchors below the window

**33. SPV checkpoints and work floor.** Item 25 verifies the last 2016 headers. Audit note O13 is the residual: a fresh wallet, or one far behind, accepts the window's first header with only a proof-of-work and `powLimit` check, and an anchor below the window is checked against an isolated header. Ship signed header checkpoints, or verify forward from the last checkpoint, and give anchors below the window more than an isolated proof-of-work check. A server that can mine 2016 headers at minimum difficulty must not present that chain as the wallet's.

## LitVM sends

**34. LitVM send and RPC invariants.** Item 18 verifies an EIP-1559 replacement (`verify_replacement_target`: sender, recipient, value, nonce, empty calldata). Item 19 caps the HTTP body, the call deadline, and redirects. A normal send already goes through `probe`, which sets `signing_enabled` only when `eth_chainId` matches the preset, and through `build_tx`, which caps the priority fee, the max fee (`MAX_FEE_GWEI`), the gas limit (`MAX_GAS_LIMIT` = 2,000,000), and the total fee (`MAX_TOTAL_FEE_WEI`, 0.05 zkLTC). `send` then trusts `signing_enabled` and does not read the chain id again. The built transfer never sets calldata and never asserts the signed transaction's input is empty. Re-check `eth_chainId` against the preset inside send, before signing. Refuse a normal send whose calldata is non-empty, the same way replacement already does. Keep the existing caps, and test that a hostile fee or gas estimate cannot pass them.

## Armed hops on disk

**35. `churn_armed.json` at rest.** `write_armed` in `crates/wallet-core/src/churn.rs` writes `ArmedRecord` with `write_atomic_0600`. The JSON includes `raw_hex` and `created_coin`, and `created_coin` is `serde_json` of `PreparedHop.created` (`bdk_mweb::MwebCoin`), whose fields include `spend_key`, `blind`, and `shared_secret`. The test `armed_hop_debug_and_wipe_protect_raw_hex_and_coin_secrets` redacts those fields in `Debug`. It does not seal the file. `docs/LOCK_LIFECYCLE.md` says the broadcast pump reads `churn_armed.json` while locked, without unlocking, so sealing the file under the key that lock wipes would stop the pump. Mode `0600` is not encryption. Keep that pump, and keep those spend secrets out of plaintext JSON. Audit note O1 is the plaintext `wallet.sqlite` (addresses and history, not keys) and does not cover this file. Tor and DNS-seed privacy stay O7. Other JSON sidecars that do not hold spend secrets stay out of this item.

## Release surface

**36. Core dumps, backup exclusion, updater.** Not ahead of items 32–35. No in-app updater exists; add one only with an explicit check that it cannot replace the wallet from an unpinned source. Exclude the wallet directory from cloud backup, and keep secrets out of core dumps. Do this with the release work in item 24.

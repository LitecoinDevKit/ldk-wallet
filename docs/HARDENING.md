# Hardening checklist

The one living checklist for hardening this wallet, which is an unaudited prototype. Update it in the same PR as the work. Rules for doing the work are in `AGENTS.md`.

## Next up

1. Transaction construction and value invariants (item 18).
2. Diagram and table checks on every PR (item 7).
3. Logging for phase changes, holds and rejections (item 15).
4. Untrusted input bounds (item 19).

## Status

| # | Task | Priority | Status | PR | Notes |
|---|------|----------|--------|----|-------|
| 1 | Tighten `AGENTS.md` | Planned | Done | [#24](https://github.com/LitecoinDevKit/ldk-wallet/pull/24) | Also adds this file. |
| 2 | `SyncPass` guard for `sync_phase` | Planned | Done | [#25](https://github.com/LitecoinDevKit/ldk-wallet/pull/25) | |
| 3 | Property tests on transition tables | High | Done | [#26](https://github.com/LitecoinDevKit/ldk-wallet/pull/26), [#27](https://github.com/LitecoinDevKit/ldk-wallet/pull/27), [#28](https://github.com/LitecoinDevKit/ldk-wallet/pull/28) | churn (500×30), lock (5×8), UI (500×30). |
| 4 | Coin-status tests | High | Done | [#29](https://github.com/LitecoinDevKit/ldk-wallet/pull/29) | Exhaustive fact combinations, hold vs freeze, and freeze commands that follow the flags. |
| 5 | Error-path integration tests | High | Done | [#30](https://github.com/LitecoinDevKit/ldk-wallet/pull/30) | Offline lock races, persist failures, bad peers, foreign spend, and rejected commands. Three state-cleanup bugs fixed. |
| 6 | UI action-flag consistency checks | High | Done | [#31](https://github.com/LitecoinDevKit/ldk-wallet/pull/31) | Pure flag-to-button mapping in `ui/src/actions.ts` and static checks in `scripts/action-flags.test.mjs`. |
| 7 | Diagram and table checks on every PR | CI | Mostly done | | Confirm and record. |
| 8 | Screenshot regression in CI | CI | Not started | | |
| 9 | `cargo miri` on pure logic | CI | Not started | | |
| 10 | Fuzz or property tests on transitions and parsers | Fuzzing | Not started | | |
| 11 | Chaos tests for lock and failure mid-pass | Fuzzing | Not started | | |
| 12 | `docs/MWEB_E2E.md` as a pre-release gate | Process | Not started | | |
| 13 | Review notes for holds vs freezes and the lock lifecycle | Process | Not started | | |
| 14 | Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current | Process | Ongoing | | Never claim the wallet is audited. |
| 15 | Logging for phase changes, holds and rejections | Observability | Not started | | The reported sync phase is now trustworthy (#25). Redaction is in `redact.rs` (item 16). |
| 16 | Secret hygiene and zeroization | High | Done | [#32](https://github.com/LitecoinDevKit/ldk-wallet/pull/32) | `Zeroizing` and `Drop` across secrets, signers, sealing keys, and armed hops; `redact::scrub_log_line` on `diag::log` and errors; redacted `Debug` and source guard in `secret_hygiene.rs` + `scripts/secret-hygiene.test.mjs`. |
| 17 | Persistence atomicity and crash recovery | High | Done | | Temp-file + `sync_all` + rename across secret, sealed, churn, hold, metadata, sidecar, LitVM, and CLI writers; v2 seal-counter enforcement and fail-closed `MwebRuntime::open`; `db.restore_spent` fix on recalled coins; `reconcile_churn_on_load` and reorg/resync recovery pinned by `crash_recovery_tests.rs` and `tests/crash_recovery.rs`. |
| 18 | Transaction construction and value invariants | High | Not started | | Amounts, fees, dust, change, and peg-in/peg-out shape. Beside the coin-status tests. |
| 19 | Untrusted input bounds | Medium | Not started | | Size, timeout, and structure limits. Refines item 10. |
| 20 | Backup and restore round-trips | Medium | Not started | | Seed plus metadata restores the same spendable set. |
| 21 | Static analysis expansion | Medium | Not started | | Unsafe surface, and optionally mutation testing of the tables. |
| 22 | Error-message sanitization | Lower | Not started | | UI and logs omit stack traces and extra address or amount detail. |
| 23 | Lookalike addresses and confirmations | Lower | Not started | | Beyond the existing wipe phrase. |
| 24 | Release SBOM | Lower | Not started | | On top of the supply-chain CI already in place. |

## Model and effort

How to staff items 6–24. Planning is Cursor chat or plan mode. Implementation is agent mode that writes the tests and code.

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
| 10 | Fuzz and structure-aware property tests | Argon · Medium | Argon · Medium–High | Structure-aware fuzz on transitions and parsers. Use Carbon if a parser stays stubborn. |
| 11 | Chaos tests (lock or failure mid-pass) | Carbon · Medium | Argon · Medium–High | Planning lists the failure cases. Implementation follows that list. |
| 12 | `MWEB_E2E.md` as a pre-release gate | Light · Low | Light · Low | Process and documentation. |
| 13 | Review notes (holds vs freezes, lock lifecycle) | Argon · Low–Medium | Light · Low | Write the notes and link the tests that already pin the behavior. |
| 14 | Keep `AUDIT_NOTES.md` and `SECURITY.md` current | Light · Low | Light · Low | Ongoing documentation. |
| 15 | Logging for phase, holds, and rejections | Argon · Low–Medium | Argon · Medium | Follows once the redaction rules in item 16 are set. |
| 16 | Secret hygiene and zeroization | Carbon · Medium | Argon · Medium–High | Enumerate every lock, wipe, error path, and buffer. Implementation is tests plus careful `zeroize` use. |
| 17 | Persistence atomicity and crash recovery | Carbon · Medium–High | Argon · High | Plan the kill points and the residual risk, then test kill, restart, and consistency. |
| 18 | Transaction construction and value invariants | Carbon · Medium | Argon · Medium–High | Checked arithmetic, dust, change, and peg-in/peg-out shape. Carbon finds the edge cases; Argon writes the property tests. |
| 19 | Untrusted input bounds | Carbon · Medium | Argon · Medium | Size, timeout, and structure limits, plus structure-aware fuzz. |
| 20 | Backup and restore round-trips | Argon · Medium | Argon · Medium–High | Seed and metadata restore under interrupted operations and holds. |
| 21 | Static analysis expansion | Light–Argon · Low | Light · Low–Medium | `cargo-geiger` and optional mutants. CI and documentation. |
| 22 | Error-message sanitization | Light · Low | Light · Low–Medium | Redaction rules and a few tests. |
| 23 | Lookalike addresses and confirmations | Argon · Low–Medium | Argon · Medium | UI warnings and extra confirmation flows. |
| 24 | Release SBOM | Light · Low | Light · Low | On top of the supply-chain CI already in place. |

Plan items 16, 17, and 18 with Carbon. Items 11 and 19 also benefit from Carbon when the failure cases or the threat model are the hard part. Use Argon for almost all implementation, and for planning the rest. Use a light model for process, CI wiring, and documentation. Carbon stays on the fund-safety items, where multi-step adversarial reasoning pays off. A strong coding model writes the PRs.

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

**7. Diagram and table checks on every PR.** `ci.yml` runs on every PR. `transition_table_matches_docs` and `lock_table_matches_docs` run inside `cargo test --workspace --locked`, and `npm run check:diagrams` runs after `npm run build`.

**8. Screenshot regression.** Run `npm run screenshots` in CI for the coins scenes that show status chips and churn cards (`?cover=` values in `ui/src/shots-fixture.ts`).

**9. `cargo miri`.** On the pure state-machine, hold and status logic, where it can run without I/O.

## Fuzzing and chaos

**10. Fuzz or structure-aware property tests** on `churn::transition`, the coin status functions, and pure parsers used by holds and phases. Size, timeout, and structure limits on Electrum responses, MWEB peer messages, address and seed parsers, and local job and settings files are item 19.

**11. Chaos tests.** Inject a lock or a failure mid-sync and mid-churn, then check that no phase is stuck and no reserved hold is orphaned. Restart after a kill mid-persist is item 17.

## Process and audit readiness

**12.** Turn `docs/MWEB_E2E.md` into a repeatable pre-release gate, including how to record the run.

**13.** Review notes for reserved holds vs user freezes and for the lock lifecycle, pointing at the tests that pin them.

**14.** Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current with new findings and residual risks.

## Observability

**15.** Log phase changes, hold take and release, and transition rejections with the job or coin id, from and to, and the reason, so support bundles and post-mortems are useful. Those logs follow the redaction rules in item 16.

## Secrets, persistence, and value

**16. Secret hygiene and zeroization.** Tests that lock, auto-lock, wipe, and error returns clear the decrypted seed, the MWEB sealing key, and intermediate buffers. `Debug`, error strings, and the logs from item 15 must not contain a mnemonic, a private key, raw MWEB payloads, or a full sensitive buffer. A CI check covers this if it can run without a new harness.

**17. Persistence atomicity and crash recovery.** Kill the process mid-sync, mid-churn, and mid-persist, then restart. Holds are not orphaned, phases are not stuck, and coin status matches the recovered files. Job and sealed files use a temp file and rename where they do not already. Whole-directory rollback stays the residual recorded in `docs/AUDIT_NOTES.md`.
- `fs_atomic` (`write_atomic`, `write_atomic_0600`, `sweep_temp_files` in `crates/wallet-core/src/fs_atomic.rs`), plus atomic `0600` temp-file + `sync_all` + rename in `crates/wallet-litvm/src/settings.rs` and `crates/wallet-cli/src/main.rs`, replace in-place truncation across `wallet.mnemonic.enc`, `mweb_*.enc`, `mweb_seal_counter.txt`, `churn_job.json`, `churn_armed.json`, `churn_depth.json`, `mweb_frozen.json`, `wallet_meta.json`, `accounts.json`, and metadata sidecars. Leftover `*.tmp.*` files are swept on `load` and `wipe`.
- `MwebRuntime::open` enforces `mweb_seal_counter.txt` (`open_changeset_with_context` and `open_with_context_at_least`), rejects legacy v1 downgrades once upgraded, and rejects a `>1` counter spread across the four sealed blobs while recovering cleanly from a `{C, C+1}` mid-persist cut (`Index -> Coins -> History -> SyncState -> save_seal_counter`). `open_wallet_state` and `create_or_restore` propagate `MwebRuntime::open` errors instead of silently loading with `mweb: None`.
- Fixed a persistence bug in `mweb::recall_unlanded_spend` and `mweb::restore_stale_unconfirmed_inputs`: both called `db.insert(coin)` instead of `db.restore_spent(&id)`, which omitted `id` from `ChangeSet.restored` so `ChangeSet::merge` discarded the recall on `persist` and left cancelled, expired, or dropped-spend coins marked spent in `mweb_coins.enc` after restart.
- `reconcile_churn_on_load` (plus idempotent `churn::inherit_depth`, `churn::revert_depth`, and `churn::commit_score`), `reconcile_mweb_chain_with_wallet`, `resync_mweb` pre-wipe `needs_mweb_scan` persistence, and cross-account stale-hold cleanup recover cleanly from process aborts and `SIGKILL` across `crash_recovery_tests.rs` and `crates/wallet-core/tests/crash_recovery.rs`.

**18. Transaction construction and value invariants.** Checked arithmetic on amounts and fees, dust limits, and change selection. Constructed transactions, especially peg-in and peg-out, meet the expected shape and do not leave a stuck or attacker-spendable output when the path returns an error. MWEB commitment and kernel balance sit here, beside the coin-status tests.

## Untrusted input, restore, and static analysis

**19. Untrusted input bounds.** Size, timeout, and structure limits on Electrum responses, MWEB peer messages, address and seed parsers, and local job and settings files. Structure-aware fuzz or property tests on those parsers. This is defense in depth on the kind of validation mismatch seen in the 2026 MWEB incident, and it refines item 10.

**20. Backup and restore round-trips.** A seed plus metadata restore recovers the same spendable transparent and MWEB coins, including after an interrupted operation, a reserved hold, and more than one account under one seed.

**21. Static analysis.** `cargo-geiger`, or the same kind of check, on the unsafe surface, and optionally `cargo-mutants` on the transition tables and status functions. Record that constant-time behavior comes from the crypto crates, or add a light test where this repo owns the comparison.

## Further surfaces

**22. Error-message sanitization.** UI text and logs omit stack traces and extra address or amount detail.

**23. Lookalike addresses and confirmations.** Warn on address lookalikes, and confirm high-value or irreversible actions beyond the existing wipe phrase.

**24. Release SBOM.** Attach an SBOM, or an explicit check of the pinned dependencies, to releases. The supply-chain CI already in place stays as it is.

# Hardening tracker and implementation guide

You are working on LitecoinDevKit/ldk-wallet (prototype desktop wallet, not independently audited). Follow `AGENTS.md` and the existing rules exactly:

- Multi-step flows with real phases use one table + generated diagram kept in sync by CI.
- Call the transition function before side effects. Terminal states stay terminal.
- Backend decides legal UI actions and sends flags; UI only renders them.
- Reproduce state bugs with a failing test first (`app_with_job`, `app_with_foreign_spent_job`, etc.).
- Never commit a patched `Cargo.lock`. Format only touched files. Run the CI checks before considering work done.
- Do not diagram code that lacks real phase changes, guards, or terminal states.

## Tracking

Create or update `docs/HARDENING.md` as the single living checklist for these tasks. Structure it as:

- Current status table (task, priority, status, PR link if any, notes)
- Detailed sections for each area below
- A short “Next up” list at the top

Update the checklist in the same PR as the work. Do not invent new process docs unless asked.

## Priority order

Work in this order unless a specific item is requested. Prefer small, reviewable PRs.

### Already planned (do these first if not landed)
1. Tighten `AGENTS.md` (terminal-state correction, dedupe, common mistakes, adding-a-flow checklist, flows-without-a-table list including sync and LitVM).
2. SyncPass RAII guard so `sync_phase` always resets to Idle on exit (failing test first, remove `set_sync_phase`, unit tests for the guard, update the flows-without-a-table entry).

### High-value automated checks
3. Property-based tests on every transition table (`churn::TRANSITIONS`, `lock::LOCK_TRANSITIONS`, UI `PHASE_FROM`): for every phase × every event the result is either a legal next phase or a clean rejection; finished/terminal states have no exits.
4. Systematic coin-status and public-coin-status tests covering the documented priority order and the reserved vs user-freeze distinction. Assert that buttons come only from the returned flags.
5. Additional error-path integration tests (lock races, persist failures, bad peers, foreign spend, early returns) that assert final phase, holds, and coin status. Reuse existing test helpers; no network.
6. UI action-flag consistency checks (backend flags → expected buttons; no phase inference in the UI).

### CI and regression
7. Ensure diagram and transition-table checks run on every PR.
8. Add screenshot regression (`npm run screenshots`) to CI for the coins scenes that exercise status chips and churn cards.
9. Run `cargo miri` on the pure state-machine, hold, and status logic where practical.

### Fuzzing and chaos
10. Lightweight fuzz or structure-aware property tests on `churn::transition`, coin status functions, and any pure parsers used by holds/phases. Size, timeout, and structure limits on untrusted input are item 19.
11. Concurrency/chaos tests that inject locks or failures mid-sync / mid-churn and verify recovery leaves a consistent state (no stuck phases, no orphaned reserved holds). Restart after a kill mid-persist is item 17.

### Process and audit readiness
12. Expand the existing `docs/MWEB_E2E.md` checklist into a repeatable pre-release gate (document how to record the run metadata).
13. Add or update focused review notes for reserved holds vs user freezes and the lock lifecycle (point at existing tests and the planned SyncPass).
14. Keep `docs/AUDIT_NOTES.md` and `SECURITY.md` current with any new findings or residual risks. Do not claim the wallet is audited.

### Observability
15. Ensure phase changes, hold take/release, and transition rejections are logged with enough context (job/coin id, from/to, reason) so support bundles and post-mortems are useful. The SyncPass change should make the reported phase trustworthy. Those logs follow the redaction rules in item 16.

### Secrets, persistence, and value
16. Secret hygiene and zeroization. Lock, auto-lock, wipe, and error paths clear the decrypted seed, the MWEB sealing key, and intermediate buffers. `Debug`, error strings, and item 15 logs never contain a mnemonic, a private key, raw MWEB payloads, or a full sensitive buffer.
17. Persistence atomicity and crash recovery. Kill the process mid-sync, mid-churn, and mid-persist, then restart. Holds are not orphaned, phases are not stuck, and coin status matches the recovered files. Temp file plus rename where job and sealed files do not already. Extends items 5 and 11. Whole-directory rollback stays the residual in `docs/AUDIT_NOTES.md`. Windows CI already runs these tests; macOS `F_FULLFSYNC` is item 30.
18. Transaction construction and value invariants. Checked arithmetic on amounts and fees, dust limits, change selection, and peg-in/peg-out shape. An error path must not leave a stuck or attacker-spendable output. MWEB commitment and kernel balance sit beside the coin-status tests.

### Untrusted input, restore, and static analysis
19. Untrusted input bounds. Size, timeout, and structure limits on Electrum responses, MWEB peer messages, address and seed parsers, and local job and settings files. Structure-aware fuzz or property tests. Refines item 10. Named cases: Electrum notification spam, a server-initiated request, and truncated local JSON. Merkle and header validity are item 25.
20. Backup and restore round-trips. A seed plus metadata restores the same spendable transparent and MWEB coins, including after an interrupted operation, a reserved hold, and more than one account under one seed. Also open a frozen file from each on-disk generation (plaintext MWEB, v1 Argon2 secrets, v1 seal envelopes).
21. Static analysis. `cargo-geiger` (or equivalent) on the unsafe surface, and optionally `cargo-mutants` on the transition tables and status functions. Record reliance on constant-time primitives from the crypto crates, or add a light test where this repo owns the comparison.

### Electrum trust and peg-out maturity
25. SPV acceptance of Electrum data. A forged merkle proof (CVE-2017-12842, CVE-2012-2459) or a header that fails Litecoin proof-of-work must not confirm a coin. `validate_merkle_proof` at pin `6ffa5afa` only recomputes the root. `cross_check_tip` stays a warning and does not replace the local check. A transaction claimed mined waits for a passing proof. Switching servers drops unconfirmed state cached from the previous server.
26. Peg-out maturity on public coins. A HogEx peg-out with fewer than 6 confirmations is maturing, not Ready. Spend buttons come from the flags. Ordinary unconfirmed public coins stay selectable. Use `is_mature` so coinbase outputs (100 confirmations) follow the same check. Update `AGENTS.md` in that PR.

### MWEB peers, reorgs, and dropped spends
These follow items 19 and 20. They do not jump ahead of item 26. Item 19 still owns size, timeout, and structure limits. HogEx anchoring and peer frame caps stay in `bdk_mweb`. Do not reimplement LIP-0006 verification here.
27. Adversarial MWEB peer. A second peer whose `leafset_root` disagrees warns and does not mark the balance complete. A sync that fails HogEx anchoring leaves the coin store and history unchanged and goes stale. Withheld leaves stay the O2 warning, including when the second peer is unreachable.
28. Cross-layer reorg unwind. A reorg that un-mines a confirmed peg-in, a confirmed peg-out, or a scored churn hop unwinds transparent coins, MWEB coins, history, holds, and churn depth together, or the sync fails closed. Item 17 only unconfirms MWEB history above the wallet tip. Failing tests first.
29. Dropped unconfirmed transparent spends. A peg-in or public spend that has left the mempool releases its inputs. Release needs own-node absence, a conflicting confirmed spend, or a timeout in the same family as the 48-hour MWEB revert. A server that merely omits a peg-in still cannot resurrect it. RBF is out of scope.
30. macOS full-disk flush. Secret and sealed writers call `F_FULLFSYNC` after `sync_all`. A rename onto a path another handle holds open fails closed and leaves the previous bytes. No new CI job.

### Further surfaces
22. Error-message sanitization so UI text and logs omit stack traces and extra address or amount detail.
23. Address lookalike warnings, and confirmation for high-value or irreversible actions beyond the existing wipe phrase.
24. An SBOM, or an explicit pin check, attached to releases, on top of the existing supply-chain CI.

## Working rules for every task
- Failing test first for any state or recovery bug.
- Single writer / no workarounds around tables or guards.
- Update diagrams and `docs/HARDENING.md` in the same PR.
- Paste the diagram diff in the PR description when a table changes.
- Run the usual checks (`cargo clippy --workspace --all-targets --locked`, `cargo test --workspace --locked`, `npm run build`) with full permissions; restore `Cargo.lock` before committing.
- Prefer small PRs. One logical change per PR when possible.

## Output format when you start a task
1. Read `docs/HARDENING.md` and the relevant source.
2. State the exact next item you will implement.
3. Write the failing test (or checklist update) first.
4. Implement the smallest change that makes the test pass and keeps the rules intact.
5. Update the tracking doc and open the PR.

The living status and the next item are in `docs/HARDENING.md`. Items 1–7, 15–18, and 25 are done. Do the next item there unless a specific one is requested. Items 27–30 follow 19 and 20; they do not jump ahead of item 26.
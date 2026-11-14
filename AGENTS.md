# Agent notes

Rules for agents (and people) changing this wallet. `README.md` covers setup.

## Multi-step flows

Each flow with real phases has one table that is the only legal path, and a diagram generated from it that a check keeps in sync:

| Flow | Table | Diagram | Regenerate |
|------|-------|---------|------------|
| Self-spend (churn) | `churn::TRANSITIONS` | `docs/CHURN.md` | `UPDATE_DIAGRAMS=1 cargo test -p wallet-core transition_table_matches_docs` |
| Lock / unlock | `lock::LOCK_TRANSITIONS` | `docs/LOCK_LIFECYCLE.md` | `UPDATE_DIAGRAMS=1 cargo test -p wallet-core lock_table_matches_docs` |
| UI lifecycle phase | `PHASE_FROM` in `ui/src/phases.ts` | `docs/UI_PHASES.md` | `npm run check:diagrams -- --write` |

Peg-in, peg-out and send are single locked calls with no stored phase, so they have no table. A private coin's status and buttons come from `mweb::coin_status` in `crates/wallet-core/src/mweb.rs`, which documents its priority order (churning, sending, pending, maturing, frozen, tied to peg-in, ready). A coin is `sending` while a send, peg-out, split or transfer that signed it is still broadcasting; that hold lives in `reserved` in `mweb_frozen.json`, apart from the user's freezes, and only the spend's `CoinHold` releases it. A public coin's status and buttons come from `mweb::public_coin_status` (sending, pending, frozen, ready). Its in-flight hold lives in `public_reserved` in the same file, keyed by `txid:vout`, and is also released only by the spend's `CoinHold`. Never use BDK's `lock_outpoint` as an in-flight hold: that lock is the user's Freeze, and Unfreeze would undo it mid-broadcast. The UI renders `status`, `actions` and `actions.blocked` on each coin, public or private, and `maturity_blocks_left` on peg-in history rows; it never works these out from `mature`, `locked`, `confirmations` or `churn_phase`. To change when a coin button is allowed, change `coin_status` and its tests.

Any change to a flow with a table follows the same rules:

- One `transition` entry point per flow and a private phase field. To allow a new change, add a row to the table first; never work around it with a setter outside tests.
- Terminal states (Done, Cancelled, Failed, Locked) cannot be re-entered or left except by the rows the table lists. Add a test that pins this.
- Regenerate the diagram after changing the table and commit it. CI fails when it is stale. Paste the diagram diff into the PR description (the PR template asks for it).
- The backend decides which UI actions are legal and sends them as flags. The UI renders the flags; it never infers an action from a phase.
- Do not diagram code without real phase changes, guards, or terminal states.

## State changes

- Self-spend phases change only through `churn::transition` in `crates/wallet-core/src/churn.rs`. The `phase` field is private; to allow a new change, add a row to `TRANSITIONS`. Never work around it with a test-only setter outside tests.
- After changing `TRANSITIONS`, run `UPDATE_DIAGRAMS=1 cargo test -p wallet-core transition_table_matches_docs` and commit the regenerated diagram in `docs/CHURN.md`. CI fails when it is stale. Put the diagram diff in the PR description.
- `Done` and `Cancelled` are final. `table_has_one_row_per_key_and_no_exit_from_finished` enforces it.
- The UI never decides whether Retry, Cancel, or Open Settings is available. It renders `churn_actions`, which `churn::allowed_actions` derives from the table. Add a flag there rather than a phase check in `ui/src/main.ts`.
- Code that holds the wallet state mutex takes it through `lock_state()`, whose guard drops the signer and wallet when the user locks while it is held. Only the documented exceptions in `docs/LOCK_LIFECYCLE.md` use `lock_state_raw()`.

## Bugs

- Reproduce a state bug with a failing test before fixing it. `app_with_job` and `app_with_foreign_spent_job` in the `app.rs` tests build a real testnet `WalletState` without network access; use them to drive private functions like `drive_churn` or `undo_expired_local`.
- Check every new or changed path against the table: what phase can the job be in when this runs, and what happens if the event is rejected? Call `transition` before side effects on the coin store or `churn_armed.json`, so a rejection leaves nothing half done.

## Building and committing

- `aws-lc-sys` cannot build inside a restricted sandbox (it copies headers into the target dir). Run `cargo` builds and tests with full permissions.
- A local, git-ignored `.cargo/config.toml` patches the bdk crates to `../bdk`. Builds then drop the git `source` lines from `Cargo.lock`. Never commit that change: run `git restore Cargo.lock` before committing. CI runs `cargo metadata --locked` and fails on it.
- `cargo fmt --check` has an existing diff in `crates/wallet-core/src/lib.rs`. Format only the files you touched (`rustfmt --edition 2021 <files>`) so unrelated churn stays out of the diff.
- Checks CI runs: `cargo clippy --workspace --all-targets --locked`, `cargo test --workspace --locked`, `npm run build`.
- UI screenshots: `npm run screenshots`. The fixture in `ui/src/shots-fixture.ts` takes `?cover=solo|no-rpc|waiting|spreading|spent|sending` on the coins scene.

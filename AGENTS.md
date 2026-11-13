# Agent notes

Rules for agents (and people) changing this wallet. `README.md` covers setup.

## State changes

- Self-spend phases change only through `churn::transition` in `crates/wallet-core/src/churn.rs`. The `phase` field is private; to allow a new change, add a row to `TRANSITIONS`. Never work around it with a test-only setter outside tests.
- After changing `TRANSITIONS`, run `UPDATE_DIAGRAMS=1 cargo test -p wallet-core transition_table_matches_docs` and commit the regenerated diagram in `docs/CHURN.md`. CI fails when it is stale. Put the diagram diff in the PR description.
- `Done` and `Cancelled` are final. `table_has_one_row_per_key_and_no_exit_from_finished` enforces it.
- The UI never decides whether Retry, Cancel, or Open Settings is available. It renders `churn_actions`, which `churn::allowed_actions` derives from the table. Add a flag there rather than a phase check in `ui/src/main.ts`.

## Bugs

- Reproduce a state bug with a failing test before fixing it. `app_with_job` and `app_with_foreign_spent_job` in the `app.rs` tests build a real testnet `WalletState` without network access; use them to drive private functions like `drive_churn` or `undo_expired_local`.
- Check every new or changed path against the table: what phase can the job be in when this runs, and what happens if the event is rejected? Call `transition` before side effects on the coin store or `churn_armed.json`, so a rejection leaves nothing half done.

## Building and committing

- `aws-lc-sys` cannot build inside a restricted sandbox (it copies headers into the target dir). Run `cargo` builds and tests with full permissions.
- A local, git-ignored `.cargo/config.toml` patches the bdk crates to `../bdk`. Builds then drop the git `source` lines from `Cargo.lock`. Never commit that change: run `git restore Cargo.lock` before committing. CI runs `cargo metadata --locked` and fails on it.
- `cargo fmt --check` has an existing diff in `crates/wallet-core/src/lib.rs`. Format only the files you touched (`rustfmt --edition 2021 <files>`) so unrelated churn stays out of the diff.
- Checks CI runs: `cargo clippy --workspace --all-targets --locked`, `cargo test --workspace --locked`, `npm run build`.
- UI screenshots: `npm run screenshots`. The fixture in `ui/src/shots-fixture.ts` takes `?cover=solo|no-rpc|waiting|spreading|spent` on the coins scene.

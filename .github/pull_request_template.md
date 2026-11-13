## What changed

<!-- One or two sentences on the behavior change, not the diff. -->

## State diagram diff

<!--
Required when a flow table changes (see "Multi-step flows" in AGENTS.md).
Paste the before/after of the generated diagram block and say which rows
were added or removed and why. Write "No state changes" otherwise.
-->

## How it was checked

- [ ] Failing test first for a bug fix
- [ ] `cargo test --workspace` and `cargo clippy --workspace --all-targets`
- [ ] `npm run build`
- [ ] `Cargo.lock` has no lost git `source` lines
- [ ] Screenshot for UI changes

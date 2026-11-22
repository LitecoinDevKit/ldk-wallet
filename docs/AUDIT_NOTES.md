# Internal security review — findings and status

Internal review performed August 2026 alongside the security-hardening pass
(TLS validation, CSP, wipe gate, supply-chain pinning, release checksums).
This is not a third-party audit; it is the working findings list and the scope
document for one. Reviewed: `wallet-core` (secrets, seed parsing, Electrum,
RPC, MWEB orchestration), the Tauri command surface, the UI's secret handling,
and both GitHub workflows. An automated diff-focused security review of the
hardening changes found no medium-or-higher issues.

Severity: **H**igh / **M**edium / **L**ow / **I**nformational.

## Fixed in the hardening pass

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| F1 | H | Electrum TLS ran with `validate_domain(false)` — any MITM could impersonate the server (hide transactions, delay broadcasts, feed a false chain view) | Validation on by default (`crates/wallet-core/src/electrum.rs`); per-wallet opt-out in Settings with a warning; CA-certified `cipig.net` servers added as first mainnet defaults (verified serving Litecoin genesis over valid TLS); `server.version` handshake added for strict ElectrumX servers |
| F2 | M | Webview CSP was `null` — any script injection had full latitude | Strict CSP (`default-src 'self'`, no inline script) + separate dev CSP in `src-tauri/tauri.conf.json`; verified baked into the release binary |
| F3 | M | `wipe_wallet` was callable with a bare `invoke()`; UI confirm was the only gate | Typed phrase `DELETE WALLET` required, enforced at the IPC boundary in `src-tauri/src/lib.rs` |
| F4 | L | RPC transport errors could echo `user:pass@` from the configured URL into UI error text | `redact_userinfo` in `crates/wallet-core/src/rpc.rs` + tests |
| F5 | L | `com.apple.security.cs.allow-jit` entitlement was unnecessary (WKWebView JIT lives in Apple's XPC process) | Removed; release build + launch verified |
| F6 | L | Secret files were created with umask permissions, then chmod'd to 0600 (brief exposure window) | Created with 0600 atomically (`OpenOptionsExt::mode`) in `crates/wallet-core/src/secrets.rs` |
| F7 | M | Supply chain: `Cargo.lock` untracked, actions pinned by tag, no CI, no artifact checksums | Lockfile tracked; all actions pinned to commit SHAs; `ci.yml` runs build/clippy/tests/`cargo audit`/`cargo deny`/`npm audit`; releases attach `SHA256SUMS-<platform>.txt`; Apple signing is drop-in via secrets |

## Accepted risks (by design — documented in SECURITY.md)

| # | Sev | Risk | Rationale |
| --- | --- | --- | --- |
| A1 | M | TLS validation can be disabled by the user | Most community Electrum-LTC servers (and all known testnet servers) are self-signed; the toggle requires an unlocked wallet and shows a warning |
| A2 | M | Wipe works without the passphrase | Only recovery path when the passphrase is lost; destroys data, not funds (mnemonic backup restores); gated by the typed phrase |
| A3 | L | CLI accepts `--passphrase` / `WALLET_PASSPHRASE` (visible in shell history / `ps` / env) | Convenience for scripting; interactive hidden prompt is the default when omitted |
| A4 | L | CLI prints the mnemonic once on `create` | Deliberate one-time backup output, sent to stderr |

## Fixed in the second hardening pass (August 2026)

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| O1 | M | `mweb.sqlite` / MWEB sync+history files were unencrypted at rest; `sealing_key()` existed but nothing consumed it | MWEB coin store, sync state, receive index and history are now sealed with ChaCha20-Poly1305 under the sealing key (`mweb_*.enc`); plaintext-era files migrate automatically and are deleted after the first sealed persist. The transparent `wallet.sqlite` remains plaintext (see updated O1 below) |
| O2 | M | MWEB sync trusted a single peer per pass — a malicious peer could omit UTXOs (understate balance) | After each successful sync the freshly downloaded leafset is verified against the MWEB header (`leafset_root` / `output_mmr_size`) reported by up to two peers; disagreement raises a user-visible warning, agreement is noted in the MWEB status line |
| O3 | M | Electrum fallback silently appended public default servers; a private-server user leaked addresses whenever theirs was briefly down | "Use public fallback servers" setting (default on, persisted in `wallet_meta.json`); when off, only the configured server is ever contacted. The server used by each sync is shown in Settings |
| O4 | L | Argon2id parameters (19 MiB, t=2, p=1) were the OWASP minimum | Raised to 64 MiB, t=3 in a new v2 file format whose sealing key is a random key stored *inside* the encrypted payload (so future KDF bumps never orphan sealed data); v1 files re-encrypt transparently on the next unlock |
| O6 | L | `tcp://` Electrum URLs were accepted silently (plaintext protocol) | The UI now requires an explicit confirmation before saving a non-localhost `tcp://` server |
| — | M | A lying Electrum server could feed a false chain view with nothing to catch it | Post-sync cross-check against a second, independent server: block headers only (no address leakage), warns when servers disagree at the tip or the sync server appears to withhold blocks |
| — | L | Unlocked wallets stayed unlocked indefinitely | Auto-lock after configurable idle time (default 15 min, 0 = off); backend zeroizes key material on lock |
| — | I | Release integrity relied on checksums alone | GitHub build provenance attestations on every artifact (`gh attestation verify`); optional minisign signing of the checksums files (drop-in via `MINISIGN_SECRET_KEY` secret) |
| — | I | Dependency advisories were only checked when code changed | Weekly scheduled CI run of `cargo audit` / `cargo deny` / `npm audit` |

## Fixed with the error-path checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | L | `cancel_churn` called `revert_unbroadcast_hop` before `churn::request_cancel`. A cancel rejected from `WaitingConfirm`, `Done`, or `Cancelled` still recalled an unbroadcast hop and rewrote the coin store and `mweb_frozen.json` | `request_cancel` runs first. Cancel only changes the phase, so a rejection leaves the coins and freezes as they were |
| — | L | An armed hop can expire, or a later hop can be broadcast, while the wallet is locked. The pump then has no `WalletState`, so it records the event and leaves the coin store behind. After unlock, `list_mweb_unspent` still showed the phantom, and `retry_churn` tried to spend it. A hop broadcast while locked also left the spent coin user-frozen with Unfreeze offered | `read_account_state` runs `undo_expired_local` and `apply_pending_local` after opening the account. `retry_churn` runs `undo_expired_local` before it reads the job |
| — | L | Signing a hop freezes both the spent output and the new one. `apply_pending_local` unlocks the spent output when a later hop is broadcast. Hop 0 is already in the coin store, so `send_armed_hop` skipped that. `note_foreign_spend` deleted `churn_armed.json` without unlocking `spent_output_id`. The freeze stayed in `mweb_frozen.json` after `Done` or cancel | Hop 0's broadcast and `note_foreign_spend` clear `spent_output_id` with `mweb_frozen::set_locked(..., false)` |

## Fixed with the coin-status checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | L | `set_mweb_utxo_locked` and `set_utxo_locked` accepted Freeze or Unfreeze when `coin_status` / `public_coin_status` left the flag off: a pending or maturing private coin, a coin a self-spend holds, and a repeat of the current freeze | The commands refuse unless the listed coin's `freeze` or `unfreeze` flag is set. A coin that is not listed can still be cleared, so a stale freeze does not get stuck |
| — | L | `toggleUtxoLocked` and `toggleMwebLocked` in `ui/src/main.ts` read `!utxo.locked` / `!coin.locked` instead of `actions.freeze` / `actions.unfreeze`, and `renderMwebControlList` kept a previously selected private coin in `panel.selected` after `actions.select` turned false | `ui/src/actions.ts` derives the freeze target and button states from `CoinActions` and `ChurnActions`, `renderMwebControlList` prunes `panel.selected` when `select` is disabled, and `scripts/action-flags.test.mjs` enforces both in CI |

## Fixed with the secret-hygiene checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | M | `LitVmHandle::attach` raced `lock_wallet`: if the wallet locked while the background task was opening `LitVmClient`, `drop_client` did not acquire `attach_gate` and `active_account_dir` did not change on lock, so `attach` still installed an unlocked EVM signer while locked | `LitVmHandle::drop_client` acquires `attach_gate`, `attach` re-checks `wallet.is_locked()` before and under `slot()`, and `LitVmClient::open` takes `Zeroizing<[u8; 32]>` |
| — | L | `MasterSecret`, `DecodedAezeed`, secret/settings DTOs, `WalletMeta`, `ArmedHop`, `PreparedHop`, `LitVmClient`, and `wallet-cli` `Command` derived `Debug`, exposing mnemonics, passphrases, BIP32 chain codes, URL `user:pass@` credentials, raw MWEB transaction hex, and serialized `MwebCoin` secrets (`spend_key`, `blind`, `shared_secret`) | Replaced with manual redacted `fmt::Debug` (plus `ZeroizeOnDrop` on secret DTOs); `sensitive_types_and_fields_do_not_derive_debug` in `crates/wallet-core/tests/secret_hygiene.rs` fails CI if `#[derive(Debug)]` returns on sensitive types or fields |
| — | L | `fetch_pegin_raw_tx` interpolated raw RPC URLs (`http://user:pass@host`) into `eprintln!`, `aezeed::words_to_bytes` echoed unknown tokens into `WalletError::InvalidMnemonic`, and `diag::log` / `DiagnosticsBundle` had no central secret or raw-payload scrubber | `redact::scrub_log_line` strips URL userinfo, mnemonics, `xprv`/WIF keys, and `>64`-char raw MWEB hex while keeping 64-char `txid`/`output_id`/`block_hash` identifiers; `words_to_bytes` reports only the 1-based word index |
| — | L | `KeyMapWrapper` on `WalletState.signer`, `MwebRuntime.sealing_key`, `ArmedHop` tail cleanup, and early-`?` error paths in `EncryptedFileSecretStore`, `aezeed::decode`, `parse_extended_key`, and `create_or_restore` left unzeroized copies; `reveal_mnemonic` accepted calls while locked; UI `lockWallet` did not clear onboarding/restore inputs | `ZeroizingSigner` wipes BIP84 keys on drop and `bdk_wallet::Wallet` receives public-only descriptors; `Zeroizing` wraps store/decode/sealed buffers; `wipe_raw_tail` zeroizes `raw_hex` and `created_coin` JSON strings; `reveal_mnemonic` requires an unlocked wallet and uses `verify_passphrase`; `lockWallet` and `wipeAndOnboard` call `clearSecretInputs()` |

## Fixed with the persistence-atomicity and crash-recovery checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | M | `mweb::recall_unlanded_spend` and `mweb::restore_stale_unconfirmed_inputs` called `db.insert(coin)` instead of `db.restore_spent(&id)`. Because `insert` does not add the id to `ChangeSet.restored`, `ChangeSet::merge` ignored the restored coin against `agg.spent` during `MwebRuntime::persist`, so any coin recalled by `cancel_churn`, armed expiry, `NotIncluded`, or the 48h unconfirmed-spend revert vanished from `mweb_coins.enc` on the next wallet restart | Both paths call `db.restore_spent(&id)`, which stages `restored` so `ChangeSet::merge` removes the id from `agg.spent` on `persist` |
| — | M | `MwebRuntime::open` passed `min_counter = 0` to `open_changeset_with_context`, called `open_with_context` (ignoring `mweb_seal_counter.txt`) on the other three sealed blobs, and `open_wallet_state` / `create_or_restore` wrapped `MwebRuntime::open` in `.ok()`, so partial rollback or corruption of `mweb_*.enc` either succeeded or silently disabled MWEB (`mweb: None`) | `MwebRuntime::open` enforces `min_counter = load_seal_counter`, rejects v1 downgrades after v2 upgrade and counter spreads `> 1` across the four blobs, advances `persist` from `max(disk, loaded) + 1` in `Index -> Coins -> History -> SyncState -> Counter` order, and `open_wallet_state` / `create_or_restore` propagate errors |
| — | L | Secret, sealed, churn, freeze/hold, metadata, LitVM settings, and CLI env writers truncated target files in place (`fs::write` / `OpenOptions::truncate`), and kills mid-`start_churn`, mid-`retry_churn`, mid-`send_armed_hop`, mid-`drive_churn`, mid-`cancel_churn`, or mid-reorg sync left torn files, uncommitted phantom coins, double-counted depth, unpromoted multi-hop jobs, or orphaned holds | All writers use sibling temp-file + `sync_all` + `rename` (`fs_atomic`); `reconcile_churn_on_load`, `reconcile_mweb_chain_with_wallet`, idempotent `commit_score` / `revert_depth`, and cross-account hold sweeps recover on `load` |

## Fixed with the transaction-construction and value-invariant checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | H | `build_send_psbt` called `Address::from_str`, which accepts `ltcmweb1…` / `tmweb1…` stealth addresses and returns an empty 0-byte `ScriptBuf::new()` from `address.script_pubkey()`. When `SendRequest.drain` was `true`, `tx_builder.add_recipient` was bypassed and `tx_builder.drain_to(ScriptBuf::new())` built and signed a transaction sending the wallet's balance to an anyone-can-spend empty `scriptPubKey`; witness v8/v9 MWEB bridge scripts were also accepted on public sends | `tx_invariants::validate_public_recipient` rejects `AddressData::Mweb`, empty scripts, `OP_RETURN`, witness v8/v9 MWEB bridge scripts, and non-standard script types before building any PSBT, and `verify_transparent_psbt` re-verifies every output script |
| — | M | `rust-litecoin` defines `DUST_RELAY_TX_FEE = 3_000` (Bitcoin's 3 sat/vB = `294` litoshis on P2WPKH) instead of Litecoin Core's `30_000` (`2,940` litoshis on P2WPKH, `3,300` on witness-v9 peg-ins), so `bdk_wallet::coin_selection::decide_change` emitted `294..2,939` litoshi change and drain outputs that Litecoin Core nodes refuse to relay | `LitecoinDustCoinSelection` enforces Litecoin Core's 30 sat/vB dust floor (`bdk_mweb::policy::dust_threshold`) on change and drain outputs, topping up with an optional UTXO when that rescues sub-dust change for less input fee than forfeiting the leftover |
| — | M | `resolve_pegin_request` read `wallet.balance().trusted_spendable()`, which includes user-frozen (`is_outpoint_locked`) UTXOs, omitted v9 dust (`3,300`) and MWEB weight-floor (`2,100`) checks in `preview_pegin`, under-estimated multi-input miner fees (`PEGIN_FEE_VB_ESTIMATE = 250`), always reported `creates_change = false` on auto-selection, and `pegin` temporarily mutated BDK's `lock_outpoint` to mask `public_reserved` holds | `resolve_pegin_request` sums unlocked, unheld UTXOs, enforces `PEGIN_V9_DUST_SATS` and `min_mweb_fee`, sizes vbytes from input count, computes `creates_change` against the `2,940` dust floor, and `mweb::prepare_pegin` passes `unspendable(held)` directly without calling `lock_outpoint` |
| — | M | `mweb::normalize_selected_ids`, `mweb::resolve_spend_coins`, and `selected_outpoints` parsing did not deduplicate repeated IDs; `split::plan_split` used `DEFAULT_MWEB_FEE_SATS = 50_000` for 28–50 private outputs (which require `53,700..92,100` litoshis by MWEB weight) and `saturating_add` on `u64::MAX` inputs; `merge_mweb_history` panicked on `net_sats == i64::MIN`; `LitVmClient::replace_tx` signed RPC-returned `to`/`value`/`nonce` without checking they matched the user-confirmed replacement request; and UI `parseLtcToSats` / `parseLitoshisToSats` allowed values above `MAX_MONEY` or decimal-comma typos (`"1,5"` -> `15`) | Coin-control lists deduplicate preserving order; `split.rs` enforces `min_mweb_fee` and `MAX_MONEY` checked arithmetic; `merge_mweb_history` uses `unsigned_abs()`; `verify_replacement_target` verifies sender, recipient, value, nonce, and empty calldata on LitVM replacements; and `ui/src/amounts.ts` enforces `MAX_MONEY_SATS` and strict `,ddd` grouping |
| — | L | `build_public_split_psbt`, `sign_pegout` (`per_coin`), `prepare_transfer_broadcast`, `sign_mweb_split`, and `sign_self_spend_hops` revealed and persisted up to 50 external or MWEB receive indices before funding and signing succeeded, so repeated failed builds could advance derivation indices past `STOP_GAP = 50` | Builders peek candidate addresses/indices first and advance/persist derivation indices only after building, signing, and invariant checks succeed |

## Fixed with the Electrum SPV checks

| # | Sev | Finding | Fix |
| --- | --- | --- | --- |
| — | H | `apply_electrum_chain_update` applied `bdk_electrum`'s update as served. Its anchors come from `electrum_client::utils::validate_merkle_proof` (pin `6ffa5afa`), which only recomputes the root against the header the same server returned. It accepts a 64-byte inner node posing as a leaf (CVE-2017-12842), a duplicated left sibling (CVE-2012-2459), and an out-of-range position, and no header was checked for scrypt proof-of-work, target, or `prev_blockhash`. A lying server could confirm a coin that was never mined | `spv::sync_electrum_spv` verifies headers (genesis, scrypt PoW, `SetCompact` targets capped at `powLimit`, Litecoin retarget and Testnet4 min-difficulty, links, fork work) and hardened merkle branches before `apply_update`. Any failure fails the sync and leaves the wallet unchanged |
| — | M | A server behind the local tip, or on a competing fork, rolled the wallet's chain to its view | Lagging servers are refused. A fork is accepted only with strictly more cumulative work from the fork point, within 2160 blocks |
| — | M | Raw transactions from Electrum, and peg-in repair bytes from Electrum, RPC, or the explorer, were applied without checking they were the requested transaction | `spv::verify_transaction` checks the txid, duplicate inputs, `MAX_MONEY`, and 64-byte transactions. Peg-in repair tries the next source when one fails |
| — | M | Unconfirmed transactions only the previous server reported stayed in the graph after the user switched servers | `electrum_spv.json` tracks them per server. `update_settings` evicts them on a switch, keeping peg-ins and spends of our own coins |
| — | L | The server that served a sync was remembered before the sync was checked, and Settings' Test connection accepted any genesis | The server is remembered only after a verified sync and forgotten on failure. `probe_tip` checks genesis and tip proof of work |
| — | M | `collect_unspent` and `mweb::public_coin_status` did not check `CanonicalTxOut::is_mature(tip)`, and manual selection in `build_send_psbt`, `public_split_utxo`, and `resolve_pegin_request` (plus `selectable_public_utxo_amounts`) accepted HogEx peg-out outputs at 1–5 confirmations and coinbase outputs below 100 confirmations (`bad-txns-premature-spend-of-pegout`) | `public_utxo_maturity` queries `CanonicalTxOut::is_mature(tip)`, `public_coin_status` marks confirmed immature coins `Maturing` with all spend/select/freeze flags off, and transparent send, split, transfer, and peg-in paths refuse immature outpoints |

## `bdk_mweb` security hardening pass

`LitecoinDevKit/bdk` has been through a security pass covering `crates/mweb`
(the plan and findings are in that repo's `docs/SECURITY_PLAN.md`). This repo
carries the wallet half of it, and the `bdk.git` rev pinned in
`crates/wallet-core/Cargo.toml` includes that work (it entered at
`d8e220c2…`). The pin cannot move back: the wallet-side code below does not
compile against an earlier `bdk`.

What the pin move changes for this repo:

| Change in `bdk_mweb` | Effect here |
| --- | --- |
| `VerifyMode` default flips from `HeaderAndPmmr` to `Anchored` | `MwebSyncer::tip_only()` now requires each `mwebheader` to be bound to its block through the HogEx commitment. This is a real behaviour change: a peer serving an internally consistent but invented MWEB chain used to pass. Escape hatch during rollout: `BDK_MWEB_VERIFY_MODE=header-and-pmmr`. It cannot select `Trusted`, so it is not a way to switch verification off |
| v2 seal envelope (`SealContext`, magic, version, counter as AAD) | Adopted in `crates/wallet-core/src/mweb.rs`: each of the four MWEB blobs is sealed under its own context, so `mweb_history.enc` can no longer be substituted for `mweb_coins.enc`. Legacy blobs still open; the next `persist` rewrites them as v2 |
| `MwebCoin` gains `Drop`, redacted `Debug`, constant-time `PartialEq` | No source change needed. Secrets no longer appear in `{:?}` output |
| `MasterKeys` gains `Drop` and a redacted `Debug` | No source change needed |
| Peer-facing decode bounds, framing caps, liveness fixes | No source change needed |
| `BanReason::Throttled`, and a UTXO batch widened to 4096 (F-21) | litecoind 0.21.5.6 meters MWEB serving node-wide and silently drops what it will not serve, which used to look exactly like a dead peer. `crates/wallet-core/src/mweb.rs` now keeps `bdk_mweb::Error` typed as far as `classify_pass_failure`, which stops reporting a metered peer as "unreachable" and, more importantly, stops the fallback to DNS-discovered peers in that case: those share the same limit and would see queries the user's own node keeps private. The sync itself is unchanged — `bdk_mweb` re-issues dropped requests — so a throttle only surfaces here when the peer serves nothing at all |

### Rollback detection is partial

The v2 envelope carries a monotonic counter, and `persist` writes the same
counter into all four MWEB blobs plus `mweb_seal_counter.txt`. That makes a
*partial* rollback detectable — restoring only `mweb_coins.enc` from an older
backup while sync state and history stay current. It does **not** detect a
rollback of the whole data directory, because the counter file rolls back with
it. Closing that needs the high-water mark inside the Argon2-sealed secrets
blob, which means a v3 secrets format. Tracked as O12 below.

## Open findings (deferred — future work, external-audit scope)

| # | Sev | Finding | Suggested direction |
| --- | --- | --- | --- |
| O1 | L | The transparent-side `wallet.sqlite` (BDK database) is unencrypted at rest (addresses/history, not keys); MWEB data and the seed are sealed | Requires SQLCipher or a custom BDK persistence backend; document FileVault/LUKS reliance meanwhile |
| O5 | L | Mnemonic crosses the IPC boundary as a plain `String` on create/restore and lives in webview memory until backup confirm | Inherent to showing the phrase for backup; keep the DOM-clear behavior; consider a native reveal window later |
| O7 | I | No Tor/proxy support; DNS-seed MWEB discovery reveals the user's IP | Roadmap item |
| O8 | I | Builds are not bit-for-bit reproducible (`.dmg`/`.AppImage` timestamps, toolchain drift) | Pin toolchain everywhere (done in workflows), strip timestamps, publish build environment details. Build provenance attestations partially compensate |
| O9 | I | Release workflow does not require green CI on the same commit before building | Protect the `release` branch with required status checks |
| O10 | I | macOS releases unsigned until Apple Developer credentials exist | CI signing is already drop-in; enroll and add the six secrets |
| O11 | I | Electrum tip cross-check compares headers only; individual mempool transactions can still be hidden by the sync server until confirmed | Full script-level cross-checking would leak addresses to a second server; revisit with Tor support |
| O12 | L | Whole-directory rollback of the sealed MWEB files is undetectable: the v2 envelope counter is checked against `mweb_seal_counter.txt`, which an attacker rolls back alongside the blobs | Move the high-water mark into the Argon2-sealed secrets blob (a v3 secrets format), so reverting it requires the passphrase. Partial rollback is already detected |
| O13 | L | SPV verifies the last 2016 headers, not the chain from genesis, and ships no checkpoints. A fresh wallet, or one far behind, accepts the window's first header with only a proof-of-work and `powLimit` check, so a server able to mine 2016+ headers at minimum difficulty could present an invented recent chain. Anchors below the window are checked against isolated headers (proof of work only) | Ship signed header checkpoints, or verify from the last checkpoint forward; cross-check the verified window with a second server's headers |
| O14 | I | Eviction keeps any unconfirmed transaction that spends our own outputs; a server could keep a fake spend of our coins with an invalid signature visible, because scripts are not verified | Verify input scripts of unconfirmed spends of our coins, or drop server-only spends after a timeout |

## Scope notes for a future third-party audit

1. **Treat the sibling forks as primary targets**: `LitecoinDevKit/bdk`
   (`crates/mweb` especially), `bdk_wallet`, `rust-litecoin`,
   `rust-electrum-client`, `rust-miniscript` at the revs pinned in the Cargo
   manifests / `Cargo.lock`. All consensus and MWEB cryptography lives there,
   not in this repo.
2. Priority order inside this repo: `crates/wallet-core/src/secrets.rs`,
   `seed.rs`, `aezeed.rs`, `descriptors.rs`, `mweb.rs`, `electrum.rs`,
   `rpc.rs`, `discovery.rs`, then the Tauri command surface
   (`src-tauri/src/lib.rs`) and `ui/src/main.ts`.
3. Freeze a tag before the engagement; the pins file makes the full source
   tree reproducible for the auditors.

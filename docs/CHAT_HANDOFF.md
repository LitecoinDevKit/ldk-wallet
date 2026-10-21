# Chat handoff — Litecoin Mac wallet (v0.4.7)

Paste or `@`-reference this file when starting a new Cursor chat in this repo.

## Decision summary

- **Product:** Native Mac Litecoin wallet (Tauri 2 + Rust core + web UI).
- **v0.1:** Transparent BIP84 (receive / sync / send / history). Encrypted mnemonic at rest.
- **v0.2:** MWEB via `bdk_wallet` `mweb` + `bdk_mweb` + LIP-0006 peer (peg-in, private send, peg-out).
- **Sync backend (transparent):** Electrum-LTC first.
- **MWEB sync:** LIP-0006 P2P to archive litecoind (not Electrum). Pure MWEB broadcast requires litecoind RPC; track **wtxid**.
- **Library deps:** Path-dep sibling checkouts:
  - `../bdk` (`LitecoinDevKit/bdk`, branch `litecoin`)
  - nested `../bdk/bdk_wallet`
  - `../rust-litecoin` via workspace `[patch]`
  - `../grail-sdk-rust` (unofficial Grail client; LiteForge only; not a CI path-dep — uncomment in `wallet-cli` locally)
- **Alias rule:** Cargo `bitcoin` → `litecoin` crate.
  - Litecoin **mainnet** = `Network::Bitcoin`, BIP84 coin type **`2`**
  - Litecoin **testnet** = `Network::Testnet4`, coin type **`1`**
- **Boundary:** UI/Tauri never see BDK types. `wallet-core` exposes serde DTOs only.
- **Secrets:** Argon2id + ChaCha20-Poly1305 `wallet.mnemonic.enc` (legacy plaintext migrated on unlock). Mode `0600`. Never store mnemonic in SQLite.
- **Concurrency:** Electrum/BDK/MWEB calls are blocking → `spawn_blocking` + `Mutex<WalletState>`.
- **UX:** No optimistic balance after send — sync, then refresh. Amounts in LTC (string decimal → litoshis). Dust floor ~2940 litoshis for `ltc1`. Auto-sync every 60s (status-line errors only).
- **LitVM:** Sidecar crate `wallet-litvm` (alloy), same seed `m/44'/60'/0'/0/0`, LiteForge presets in `litvm.json`. Testnet-only until official mainnet params. See [`docs/LITVM.md`](LITVM.md).
- **Grail:** Sibling `grail-sdk-rust` — verify-before-fund, no invented leaf. `wallet-cli grail-verify --offer`. `grail-deposit` stubbed until a captured offer verifies. No Tauri UI. No mainnet.

## Default endpoints

| Network | Electrum |
| --- | --- |
| mainnet | `ssl://electrum-ltc.bysh.me:50002` |
| testnet | `ssl://electrum-ltc.bysh.me:51002` |

MWEB peers default to empty (DNS auto-discovery). A sole `127.0.0.1:9333` leftover from older builds is cleared on meta load. Electrum TLS certificate validation is on by default (cipig.net defaults have CA certs); the self-signed community servers need the Settings toggle off.

## `wallet-core` surface

- `exists` / `create` / `restore` / `load` / `wipe`
- `unlock` / `lock` / `migrate_encrypt` / `is_locked` / `needs_migration`
- `sync` (transparent + best-effort MWEB tip sync)
- `summary` / `combined_summary` / `receive_address` / `mweb_receive_address`
- `transactions` / `send` (optional `drain`)
- `settings` / `update_settings` (includes `explorer_base_url`, `show_fiat`, `use_explorer_fee_hints`)
- `explorer_tx_url` / `open_explorer_url` / `fetch_tx_detail` / `fetch_spot_price` / `fetch_fee_ladder`
- Insights (litview): `fetch_network_pulse` / `fetch_insight_charts`
- `get_tx_labels` / `set_tx_label` / `export_history`
- `list_contacts` / `upsert_contact` / `delete_contact`
- `list_unspent` / `list_mweb_unspent` / `set_utxo_locked` / `set_mweb_utxo_locked` / `set_utxo_label` (Public + Private coin control; `SendRequest.selected_outpoints`; `MwebSendRequest` / `PegoutRequest.selected_output_ids`)
- `preview_split` / `split_coin` (Coins → 1-in-N-out self-split; Public + MWEB; `TxKind::Split` / `MwebSplit`)
- `preview_pegout` / `pegout`: typed amount stays 1 HogEx output; Max / chosen coins are **N-to-N** (one fresh `ltc1` per private coin, fee from the largest). History is still one peg-out entry.
- `export_metadata_json` / `import_metadata_json` (contacts + tx/utxo labels + split txids + frozen MWEB ids; merge on import)
- `test_electrum` / `default_electrum_urls`
- `pegin` / `mweb_send` / `pegout` / `resync_mweb`

## Peg-in UX model

Peg-in is a **self-transfer** from the wallet’s own transparent UTXOs. Exchanges fund the normal `ltc1` address; the app then offers “Move to private (peg-in)”. Maturity: 6 blocks.

## Screens

Boot → Unlock | Migrate | Onboarding → Mnemonic backup → verify quiz → Home (balance, QR, send, history, Insights, MWEB, settings).

## UX backlog ([`docs/UX_REVIEW.md`](UX_REVIEW.md))

- **Done (P0):** Hard-gated recovery-phrase quiz after create; wallet passphrase minimum 8 chars + strength meter on Create/Migrate/Restore; first-funds backup banner for unverified/legacy installs; send/swap review shows full destination, type badge, total leaving wallet, and high-fee warning (≥50% of amount).
- **Done (P1):** Public/Private first-use coach (`ltc-mweb-coach-seen`); empty-wallet funding CTA → Public Receive; peg-in maturity as spendable vs maturing (+ unconfirmed private, History maturing pill); Swap dual-fee labels + MWEB “no explorer” success copy / kind-aware litview; progressive security checklist at ≥1 LTC (`ltc-security-checklist-dismissed`).
- **Done (P2):** Display unit LTC|litoshis (`ltc-display-unit`, Settings + hero tap); Public BIP21 amount/label QR + copy payment link + Send URI parse; fee chips time labels + Economy + custom sat/vB + `estimate_fee` when explorer hints off; receive toast/history pulse + first-receive modal (`ltc-first-receive-seen`).
- **Done (P3):** Hide balances (`ltc-hide-balances`, Settings + hero LTC→litoshis→hidden); send-side transparent reuse warn via `address_reuse_hint` (warn-only; Private never warns); Settings “What leaves this computer” panel; tx labels in wipeable `tx_labels.json` sidecar (confirm note + History/detail edit).
- **Done (P4 shippable):** History search/filter + CSV/JSON export; contacts (`contacts.json`, name + one address + Public/Private, Send picker); Public coin control for Send and Public→Private Swap (`list_unspent`, freeze, opt-in `selected_outpoints`).
- **Done (feat/private-coin-control):** Coins Private freeze/labels; Send private and peg-out coin pickers (`selected_output_ids`); frozen coins skipped by automatic MWEB selection.
- **Done (post-competitive M2–M4):** Broadcast failure recovery modal; persistent Electrum/MWEB status strip; UTXO labels + change warning; Coins nav; metadata export/import; Electrum presets + test connection. Live E2E checklist [`MWEB_E2E.md`](MWEB_E2E.md); notarization runbook [`NOTARIZATION.md`](NOTARIZATION.md).
- **Done (feat/denomination-split):** Coins Public/Private lists; Split modal (equal + preset denominations) as 1-in-N-out self-transfer. Simple Send stays single-recipient.
- **Done (feat/n-to-n-pegout):** Swap → Public Max / Choose coins emit one HogEx output per private coin (one kernel, fee from largest). Typed amount with no coins picked stays 1-out.
- **Done (feat/mweb-churn):** Coins → Spend to self. One private coin, one confirmed block per hop, counted only when the inclusion headers show the block was not ours alone. See [`docs/CHURN.md`](CHURN.md).
- **Next (P4 deferred):** Multi-wallet, hardware wallets, Tor/proxy — future architecture.

## Implementation status

1. ~~wallet-core BIP84 + CLI + Tauri + UI polish + mainnet default~~
2. ~~Usability: history, LTC amounts, send-max, auto-refresh~~
3. ~~Hardening: encrypted mnemonic, Electrum settings~~
4. ~~Packaging prep: icon, bundle metadata, entitlements, release docs~~
5. ~~MWEB store + tip seam + peg-in/send/pegout commands + UI~~
6. Live MWEB E2E against archive peer + RPC ([`docs/MWEB_E2E.md`](MWEB_E2E.md)); notarized ship ([`docs/NOTARIZATION.md`](NOTARIZATION.md))
7. UX P0 fund-loss safety (backup verify, passphrase gate, send confirm)
8. UX P1 MWEB comprehension (coach, funding CTA, maturity, Swap fees/explorer, security checklist)
9. UX P2 payment polish (units, BIP21, fee clarity, receive feedback)
10. UX P3 privacy hardening (hide balance, reuse warn, disclosure, labels)
11. UX P4 shippable (history search/export, contacts, Public coin control)
12. LitVM Phase 0–2 ([`LITVM.md`](LITVM.md)): `wallet-litvm` crate, LiteForge receive/send, history, custom RPC. Grail: unofficial sibling SDK + CLI verify; in-app peg / mainnet not started.

## Litview / LRK / Insights

First-party explorer at [litview.space](https://litview.space). Design and privacy
matrix: [`docs/LITVIEW.md`](LITVIEW.md). Deep links + enrichment/price/fees + Insights
(pulse, charts) via Rust `ureq`; never scan wallet addresses against litview.

## Out of scope (still)

Multi-peer UTXO-omission detection, embedded litecoind, hardware wallets, fine-window sync in UI, universal binary.
Grail in-app / mainnet peg, WalletConnect, ERC-20, x402.

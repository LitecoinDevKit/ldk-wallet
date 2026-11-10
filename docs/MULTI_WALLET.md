# Multi-wallet from one seed

Living design for BIP84 account-indexed wallets that share a single encrypted
mnemonic. `@`-reference this file when changing layout, derivation, or the
wallet switcher.

## Status

**Implemented (single-seed accounts).** Multi-seed profiles, hardware wallets,
Tor/proxy, and restore-time account gap-scan remain deferred.

## Non-goals (this revision)

- Separate seeds or passphrases per wallet
- Automatic discovery of used account indices on restore
- Hardware wallets / multi-key
- Tor or app-wide proxy

## Threat and privacy model

Each wallet is a BIP32 **account** under one master seed. On-chain (and MWEB /
LitVM) keys diverge by account index so tip-jar activity does not reuse the
same addresses or scan keys as savings.

Compromise of the recovery phrase still unlocks **every** wallet. Isolation is
for privacy and bookkeeping, not custody separation. Prefer a separate seed
(future) when wallets must not share that fate.

## On-disk layout

```text
data_dir/
  wallet.mnemonic.enc       # shared seed (Argon2id + ChaCha20-Poly1305)
  wallet.mnemonic           # legacy plaintext; migrate-on-unlock
  accounts.json             # registry + active_index
  accounts/
    0/
      wallet.sqlite
      wallet_meta.json      # includes account_index
      mweb_*.enc / mweb_seal_counter.txt
      litvm.json
      contacts / labels / churn / …
    N/
      …
```

- **Seed-scoped:** mnemonic files at the data-dir root; one unlock unlocks all
  wallets for the session.
- **Wallet-scoped:** everything under `accounts/N/` (transparent DB, MWEB,
  LitVM settings, contacts, labels, coin control, churn).

### Migration

If `data_dir/wallet.sqlite` exists and `accounts/` does not, move flat state
files (including `litvm.json` and `mweb_seal_counter.txt`) into `accounts/0/`,
write `accounts.json` with wallet 0 named `Personal`, and leave the mnemonic at
the root. Idempotent; safe to run on every load.

### Wipe

Wipe is **global**: delete mnemonic, `accounts.json`, every `accounts/N/`, and
any leftover flat files (including `mweb_seal_counter.txt`).

### Exists

A wallet exists when the encrypted (or legacy) mnemonic is present, or when any
`accounts/*/wallet.sqlite` (or legacy root `wallet.sqlite`) is present.

## Derivation

Account `0` paths are byte-compatible with pre-multi-wallet builds.

| Domain | Account 0 | Account N≥1 |
| --- | --- | --- |
| BIP84 | `m/84'/coin'/0'/{0,1}/*` | `m/84'/coin'/N'/{0,1}/*` |
| MWEB LitecoinCore | `m/0'/100'/{0,1}'` | `m/N'/100'/{0,1}'` |
| MWEB mwebd | `m/1000'/2'/0'/{0,1}'` | `m/1000'/2'/N'/{0,1}'` |
| LitVM | `m/44'/60'/0'/0/0` | `m/44'/60'/N'/0/0` |

`coin` is `2` on Litecoin mainnet and `1` on testnet.

Transparent descriptors use `P2Wpkh((master_xprv, path))` with the full BIP84
path (BDK’s `Bip84` template hardcodes account `0'`). MWEB always derives from
the **depth-0** master with account-aware scan/spend paths (never an
account-level xprv).

DTO `MwebScheme::Lip0004` continues to follow the implemented Core path (same
as LitecoinCore).

## Lifecycle

| Action | Behavior |
| --- | --- |
| Create / restore | Write seed at root; create wallet **0** only; set active to 0 |
| Add wallet | Next free index; new `accounts/N/`; copy settings from active; switch |
| Switch | Drop in-memory state; load that account dir; reattach LitVM; no re-prompt while unlocked |
| Rename | Update `accounts.json` display name |
| Delete | Refuse if last wallet; remove `accounts/N/`; if deleting active, switch first |
| Unlock / lock | Seed-level; lock clears all in-memory wallet state |
| Wipe | Entire device wallet (all accounts + seed) |

Restore does **not** scan for used accounts; the user adds wallets explicitly.

## API surface

`WalletApp` (root `data_dir` on each call):

- `list_wallets` → `{ index, name, is_active }[]`
- `create_wallet_account(name)`
- `switch_wallet(index)`
- `rename_wallet(index, name)`
- `delete_wallet(index)`
- `preview_transfer_coin` / `transfer_coin` (see Inter-wallet transfer)
- Existing `create` / `restore` / `load` / `wipe` / `exists` / unlock

Tauri mirrors these commands. LitVM `attach` uses `accounts/N` and
`litvm_account_secret(N)`.

CLI: `derive --account N` for address parity checks.

## UI contract

- Header wallet switcher (name + index): switch, add, rename, delete (not last).
- One recovery phrase backs all wallets; switching while unlocked does not ask
  for the passphrase again.
- No combined balance across wallets.
- Wipe remains “erase this device.”

## Inter-wallet transfer

From Coins (Public or Private) → **Transfer to…** moves **one coin** to another
account under the same seed. Same chain only (no auto peg-in/out).

- Public: drain the selected outpoint to a fresh `ltc1` receive on the dest account.
- Private: drain the selected MWEB output to a dest stealth address.
- Destination address is revealed on the **target** account without switching the
  active wallet (preview peeks; broadcast commits).
- The source wallet stays active after broadcast.
- Disabled when frozen, unconfirmed/immature, fewer than two wallets, or when an
  active self-spend holds this coin. Send, Split, and Transfer stay disabled only
  for that coin. Other coins can be broadcast while the hop is signed, waiting,
  or unconfirmed.

APIs: `preview_transfer_coin` / `transfer_coin`
`{ chain, coin_id, to_account_index, fee_rate_sat_vb?, fee_sats }`.

## Test vectors

1. **Account-0 parity:** descriptors / peek addresses for account `0` match
   stock BDK `Bip84` for the same master.
2. **Divergence:** account `1` receive address ≠ account `0` for the same seed.
3. **Migration:** flat `wallet.sqlite` + sidecars move under `accounts/0/` and
   load with the same receive address.
4. **CLI:** `wallet-cli derive --account 0` vs `--account 1` on a fixed mnemonic.

## Related docs

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — overall app shape
- [`CHAT_HANDOFF.md`](CHAT_HANDOFF.md) — decision summary
- [`UX_REVIEW.md`](UX_REVIEW.md) — P4-4 multi-wallet
- [`LITVM.md`](LITVM.md) — LitVM sidecar (per-account path)

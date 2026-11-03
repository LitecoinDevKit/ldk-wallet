# LitVM sidecar (planned)

Living plan for a LitVM EVM account beside L1 + MWEB. `@`-reference this file
when implementing. Phase 0–2 is in the tree (`crates/wallet-litvm`, LitVM nav).

Official docs: [docs.litvm.com](https://docs.litvm.com/). Testnet hub:
[testnet.litvm.com](https://testnet.litvm.com).

## Status

**Phase 2 (LiteForge read/write + history + custom RPC) · mainnet TBA · Grail SDK sibling started (unofficial)**

Last verified: 2026-08-15. Live probe: `eth_chainId` on
`https://liteforge.rpc.caldera.xyz/http` returned `0x1159` (4441). Explorer
`https://liteforge.explorer.caldera.xyz` returned HTTP 200. WebSocket still
unconfirmed. Blockscout `account/balance` works; `txlist` may be flaky — the
wallet treats an indexer miss as empty history plus “open explorer”, and
overlays a just-sent tx locally until the indexer lists it.

## Locked decisions

- Separate workspace crate `wallet-litvm` (alloy, not ethers-rs). Feature flag
  `litvm`. Do not pull alloy types into `wallet-core` or the BDK/`litecoin`
  crate graph.
- Same BIP39 seed as L1. Derivation `m/44'/60'/{account}'/0/0` (MetaMask/Rabby
  account index; wallet 0 is the default). Settings live under `accounts/N/litvm.json`.
  Same passphrase lock and wipe as the L1 mnemonic. See [`MULTI_WALLET.md`](MULTI_WALLET.md).
- Tauri IPC stays serde string DTOs (`0x` address, decimal zkLTC). No
  `alloy::primitives` across the boundary.
- Signing **chain ID is hardcoded per network preset**. Do not use the RPC
  `eth_chainId` response as the signature chain ID.
- zkLTC never enters the hero LTC balance or MWEB / Public coin-control
  selectors.
- UI is vanilla TS in `ui/src/main.ts` (not React).
- History is Blockscout `txlist` only. Native zkLTC transfers between EOAs do
  not emit logs, so `eth_getLogs` is blind to them. `txreceipt_status == "0"`
  is failed, not pending.
- Two-layer fee cap: per-gas headroom (`MAX_FEE_GWEI = 10_000`) for Orbit’s
  L2 + L1-calldata spike, plus a **total** drain brake
  (`gas_limit * max_fee_per_gas ≤ 0.05 zkLTC`). Congestion vs hostile-RPC
  errors are distinct.
- Same-nonce speed-up loads the in-mempool tx and bumps both EIP-1559 fields
  by at least 12.5% (`ceil(old * 1125 / 1000)`), then `max` with a fresh
  estimate. A receipt means “already confirmed”.
- Mixed-case `0x` addresses are EIP-55 checksummed. All-lower / all-upper
  are accepted without a checksum.
- Grail in-app peg is still gated on an official lock-script spec and operator
  MuSig2 params. Unofficial sibling `../grail-sdk-rust` implements
  verify-before-fund only (LiteForge). Do not invent a TapTree leaf. Do not
  pay an offer that returns `UnverifiedTree`. No mainnet.

## Network is data

Code against a `LitVmNetwork` record. LiteForge is the first row. Mainnet is a
second row added when official params exist — not a rewrite.

| Field | Meaning |
| --- | --- |
| `id` | `"liteforge"` \| `"mainnet"` |
| `display_name` | UI label |
| `chain_id` | `u64` used for EIP-155 signing |
| `rpc_http` | JSON-RPC HTTP |
| `rpc_ws` | optional WebSocket |
| `explorer` | block explorer base URL |
| `history_api` | optional Blockscout-style tx list |
| `symbol` | native ticker |
| `decimals` | EVM decimals (18) |
| `faucet_url` | testnet only |
| `signing_enabled` | `false` until a live `eth_chainId` probe matches |

Defaults live in Rust (same pattern as Electrum presets). Settings: preset +
optional user RPC override.

| | LiteForge (testnet) | Mainnet |
| --- | --- | --- |
| `id` | `liteforge` | `mainnet` |
| Display | LitVM LiteForge | TBA |
| Chain ID | `4441` (`0x1159`) | TBA |
| Symbol / decimals | zkLTC / 18 | TBA / 18 |
| HTTP RPC | `https://liteforge.rpc.caldera.xyz/http` (probed) | TBA |
| WebSocket | `wss://liteforge.rpc.caldera.xyz/ws` (unconfirmed) | TBA |
| Explorer | `https://liteforge.explorer.caldera.xyz` (HTTP 200) | TBA |
| History API | Blockscout `?module=account&action=txlist` (may 500) | TBA |
| Faucet | `https://testnet.litvm.com` | — |
| `signing_enabled` | after live `eth_chainId == 4441` | after official params + probe |

## Phases (gates, not dates)

| Phase | Ship when | Work |
| --- | --- | --- |
| **0 Boundaries** | Done | `wallet-litvm` crate, feature flag, DTOs, derive `0x` from mnemonic. |
| **1 LiteForge read/write** | Done (probed `0x1159`) | Balance, receive QR, native send, fee cap, `0x` vs `ltc1` guard, persistent testnet banner. |
| **2 Polish on testnet** | Done | History API, custom RPC, stuck-tx / same-nonce replace (12.5% over the pending tx). Not blocked on mainnet. |
| **3 Mainnet enable** | Official chain ID + RPC + explorer published **and** live probe matches | Add preset, default new installs to mainnet, keep LiteForge as advanced. |
| **4 Grail** | Official lock-script spec + operator params; captured LiteForge offer verifies | Sibling `grail-sdk-rust` + `wallet-cli grail-verify` / stubbed `grail-deposit`. No Tauri UI yet. |

### Mainnet enable checklist

- Official chain ID, HTTP RPC, explorer, symbol published (not a recap blog).
- Live `eth_chainId` equals the published ID.
- `eth_getBalance` / `eth_estimateGas` / `eth_sendRawTransaction` work on a
  throwaway key.
- History API works, or accept “open in explorer” only.
- Fee-cap constants re-checked (Orbit L1+L2 fees will differ on mainnet).
- UI: remove faucet / LiteForge-only copy; warn that L1 LTC ≠ zkLTC.
- Release: `litvm` feature on in the notarized build only after the above.

## Product constraint

Phase 1 is a **testnet L2 hanging off a mainnet L1 seed** (different derivation
paths). Fine cryptographically; dangerous socially.

Until Phase 3:

- LitVM surface shows a persistent **LiteForge testnet** banner and faucet link.
- Do not add zkLTC into the hero / combined LTC balance.
- Settings “What leaves this computer” must mention the Caldera RPC (IP +
  address leak), same spirit as the Electrum disclosure.

Send validation: L1 fields reject `0x…`; LitVM fields reject `ltc1` / `M` / `L`.
Point the user at the other network instead of constructing a tx.

## Non-goals

WalletConnect, dapp browser, ERC-20 / USDC, x402 / agent payments, MetaMask
embedding, inventing a Grail TapTree leaf, merging LitVM into MWEB coin control.

## E2E (LiteForge)

1. Unlock an existing wallet; derive `0x` from the same mnemonic at
   `m/44'/60'/0'/0/0`.
2. Request faucet zkLTC at [testnet.litvm.com](https://testnet.litvm.com).
3. Balance poll reflects the faucet.
4. Send native zkLTC to a second `0x` address.
5. Confirm on the LiteForge explorer.

## Open questions

| Question | Why it matters |
| --- | --- |
| WebSocket `wss://liteforge.rpc.caldera.xyz/ws` | Subscribe vs HTTP poll + rate limits |
| Public RPC rate limits | Backoff in the HTTP transport |
| Grail SDK / lock-script spec | Sibling `grail-sdk-rust` started; leaf still unknown — capture initiate/confirm JSON (`../grail-sdk-rust/docs/CAPTURE.md`) |
| L1 deposit address format (P2TR vs P2WPKH) | Whether BIP84 is enough for a later peg |

## Refresh

Edit the network table when official mainnet params ship, LiteForge URLs move,
or Grail status changes. Re-run a **narrow** params probe (chain ID, RPC,
explorer, faucet, Grail SDK). Do not re-run a full ecosystem brief. Leave locked
decisions alone unless derivation or Grail readiness actually changed.

Quarterly is enough if nothing was announced: `eth_chainId` on the HTTP URL,
open the explorer, check the mainnet row on [docs.litvm.com](https://docs.litvm.com/).

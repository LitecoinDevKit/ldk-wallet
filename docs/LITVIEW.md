# Litview / LRK integration

First-party companion to [litview.space](https://litview.space) (sibling checkout
`../lrk`, Litecoin Research Kit). BDK / `wallet-core` remains the wallet; LRK
stays a remote chain index + explorer. The wallet does **not** embed the LRK
indexer or copy the `website_next` SPA.

## Architecture

```text
ui  --invoke-->  src-tauri commands  -->  wallet-core
                                            |-- Electrum / MWEB (BDK)
                                            '-- ureq HTTPS --> litview or self-host
ui  --open_explorer_url-->  system browser  -->  {explorer}/explorer/tx/{txid}
                                         or  -->  {explorer}/explorer/block/{height|hash}
                                         or  -->  {explorer}/studio/#chart={json}
```

- All litview HTTP goes through Rust (`ureq`). WebView CSP stays IPC-only
  (`connect-src` does not include litview).
- Deep links open in the OS browser; the WebView never navigates to litview.
- Explorer and Insights settings live on `WalletMeta` / `WalletSettings`.

## Privacy matrix

| Action | Trigger | What litview learns | Default |
| --- | --- | --- | --- |
| “View on litview” | User click | IP + txid (browser) | Button visible |
| Tx enrichment `GET /api/tx/{txid}` | User opens tx detail | IP + that txid | On when detail opens; in-session cache |
| Spot price `GET /api/oracle/price` | Auto while unlocked (~60s), and before a USD send | IP only | On; Settings toggle |
| Fee ladder `GET /api/v1/fees/recommended` | Send form / preview | IP only | On; chips are suggestions |
| Insights pulse (tip, price, fees, mempool) | Auto while unlocked (~90s) when Insights on | IP only | On; Settings `insights_enabled` |
| Insights charts `GET /api/series/…` | Insights view open / refresh | IP only | On with Insights |
| Tip height cross-check | Automatic | IP only | Deferred (Electrum header check exists) |
| Address / xpub scan | — | IP + address set | **Never** |

Wallet addresses are never uploaded. When enrichment returns vin/vout, the
wallet marks `is_wallet` locally by matching revealed SPKs.

## API surface

Settings (serde defaults for older wallets):

- `explorer_base_url` — default `https://litview.space`
- `show_fiat` — default `true`
- `use_explorer_fee_hints` — default `true`
- `insights_enabled` — default `true`

Helpers / commands:

- `explorer_tx_url(txid)` / `explorer_block_url(hash)` — `/explorer/tx/…` and
  `/explorer/block/…`, no network
- Insights chart cards open `/studio/#chart=` with the chart's series; “Open
  litview” opens `/studio/`; the status-strip block opens `/explorer/block/{height}`
- `open_explorer_url(url)` — OS browser
- `fetch_tx_detail(txid)` → `TxEnrichment` from `/api/tx/{txid}`
- `fetch_spot_price()` → `/api/oracle/price`
- `fetch_fee_ladder()` → `/api/v1/fees/recommended`
- `fetch_network_pulse()` → tip + price + fees + mempool
- `fetch_insight_charts()` → allowlisted `/api/series/{name}/day1` windows

Hand-rolled GETs against the mempool.space-compatible JSON and LRK series API;
no `brk_client` dep.

## Phases

1. **Deep links** — Settings base URL, “View on litview”, SECURITY note.
2. **Enrichment** — vin/vout in tx modal, wallet highlighting, soft fail.
3. **Price + fee hints** — USD under balance, fee chips on send, toggles.
4. **Insights** — Balance pulse + Insights nav (charts).

## Non-goals

- Embedding LRK / Litecoin Core / `BrkClient` in the WebView
- Porting the full litview explore cube, Learn catalog, mining pools UI, or
  Wallets address scan
- Address history from litview, litview tip cross-check, Tor for explorer traffic
- In-app news feeds, X integration, or LLM / AI analysis

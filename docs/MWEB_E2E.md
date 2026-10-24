# LDK Wallet — live MWEB end-to-end checklist

Operator checklist for proving v0.2 MWEB against a live archive peer + litecoind RPC.
Library-level loops live in the sibling BDK repo ([`LITECOIN_E2E.md`](../../bdk/docs/LITECOIN_E2E.md),
[`MWEB_PEER_OPS.md`](../../bdk/docs/MWEB_PEER_OPS.md)). This document is the **desktop product** gate.

## Prerequisites

- [ ] Archive litecoind with MWEB + LIP-0006 (`initialblockdownload=false`, P2P accepting peers)
- [ ] JSON-RPC reachable (cookie or `user:pass` URL) — required for pure MWEB broadcast fallback
- [ ] Electrum-LTC reachable for transparent sync
- [ ] Fresh test wallet (or throwaway amounts) on the target network
- [ ] App Settings: MWEB peer(s) and Litecoin RPC URL configured; Sync succeeds

## Broadcast identity rules

- Transparent / peg-in (hybrid): track **txid**; litview deep links OK when chain txid.
- Pure MWEB send / peg-out: track **wtxid** (empty-skeleton `txid` collides). App result modal shows the id returned by `wallet-core`.
- If Electrum rejects MWEB payloads (“decode failed”), RPC/P2P path must succeed with humanized Settings CTA.

## Checklist

### 1. Transparent baseline

- [ ] Create or restore wallet; backup quiz / unlock works
- [ ] Sync: status strip shows Electrum tip; no persistent error
- [ ] Receive Public → fund small amount → appears after sync (pending then confirmed)

### 2. Peg-in (Public → Private)

- [ ] Swap → Move to private; preview shows miner fee + MWEB fee
- [ ] Broadcast succeeds (txid); History shows peg-in **maturing** until 6 confs
- [ ] Combined balance: maturing vs spendable Private correct
- [ ] Optional: coin control selection + freeze respected

### 3. Private send (MWEB → MWEB)

- [ ] After maturity, Send Private to a known stealth address (or self)
- [ ] Result id is **wtxid**; success copy does not imply explorer lookup
- [ ] Balance updates after sync; no silent zeroing

### 4. Peg-out (Private → Public)

- [ ] Swap → Move to public; broadcast via P2P and/or RPC
- [ ] Transparent balance increases after HogEx credit visible to Electrum sync
- [ ] History labels peg-out correctly

### 5. Spend to self (Coins → Private)

- [ ] Coins → Private list is scannable: amount + attention chip + short status only; no unknown-depth line, hop dump, or full output id on collapsed rows
- [ ] Action column is one line tall (Spend to self + More side by side when spendable; More only when not); More menu overlays and does not grow the row
- [ ] Known depth on collapsed rows is at most “Shared N blocks”; expand does not restate that line
- [ ] Peg-in-tied mature coin: “Tied to peg-in” chip, primary Spend to self, Balance banner still opens Coins
- [ ] Spend to self confirm: what it does, the "Other private transactions in the mempool" count (1–10, default 2), the "Spread out the send" checkbox (off by default) with its 1–3 minute hint, the wait, fee, amount, quiet-block note (one hop says Try again costs another 0.0005 LTC), and the 1-in-1 pattern sentence. With an RPC URL and the spread off, the wait says the hop is sent on the first check that finds at least N other private transactions; with the spread on it says it then waits 1–3 minutes. Changing the count or the checkbox updates the sentence. With no URL the hop will be signed now and will not be sent until a Litecoin RPC URL is saved in Settings → Connection. The no-RPC card says it is waiting for a Litecoin node, says to save that URL, and Open Settings focuses the field. Nothing is sent until the URL is saved
- [ ] With a node, the waiting card's smaller line says "Needs N other private transactions in the node's mempool." and, within about a minute, "Checked N s ago: T transactions in the mempool, M other private transactions (K kernels, O outputs)." The age advances each minute. Stopping litecoind changes it to "Could not read the mempool N s ago: <reason>." and starting it again clears that on the next read. "Waiting to spread the send." is appended only while the spread is on and the count has been met. The hop is sent on the first check that meets the count when the spread is off
- [ ] A quiet block on a one-hop job pauses the card and says signing a new hop spends another 0.0005 LTC. Try again stays the button label. A longer run arms the next signed hop and waits for cover again. It does not sign a replacement hop
- [ ] Live `#churn-status` card tracks Waiting for cover / Waiting for the block / Paused / Couldn't send. With no RPC URL the card offers Open Settings ahead of Cancel. Try again is only on a one-hop quiet block, an unscored pause, or Couldn't send. Cancel is available before broadcast
- [ ] Unconfirmed self-spend outputs show Pending (not Maturing); Maturing is for peg-in countdown only
- [ ] After a scored hop: settled card + Just spent highlight; More → Details shows labeled Privacy / Last block / Technical sections
- [ ] Frozen / maturing coins: Spend and Split blocked; Frozen is a visible chip + left-edge accent
- [ ] Empty Private list offers Move to private → Swap peg-in

### 6. Failure recovery (must pass)

- [ ] With RPC cleared and peers unreachable: private send/peg-out failure opens recovery modal → Settings Connection
- [ ] Mempool conflict / already-known messages point to Sync + History Pending (no RBF UI)
- [ ] After fixing RPC/peers, retry succeeds

### 7. Record the run

Fill in when green:

| Field | Value |
| --- | --- |
| Network | mainnet / testnet |
| Electrum tip | |
| MWEB synced height | |
| Peg-in txid | |
| Private send wtxid | |
| Peg-out wtxid | |
| litecoind version / peer | |
| App version / git SHA | |
| Date | |

## Exit criteria (M1)

This checklist is green on at least one live network (testnet preferred for dogfood; mainnet with dust amounts OK). Packaging/notarization is a separate M1 track — see [`VERIFYING.md`](VERIFYING.md).

## Out of scope here

Fine-window sync UI, embedded litecoind, mwebd, hardware wallets, Tor.

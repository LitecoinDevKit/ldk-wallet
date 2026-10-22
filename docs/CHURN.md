# Spend to self (MWEB churn)

A private coin does not get harder to link just by sitting. A spend publishes the output id it consumes. The new output is only ambiguous among the other outputs created in that same extension block. [LIP-0004](https://github.com/litecoin-project/lips/blob/master/lip-0004.mediawiki) aggregation is what mixes, and it mixes inside one block.

Cut-through does not hide a same-block intermediate. LIP-0004 §6 keeps the spent output in the TXO set until it passes the horizon. Two self-spends in one quiet block publish the path. The next hop waits until the previous one is confirmed so it is a separate aggregation.

## What the wallet does

One coin, one job. Each hop is a 1-in-1 spend to a fresh address of this wallet. The fee is the public kernel fee (0.0005 LTC). The coin stays frozen until the job is cancelled or finished, so Send, Swap, and Split cannot take it.

The default is one hop. A collapsed control can ask for up to 10 non-solo blocks. While the wallet is unlocked the wallet signs that many hops and reserves a receive index for each one. It does not rewind those indexes if the job is cancelled or the signature expires. Only the first hop is applied to the coin list. The rest stay in `churn_armed.json` (mode `0600`) until each previous hop is scored. That file is not part of the metadata export.

A hop is broadcast only when a Litecoin RPC URL is set and the node's mempool has enough other MWEB transactions. The count is chosen on the confirm sheet, 1 to 10, default 2, and is stored on the job so every hop in a run uses it. The wallet checks the mempool about once a minute and sends the hop on the first check that meets the count. "Spread out the send" is off by default. When it is on, the first check that meets the count draws a 1–3 minute deadline, the hop is sent on the first check at or after it, and a check that falls below the count drops the deadline. Transactions this wallet already has unconfirmed, including earlier hops in this chain, are not cover. Without an RPC URL the card says it is waiting for a Litecoin node, a smaller line says to save a Litecoin RPC URL in Settings → Connection, and Open Settings focuses that field. Nothing is sent. With a node, the card says it is waiting for other private transactions, and a smaller line says how many it needs and what the last check saw.

The signed hop can be broadcast while the wallet is locked. Scoring still waits until the next unlock. A hop expires 24 hours or 576 blocks after it becomes the armed hop, whichever comes first. The raw transaction is then deleted. On the next unlock the wallet checks that the input is still unspent, or spent only by this job's own mark.

A quiet block does not count. If another signed hop remains, it is armed and waits for cover again. The wallet does not sign a replacement, so the fee stays within `target_depth` times the hop fee. If quiet blocks use up the chain before the target count, the job finishes and says how many blocks counted. A one-hop job still pauses. Try again signs one new hop and spends another fee, and only while the wallet is unlocked.

Cancel is offered while a hop is waiting for cover, after a quiet-block or unscored pause, or when the hop could not be sent. It is not offered while the hop is already on the network. An unconfirmed self-spend output shows as Pending (not Maturing — that label is for peg-in maturity).

A hop counts when the inclusion block was not ours alone. For this 1-in-1, that is when the inclusion header's `kernel_mmr_size` is more than 1 or `output_mmr_size` grew by more than 1 from the parent header. The kernel field is the block's own kernel count; litecoind rebuilds the kernel MMR every block, so it is never compared with the parent. Header sizes cannot tell a peg-in from a private spend. The row says how many other kernels and outputs were in the block, and that peg-ins and peg-outs in that count publish an amount.

This sync stores one tip leafset. Scoring does not diff that leafset. The hop is in a block after the tip at broadcast. The wallet finds the new output's leaf and scores the block whose output MMR crosses it, through the current tip. A header it cannot read yet leaves the hop waiting for a later sync. If several blocks pass and that output is still not on chain, the spend is marked not included and the original coin can be sent again.

The resulting amount is still the starting amount minus one public fee per hop. Depth does not change that. Depth is how many non-solo blocks this coin has been in. It is not an anonymity-set size, and it is not a point at which pegging out is safe.

Depth is local. Spent outputs leave the UTXO set, so a restore cannot reconstruct it. The metadata bundle carries `output_id → depth`. Without that file, the wallet shows the count as unknown.

## Copy

- Button: "Spend to self." History: "self-spend." The amount on that row is the fee.
- Confirm sheet order: what the spend does, the "Other private transactions in the mempool" count (1–10, default 2), the "Spread out the send" checkbox with its hint ("After the mempool has enough other private transactions, wait a random 1–3 minutes before sending. This can take longer."), then the wait, the fee for this hop, the amount line, the quiet-block sentence, then "A chain of self-spends is still a recognizable 1-in-1 pattern. It does not create a larger anonymity set." With a saved Litecoin RPC URL and the spread off, the wait says "This hop is sent on the first check that finds at least N other private transactions in the node's mempool. That can take a long time." With the spread on: "This hop waits until a check finds at least N other private transactions in the node's mempool. Then it waits 1–3 minutes before sending. That can take a long time." With no URL it says the hop will be signed now and will not be sent until a Litecoin RPC URL is saved in Settings → Connection, then it waits for other private transactions. Do not lead with the depth stepper.
- A one-hop quiet-block sentence also says pressing Try again later signs a new hop and spends another 0.0005 LTC. A longer run still says the next prepared spend waits for other private transactions.
- After a hop, the main line is "This block only contained your spend." or "This block also had N other kernels and M other outputs." A quiet block adds "Signing a new hop spends another 0.0005 LTC." The count of blocks is the smaller line.
- A quiet block stays on the row when no signed hop remains. When one does, the card waits for other private transactions instead. A block the wallet could not read yet stays waiting there too. They are not error toasts.
- While a signed hop is waiting, the card says "Waiting for a Litecoin node." or "Waiting for other private transactions." With no URL, a smaller line says "Save a Litecoin RPC URL in Settings → Connection." and Open Settings focuses that field. With a node, the smaller line is "Needs N other private transactions. Last check saw M." (the second sentence appears after the first read) and "Waiting to spread the send." is appended while a spread deadline is running. Cancel stays. "Waiting for the next block." is only after the hop has been broadcast.
- Balance shows one dismissible line when a spendable peg-in coin has never shared a block. It opens Coins. It is not a second maturity warning.

No privacy meter, no automatic start after peg-in, and no "safe to peg out" state.

## Coins list presentation

Coins → Private default row is a decision surface: amount, an attention chip when needed (Maturing / Frozen / Tied to peg-in / churn / Just spent), one short status line when useful, and a one-line action column — Spend to self (when spendable; primary only when peg-in-tied) beside More. Freeze, Split, and Details live in the More overlay so opening it does not change row height. Frozen uses a chip plus a muted left-edge accent.

Default-row depth is at most "Shared N blocks". Unknown or zero depth shows nothing on the collapsed row. Expand never restates that depth line. Expanded detail uses labeled sections: Privacy (only when it adds info — tied sentence, no shared blocks yet, or "No shared-block history available."), Last block (companions), Technical (confirmations, truncated output id, hops, anonymity-set disclaimer, label). The live `#churn-status` card and confirm sheet keep the copy above (kernels/outputs, non-solo block counts, fee-first confirm).

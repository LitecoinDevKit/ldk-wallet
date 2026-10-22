# Spend to self (MWEB churn)

A private coin does not get harder to link just by sitting. A spend publishes the output id it consumes. The new output is only ambiguous among the other outputs created in that same extension block. [LIP-0004](https://github.com/litecoin-project/lips/blob/master/lip-0004.mediawiki) aggregation is what mixes, and it mixes inside one block.

Cut-through does not hide a same-block intermediate. LIP-0004 §6 keeps the spent output in the TXO set until it passes the horizon. Two self-spends in one quiet block publish the path. The next hop waits until the previous one is confirmed so it is a separate aggregation.

## What the wallet does

One coin, one job. Each hop is a 1-in-1 spend to a fresh address of this wallet. The fee is the public kernel fee (0.0005 LTC). The coin stays frozen until the job is cancelled or finished, so Send, Swap, and Split cannot take it.

The default is one hop. A collapsed control can ask for up to 10 non-solo blocks. A quiet block pauses the job. It does not retry by itself.

Cancel is only offered after a quiet-block / unscored pause, or when the hop could not be sent. It is not offered while Sending or Waiting: once broadcast, the hop is on the network and cannot be unbroadcast. An unconfirmed self-spend output shows as Pending (not Maturing — that label is for peg-in maturity).

A hop counts when the inclusion block was not ours alone. For this 1-in-1, that is when the inclusion header's `kernel_mmr_size` is more than 1 or `output_mmr_size` grew by more than 1 from the parent header. The kernel field is the block's own kernel count; litecoind rebuilds the kernel MMR every block, so it is never compared with the parent. Header sizes cannot tell a peg-in from a private spend. The row says how many other kernels and outputs were in the block, and that peg-ins and peg-outs in that count publish an amount.

This sync stores one tip leafset. Scoring does not diff that leafset. The hop is in a block after the tip at broadcast. The wallet finds the new output's leaf and scores the block whose output MMR crosses it, through the current tip. A header it cannot read yet leaves the hop waiting for a later sync. If several blocks pass and that output is still not on chain, the spend is marked not included and the original coin can be sent again.

The resulting amount is still the starting amount minus one public fee per hop. Depth does not change that. Depth is how many non-solo blocks this coin has been in. It is not an anonymity-set size, and it is not a point at which pegging out is safe.

Depth is local. Spent outputs leave the UTXO set, so a restore cannot reconstruct it. The metadata bundle carries `output_id → depth`. Without that file, the wallet shows the count as unknown.

## Copy

- Button: "Spend to self." History: "self-spend." The amount on that row is the fee.
- Confirm sheet order: what the spend does, the fee for this hop, the amount line, then the quiet-block sentence. Do not lead with a stepper.
- After a hop, the main line is "This block only contained your spend." or "This block also had N other kernels and M other outputs." The count of blocks is the smaller line.
- A quiet block stays on the row. A block the wallet could not read yet stays waiting there too. They are not error toasts.
- Balance shows one dismissible line when a spendable peg-in coin has never shared a block. It opens Coins. It is not a second maturity warning.

No privacy meter, no automatic start after peg-in, and no "safe to peg out" state.

## Coins list presentation

Coins → Private default row is a decision surface: amount, an attention chip when needed (Maturing / Frozen / Tied to peg-in / churn / Just spent), one short status line when useful, and a one-line action column — Spend to self (when spendable; primary only when peg-in-tied) beside More. Freeze, Split, and Details live in the More overlay so opening it does not change row height. Frozen uses a chip plus a muted left-edge accent.

Default-row depth is at most "Shared N blocks". Unknown or zero depth shows nothing on the collapsed row. Expand never restates that depth line. Expanded detail uses labeled sections: Privacy (only when it adds info — tied sentence, no shared blocks yet, or "No shared-block history available."), Last block (companions), Technical (confirmations, truncated output id, hops, anonymity-set disclaimer, label). The live `#churn-status` card and confirm sheet keep the copy above (kernels/outputs, non-solo block counts, fee-first confirm).

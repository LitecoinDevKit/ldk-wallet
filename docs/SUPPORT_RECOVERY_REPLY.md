# Discord reply — recovery spin / logs / Nexus receive

Copy/paste as needed (do **not** request or quote any seed):

---

## Recovery spinning / logs

Hey — restore creates the wallet in a few seconds; the long part is the **first sync** after that (Electrum full address scan + full MWEB UTXO download). On a decent connection that’s often **a couple of minutes**; **10–30+** on a slow link or a throttled MWEB peer is still normal. Watch the Sync control for **“Syncing…”** and later **Downloading MWEB outputs: N / M** (v0.4.7+ keeps a labeled overlay through the first restore sync).

If it never finishes until you **quit and reopen**, older builds defaulted MWEB peers to `127.0.0.1:9333`. With no local litecoind, first sync could stall. **v0.4.7+** leaves peers empty (auto-discovery), migrates the bare localhost default away, and skips unreachable peers in ~2s. Workaround on older builds: Settings → clear **MWEB P2P peers** → Save → Sync.

For the **old MWEB derivation path**, on Restore pick **mwebd (before 1 June 2026)**.

**Logs:** Settings → Diagnostics → Export / Copy (v0.4.7+). On older builds share screenshot, Connection test result, optional `wallet_meta.json` only (never `*.enc` / seed).

Please don’t paste recovery words in Discord.

---

## MWEB sent to Nexus / Cake

Outbound private sends pay the pasted `ltcmweb1…` keys directly. LDK→Nexus private has worked in testing; LDK→Cake private has failed while public→Cake worked — treat Cake private receive as a Cake-side scan/enable issue until proven otherwise.

1. In **this** wallet History: is the private send **confirmed** or still pending?
2. Compare exact `ltcmweb1` vs the recipient’s Private receive QR.
3. On Cake: Enable MWEB, let MWEB sync finish, then check again.
4. Keep the **Kernel ID (wtxid)** from the success modal.

---

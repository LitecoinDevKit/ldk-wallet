//! MWEB orchestration beside the transparent wallet.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::str::FromStr;

use std::sync::Arc;

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::limits::MAX_REQUESTED_MWEB_UTXOS;
use bdk_mweb::lip0006::MwebUtxoSource;
use bdk_mweb::lip0006_tcp::{BroadcastAck, TcpMwebPeer};
use bdk_mweb::mweb_sync::{
    leafset_has_leaf, FixedHeaderProvider, MwebSyncer, PeerPool, ReadyNotifier, SyncProgress,
    SyncState,
};
use bdk_mweb::p2p::{GetMwebUtxos, MwebLeafset, OUTPUT_FORMAT_FULL};
use bdk_mweb::pmmr::verify_leafset;
use bdk_mweb::tx_builder::CHANGE_ADDRESS_INDEX;
use bdk_mweb::MwebCoinDatabase;
use bdk_mweb::{AddressBook, BanReason, ChangeSet, SealContext, MWEB_PEGIN_MATURITY};
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize_hex};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, NetworkKind, ScriptBuf, Transaction};
use bdk_wallet::chain::Merge;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{
    extract_prepared_mweb_pegin, select_mweb_coins, MwebStore, PersistedWallet, SignOptions,
};

use crate::dto::{
    CombinedSummary, MwebBroadcastResult, MwebSendRequest, MwebUtxoRecord, PeginRequest,
    PeginResult, PegoutRequest, SplitResult, TxKind, WalletSummary,
};
use crate::error::WalletError;
use crate::meta;
use crate::mweb_frozen;
use crate::mweb_history::{now_ts, MwebHistory, MwebHistoryEntry};
use crate::network::WalletNetwork;
use crate::rpc;
use crate::utxo_labels;

/// MWEB address-book size. Ownership lookup during scanning is a single map
/// probe regardless of book size (see `bdk_mweb::scan`), so this is sized for
/// recovery: coins received at any index below it are found on restore. The
/// old `DEFAULT_GAP_LIMIT` of 20 silently missed coins at higher indices.
pub const MWEB_GAP_LIMIT: u32 = 1000;

/// Mature, unfrozen MWEB coins at `tip_height`.
pub fn spendable_pool(
    db: &MwebCoinDatabase,
    tip_height: u32,
    frozen: &BTreeSet<String>,
) -> Vec<bdk_mweb::MwebCoin> {
    db.unspent_spendable(tip_height, MWEB_PEGIN_MATURITY)
        .into_iter()
        .filter(|c| !frozen.contains(&hex::encode(c.output_id)))
        .collect()
}

/// Sum of mature, unfrozen MWEB coin amounts at `tip_height`.
pub fn spendable_mweb_sats(
    runtime: &MwebRuntime,
    tip_height: u32,
    frozen: &BTreeSet<String>,
) -> u64 {
    spendable_pool(runtime.store.db(), tip_height, frozen)
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.amount))
}

pub fn normalize_selected_ids(ids: Option<&[String]>) -> Option<Vec<String>> {
    let v: Vec<String> = ids
        .unwrap_or(&[])
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Resolve coins for a private send or peg-out.
///
/// Manual selection spends **exactly** the listed coins (all of them). Automatic
/// selection greeds over the unfrozen mature pool.
pub fn resolve_spend_coins(
    db: &MwebCoinDatabase,
    tip_height: u32,
    frozen: &BTreeSet<String>,
    selected_ids: Option<&[String]>,
    needed: u64,
    action: &str,
) -> Result<Vec<bdk_mweb::MwebCoin>, WalletError> {
    if let Some(ids) = selected_ids.filter(|v| !v.is_empty()) {
        let mut coins = Vec::with_capacity(ids.len());
        for id in ids {
            coins.push(select_mweb_coin(db, id, tip_height, frozen, action)?);
        }
        let sum: u64 = coins.iter().map(|c| c.amount).sum();
        if sum < needed {
            return Err(WalletError::BuildTx(format!(
                "need {needed} litoshis from the selected private coins but they only total {sum}"
            )));
        }
        Ok(coins)
    } else {
        let pool = spendable_pool(db, tip_height, frozen);
        select_mweb_coins(&pool, needed).map_err(|e| WalletError::Mweb(e.to_string()))
    }
}

/// Planned HogEx amounts for a per-coin peg-out (one public output per private coin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegoutPerCoinPlan {
    pub amounts: Vec<u64>,
    /// Index of the output that absorbed the kernel fee.
    pub fee_output_index: usize,
}

/// P2WPKH dust at the same 30 sat/vB relay rate used for typed peg-outs.
pub fn p2wpkh_dust_sats() -> Result<u64, WalletError> {
    let dust_relay = FeeRate::from_sat_per_vb(30)
        .ok_or_else(|| WalletError::BuildTx("internal dust fee rate".into()))?;
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[0u8; 20]);
    Ok(ScriptBuf::from_bytes(bytes)
        .minimal_non_dust_custom(dust_relay)
        .to_sat())
}

/// Map each spent private coin to a public HogEx amount.
///
/// The kernel fee is taken from the largest coin so other denominations stay exact.
/// `N = 1` is the same as today's single-output drain of that coin.
pub fn plan_pegout_per_coin(
    coin_amounts: &[u64],
    fee_sats: u64,
    dust_sats: u64,
) -> Result<PegoutPerCoinPlan, WalletError> {
    if coin_amounts.is_empty() {
        return Err(WalletError::BuildTx(
            "no spendable private coins to peg out".into(),
        ));
    }
    let fee_output_index = coin_amounts
        .iter()
        .enumerate()
        .max_by_key(|(i, amt)| (*amt, *i))
        .map(|(i, _)| i)
        .expect("non-empty");
    let mut amounts = coin_amounts.to_vec();
    let largest = amounts[fee_output_index];
    let after_fee = largest.checked_sub(fee_sats).ok_or_else(|| {
        WalletError::BuildTx(
            "After paying the fee, the largest coin would be below the dust limit".into(),
        )
    })?;
    if after_fee < dust_sats {
        return Err(WalletError::BuildTx(
            "After paying the fee, the largest coin would be below the dust limit".into(),
        ));
    }
    amounts[fee_output_index] = after_fee;
    for (i, amt) in amounts.iter().enumerate() {
        if *amt < dust_sats {
            return Err(WalletError::BuildTx(format!(
                "public output {} of {amt} litoshis is below the {dust_sats} litoshis dust limit",
                i + 1
            )));
        }
    }
    Ok(PegoutPerCoinPlan {
        amounts,
        fee_output_index,
    })
}

pub struct MwebRuntime {
    pub store: MwebStore,
    pub keys: MasterKeys,
    pub book: AddressBook,
    pub sync_state: SyncState,
    pub receive_index: u32,
    pub last_synced_height: Option<u32>,
    pub last_status: String,
    pub stale: bool,
    pub history: MwebHistory,
    /// Warning from the last sync's second-peer leafset cross-check, if any.
    pub cross_check_warning: Option<String>,
    /// Peer that served the last successful sync pass. Scoring asks it first.
    pub last_good_peer: Option<std::net::SocketAddr>,
    /// Full aggregate coin changeset mirrored on disk (sealed persistence).
    agg: ChangeSet,
    /// Key for encrypting MWEB files at rest; `None` falls back to the legacy
    /// plaintext formats (tests / plaintext-era wallets awaiting migration).
    sealing_key: Option<[u8; 32]>,
    secp: Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
}

/// What to tell the user about a failed sync pass, and whether the failure
/// justifies going looking for another peer.
struct PassFailure {
    /// Shown verbatim in the UI, so it has to be plain and actionable.
    status: String,
    /// Whether to fall back to peers discovered from the DNS seeds.
    allow_public_fallback: bool,
}

/// Interpret a failed sync pass.
///
/// Split out as a free function so the decision can be tested without a peer;
/// the alternative is exercising it only through a live socket, which is how it
/// went untested before.
fn classify_pass_failure(err: &bdk_mweb::Error) -> PassFailure {
    if err.ban_reason() == Some(BanReason::Throttled) {
        // The peer answered, it just would not serve us: litecoind 0.21.5.6+
        // meters MWEB serving node-wide and silently drops what it will not
        // serve. Calling that "unreachable" would send the user debugging
        // their network, and switching to a public peer would make it worse —
        // shared peers are the ones most likely to be metered dry, and they
        // would see queries our own node keeps to itself.
        return PassFailure {
            status: "MWEB peer is rate-limiting requests; balance may lag. Run your node \
                     with -whitelist=noban@127.0.0.1 to exempt this wallet."
                .into(),
            allow_public_fallback: false,
        };
    }
    PassFailure {
        status: format!("MWEB peer unreachable: {err}"),
        allow_public_fallback: true,
    }
}

impl MwebRuntime {
    pub fn open(
        data_dir: &Path,
        secret: &crate::seed::MasterSecret,
        network: WalletNetwork,
        scheme: MasterKeyScheme,
        sealing_key: Option<[u8; 32]>,
    ) -> Result<Self, WalletError> {
        let secp = Secp256k1::new();
        let bdk_net = network.to_bitcoin_network();
        let master = secret.master_xprv(bdk_net)?;
        let keys = MasterKeys::from_xprv(&master, scheme, &secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        let book = AddressBook::from_keys(&keys, MWEB_GAP_LIMIT, &secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;

        let (store, agg) = load_store(data_dir, sealing_key.as_ref())?;
        let sync_state = load_sync_state(data_dir, sealing_key.as_ref())?;
        let receive_index = load_receive_index(data_dir, sealing_key.as_ref())?;
        let history = load_history(data_dir, sealing_key.as_ref())?;

        Ok(Self {
            store,
            keys,
            book,
            sync_state,
            receive_index,
            last_synced_height: None,
            last_status: "MWEB not synced yet".into(),
            stale: true,
            history,
            cross_check_warning: None,
            last_good_peer: None,
            agg,
            sealing_key,
            secp,
        })
    }

    pub fn persist(&mut self, data_dir: &Path) -> Result<(), WalletError> {
        if let Some(key) = self.sealing_key {
            self.agg.merge(self.store.take_staged());
            // One counter for all four blobs, so a later read can tell whether
            // they came from the same persist.
            let counter = load_seal_counter(data_dir).saturating_add(1);

            let coins =
                bdk_mweb::seal_changeset_with_context(&key, &self.agg, SealContext::Coins, counter)
                    .map_err(|e| WalletError::Mweb(e.to_string()))?;
            write_sealed(&meta::mweb_coins_enc_path(data_dir), coins)?;
            let sync_json = serde_json::to_vec(&self.sync_state)
                .map_err(|e| WalletError::Mweb(e.to_string()))?;
            write_sealed(
                &meta::mweb_sync_enc_path(data_dir),
                seal_bytes(&key, &sync_json, SealContext::SyncState, counter)?,
            )?;
            write_sealed(
                &meta::mweb_index_enc_path(data_dir),
                seal_bytes(
                    &key,
                    self.receive_index.to_string().as_bytes(),
                    SealContext::Index,
                    counter,
                )?,
            )?;
            let history_json =
                serde_json::to_vec(&self.history).map_err(|e| WalletError::Mweb(e.to_string()))?;
            write_sealed(
                &meta::mweb_history_enc_path(data_dir),
                seal_bytes(&key, &history_json, SealContext::History, counter)?,
            )?;
            // Written last: a crash between the blobs and the counter leaves the
            // counter behind, which reads as "not yet advanced" rather than as a
            // rollback.
            save_seal_counter(data_dir, counter)?;
            // Everything is sealed on disk now; drop plaintext-era leftovers.
            remove_legacy_plaintext_files(data_dir);
        } else {
            persist_store(data_dir, &mut self.store)?;
            save_sync_state(data_dir, &self.sync_state)?;
            save_receive_index(data_dir, self.receive_index)?;
            self.history.save(&meta::mweb_history_path(data_dir))?;
        }
        Ok(())
    }

    pub fn receive_address(&mut self, network: WalletNetwork) -> Result<String, WalletError> {
        let kind = match network {
            WalletNetwork::Mainnet => NetworkKind::Main,
            WalletNetwork::Testnet => NetworkKind::Test,
        };
        let addr = self
            .keys
            .address(self.receive_index, kind, &self.secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        Ok(addr.to_string())
    }

    pub fn advance_receive_index(&mut self) {
        self.receive_index = self.receive_index.saturating_add(1);
    }

    /// Tip-only LIP sync. On peer failure, mark stale and keep transparent usable.
    ///
    /// `prev_tip_hash` is the block hash on the *current* chain at the height of the
    /// previous MWEB sync. Providing it lets the syncer prove the previous tip is still
    /// on-chain (pure extension), keeping the leafset snapshot so only new leaves are
    /// downloaded instead of the full UTXO set on every block.
    pub fn sync_at_tip(
        &mut self,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        prev_tip_hash: Option<bdk_wallet::bitcoin::BlockHash>,
        peers: &[String],
        network: WalletNetwork,
        progress: Option<Arc<SyncProgress>>,
    ) -> Result<(), WalletError> {
        let configured = resolve_reachable_peers(peers)?;
        let mut configured_failure = None;
        if !configured.is_empty() {
            match self.sync_pass(
                configured.clone(),
                tip_height,
                tip_hash,
                prev_tip_hash,
                network,
                progress.clone(),
            ) {
                Ok(()) => {
                    let mut candidates = configured;
                    if candidates.len() < 2 {
                        candidates.extend(crate::discovery::discover_mweb_peers(network));
                    }
                    self.cross_check_leafset(tip_hash, candidates, network);
                    return Ok(());
                }
                Err(e) => {
                    let failure = classify_pass_failure(&e);
                    // A metered node is healthy and it is ours. Keep waiting on
                    // it rather than defecting to a stranger's.
                    if !failure.allow_public_fallback {
                        self.stale = true;
                        self.last_status = failure.status;
                        return Ok(());
                    }
                    configured_failure = Some(failure);
                }
            }
        }
        // Their own node is absent or down, so fall back to public MWEB peers
        // from the DNS seeds rather than leaving MWEB dark.
        let discovered = crate::discovery::discover_mweb_peers(network);
        if discovered.is_empty() {
            self.stale = true;
            self.last_status = match configured_failure {
                Some(failure) => failure.status,
                None => "no MWEB peers configured, and none found via DNS seeds".into(),
            };
            return Ok(());
        }
        match self.sync_pass(
            discovered.clone(),
            tip_height,
            tip_hash,
            prev_tip_hash,
            network,
            progress,
        ) {
            Ok(()) => {
                self.last_status.push_str(" via public peer");
                self.cross_check_leafset(tip_hash, discovered, network);
                Ok(())
            }
            Err(e) => {
                self.stale = true;
                self.last_status = classify_pass_failure(&e).status;
                Ok(())
            }
        }
    }

    /// Ask up to two peers for the MWEB header at `tip_hash` and verify our
    /// freshly synced leafset against each header's `leafset_root`.
    ///
    /// A single LIP-0006 peer can understate the balance by serving an
    /// internally consistent but stale/forged header + leafset; agreement from
    /// a second peer means omission now requires collusion. Only headers are
    /// requested, so the peers learn nothing about the wallet.
    fn cross_check_leafset(
        &mut self,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        addrs: Vec<std::net::SocketAddr>,
        network: WalletNetwork,
    ) {
        self.cross_check_warning = None;
        if self.sync_state.leafset.is_empty() {
            return;
        }
        let mut distinct: Vec<std::net::SocketAddr> = Vec::new();
        for addr in addrs {
            if !distinct.contains(&addr) {
                distinct.push(addr);
            }
        }
        let leafset = MwebLeafset {
            block_hash: tip_hash,
            leafset: self.sync_state.leafset.clone(),
        };
        let bdk_net = network.to_bitcoin_network();
        let mut confirmed = 0u32;
        for addr in distinct {
            if confirmed >= 2 {
                break;
            }
            let Ok(mut peer) = TcpMwebPeer::connect(addr, bdk_net) else {
                continue;
            };
            let Ok(hdr) = peer.get_header(tip_hash) else {
                continue;
            };
            match verify_leafset(
                &leafset,
                &hdr.mweb_header.leafset_root,
                hdr.mweb_header.output_mmr_size,
            ) {
                Ok(()) => confirmed += 1,
                Err(_) => {
                    self.cross_check_warning = Some(format!(
                        "WARNING: MWEB peer {addr} reports a different UTXO set than the peer \
                         used for this sync — your private balance may be incomplete. Run \
                         'Resync MWEB' or verify against your own node"
                    ));
                    return;
                }
            }
        }
        match confirmed {
            0 => self
                .last_status
                .push_str(" · cross-check unavailable (no second peer reachable)"),
            1 => self.last_status.push_str(" · leafset confirmed by 1 peer"),
            n => self
                .last_status
                .push_str(&format!(" · leafset confirmed by {n} peers")),
        }
    }

    /// One differential sync attempt against a fixed set of peers.
    ///
    /// Returns the typed [`bdk_mweb::Error`] rather than a string: the
    /// [`BanReason`] behind a failure decides both what the user is told and
    /// whether we go looking for another peer. See [`classify_pass_failure`].
    #[allow(clippy::too_many_arguments)]
    fn sync_pass(
        &mut self,
        addrs: Vec<std::net::SocketAddr>,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        prev_tip_hash: Option<bdk_wallet::bitcoin::BlockHash>,
        network: WalletNetwork,
        progress: Option<Arc<SyncProgress>>,
    ) -> Result<(), bdk_mweb::Error> {
        // Heal before this pass so a stuck split/send is included in the
        // full UTXO download rather than waiting for a later sync.
        if pending_unverifiable_outgoing(&self.history, self.store.db()) {
            self.sync_state.invalidate_leafset();
        }
        let pool_first = addrs.first().copied();
        let mut pool = PeerPool::new(addrs);
        let syncer = MwebSyncer {
            progress,
            ..MwebSyncer::tip_only()
        };
        let bdk_net = network.to_bitcoin_network();
        let mut hashes = std::collections::BTreeMap::new();
        if let (Some(prev_height), Some(prev_hash)) = (self.sync_state.tip_height, prev_tip_hash) {
            hashes.insert(prev_height, prev_hash);
        }
        hashes.insert(tip_height, tip_hash);
        let mut headers = FixedHeaderProvider {
            tip_hash,
            tip_height,
            hashes,
        };
        headers.set_tip(tip_hash, tip_height);
        let mut notifier = ReadyNotifier { tip_height };
        match pool.with_failover(bdk_net, |peer| {
            self.store.sync_differential(
                bdk_wallet::MwebSyncDrivers {
                    syncer: &syncer,
                    headers: &headers,
                    notifier: &mut notifier,
                    state: &mut self.sync_state,
                },
                peer,
                bdk_wallet::MwebScanContext {
                    keys: &self.keys,
                    book: &self.book,
                    secp: &self.secp,
                },
            )
        }) {
            Ok(result) => {
                self.last_good_peer = pool.last_connected().or_else(|| pool_first);
                self.last_synced_height = Some(tip_height);
                self.stale = false;
                self.last_status = format!(
                    "MWEB synced at {tip_height} (+{} downloaded, {} found)",
                    result.downloaded,
                    result.found.len()
                );
                self.absorb_received_coins();
                let leafset = self.sync_state.leafset.clone();
                update_outgoing_confirmations(
                    &mut self.history,
                    self.store.db_mut(),
                    &leafset,
                    tip_height,
                );
                // Inputs recorded before leaf backfill cannot be checked against
                // the current leafset. Force a full UTXO download next pass so
                // sync can re-find the live coins and date or restore them.
                if pending_unverifiable_outgoing(&self.history, self.store.db()) {
                    self.sync_state.invalidate_leafset();
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn disconnect_from(&mut self, height: u32) {
        self.store.disconnect_from(height);
        // Reorged-out entries must be re-resolved on the new chain.
        for entry in &mut self.history.entries {
            if entry.confirmed_height.is_some_and(|h| h >= height) {
                entry.confirmed_height = None;
            }
        }
    }

    /// Add history entries for coins in the store that no entry accounts for
    /// yet (external MWEB receives, or peg-ins found on restore). Coins created
    /// by our own peg-ins / sends are pre-registered and skipped.
    fn absorb_received_coins(&mut self) {
        for coin in self.store.db().unspent_vec() {
            let id_hex = hex::encode(coin.output_id);
            if self.history.is_known(&id_hex) {
                continue;
            }
            self.history.record(MwebHistoryEntry {
                id: id_hex.clone(),
                kind: if coin.is_pegin {
                    TxKind::Pegin
                } else {
                    TxKind::MwebReceive
                },
                net_sats: coin.amount as i64,
                fee_sats: None,
                timestamp: now_ts(),
                output_ids: vec![id_hex],
                input_ids: Vec::new(),
                confirmed_height: None,
            });
        }
    }

    pub fn combined_summary(
        &mut self,
        wallet: &PersistedWallet<Connection>,
        transparent: WalletSummary,
    ) -> Result<CombinedSummary, WalletError> {
        let bal = wallet.balance_combined_store(&self.store);
        let tip = wallet.latest_checkpoint().height();
        let immature = self
            .store
            .db()
            .unspent_vec()
            .into_iter()
            .filter(|c| {
                c.is_pegin
                    && c.block_height
                        .map(|h| tip.saturating_sub(h) < MWEB_PEGIN_MATURITY)
                        .unwrap_or(true)
            })
            .map(|c| c.amount)
            .sum::<u64>();
        let mweb_addr = self.receive_address(transparent.network).ok();
        Ok(CombinedSummary {
            transparent,
            mweb_confirmed_sats: bal.mweb_confirmed.to_sat().saturating_sub(immature),
            mweb_unconfirmed_sats: bal.mweb_untrusted_pending.to_sat(),
            mweb_immature_sats: immature,
            mweb_total_sats: bal.mweb_total().to_sat(),
            mweb_receive_address: mweb_addr,
            mweb_synced_height: self.last_synced_height,
            mweb_stale: self.stale,
            mweb_status: self.last_status.clone(),
        })
    }
}

/// After this long an outgoing MWEB tx that never dated is treated as dropped.
/// Regular sync otherwise leaves the input marked spent and the new coins
/// unspendable forever (differential sync does not re-download old leaves).
const UNCONFIRMED_MWEB_REVERT_SECS: u64 = 48 * 60 * 60;

fn is_outgoing_mweb(kind: TxKind) -> bool {
    matches!(
        kind,
        TxKind::Pegout | TxKind::MwebSend | TxKind::MwebSplit | TxKind::MwebChurn
    )
}

/// Minimum inclusion height among coins this entry created, if any are dated.
pub(crate) fn history_entry_height(entry: &MwebHistoryEntry, db: &MwebCoinDatabase) -> Option<u32> {
    let mut height = entry.confirmed_height;
    for id_hex in &entry.output_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        let coin = db.get(&id).or_else(|| db.get_spent(&id));
        if let Some(h) = coin.and_then(|c| c.block_height) {
            height = Some(height.map_or(h, |cur| cur.min(h)));
        }
    }
    height
}

fn date_undated_outputs(db: &mut MwebCoinDatabase, output_ids: &[String], height: u32) {
    for id_hex in output_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        if db.get(&id).is_some_and(|c| c.block_height.is_none()) {
            db.set_block_height(&id, height);
        }
    }
}

/// Pending outgoing txs whose spent inputs have no `leaf_index`, so the
/// leafset cannot prove inclusion or drop. A full UTXO download re-finds them.
pub(crate) fn pending_unverifiable_outgoing(history: &MwebHistory, db: &MwebCoinDatabase) -> bool {
    history.entries.iter().any(|entry| {
        if entry.confirmed_height.is_some() || !is_outgoing_mweb(entry.kind) {
            return false;
        }
        if history_entry_height(entry, db).is_some() {
            return false;
        }
        entry.input_ids.iter().any(|id_hex| {
            let Some(id) = decode_output_id(id_hex) else {
                return false;
            };
            db.get(&id)
                .or_else(|| db.get_spent(&id))
                .is_some_and(|c| c.leaf_index.is_none())
        })
    })
}

fn restore_stale_unconfirmed_inputs(
    history: &MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    now: u64,
) {
    if leafset.is_empty() {
        return;
    }
    let input_ids: Vec<[u8; 32]> = history
        .entries
        .iter()
        .filter(|entry| {
            entry.confirmed_height.is_none()
                && is_outgoing_mweb(entry.kind)
                && now.saturating_sub(entry.timestamp) >= UNCONFIRMED_MWEB_REVERT_SECS
        })
        .flat_map(|entry| {
            entry
                .input_ids
                .iter()
                .filter_map(|id_hex| decode_output_id(id_hex))
        })
        .collect();
    for id in input_ids {
        let Some(coin) = db.get_spent(&id).cloned() else {
            continue;
        };
        let Some(leaf) = coin.leaf_index else {
            continue;
        };
        if leafset_has_leaf(leafset, leaf) {
            db.insert(coin);
        }
    }
}

fn forget_stale_unlanded_outgoing(history: &mut MwebHistory, db: &mut MwebCoinDatabase, now: u64) {
    let mut forget: Vec<String> = Vec::new();
    for entry in &history.entries {
        if entry.confirmed_height.is_some() || !is_outgoing_mweb(entry.kind) {
            continue;
        }
        if now.saturating_sub(entry.timestamp) < UNCONFIRMED_MWEB_REVERT_SECS {
            continue;
        }
        if history_entry_height(entry, db).is_some() {
            continue;
        }
        if entry.input_ids.is_empty() {
            continue;
        }
        let inputs_live_again = entry.input_ids.iter().all(|id_hex| {
            let Some(id) = decode_output_id(id_hex) else {
                return false;
            };
            db.get(&id).is_some()
        });
        if inputs_live_again {
            forget.push(entry.id.clone());
            for id_hex in &entry.output_ids {
                let Some(id) = decode_output_id(id_hex) else {
                    continue;
                };
                if db.get(&id).is_some_and(|c| c.block_height.is_none()) {
                    let _ = db.mark_spent(&id);
                }
            }
        }
    }
    history.forget_ids(&forget);
}

/// Resolve `confirmed_height` for outgoing MWEB entries (peg-outs and MWEB
/// sends) after a successful sync at `tip`.
///
/// Signals, in order of preference:
/// 1. A coin the tx created for us (change) carries a `block_height` — exact.
/// 2. Every spent input's leaf is gone from the network leafset (spends only
///    clear at inclusion), or the coin vanished from the store entirely after
///    a wipe/resync — confirmed at or before `tip`, recorded as `tip`.
/// 3. Legacy entries with nothing to track (recorded before input tracking
///    existed, no change): resolved at `tip` rather than pending forever; the
///    inputs already left the balance at broadcast.
///
/// When (2) fires, undated local output coins are given `tip` so they become
/// spendable. When a spend is still in the leafset after
/// [`UNCONFIRMED_MWEB_REVERT_SECS`], the input is restored and the optimistic
/// outputs / history row are dropped — otherwise a dropped split locks funds.
pub(crate) fn update_outgoing_confirmations(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
) {
    update_outgoing_confirmations_at(history, db, leafset, tip, now_ts());
}

fn update_outgoing_confirmations_at(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
    now: u64,
) {
    restore_stale_unconfirmed_inputs(history, db, leafset, now);

    for entry in &mut history.entries {
        if entry.confirmed_height.is_some() || !is_outgoing_mweb(entry.kind) {
            continue;
        }
        if let Some(h) = history_entry_height(entry, db) {
            entry.confirmed_height = Some(h);
            date_undated_outputs(db, &entry.output_ids, h);
            continue;
        }
        if entry.input_ids.is_empty() {
            if entry.output_ids.is_empty() {
                entry.confirmed_height = Some(tip);
            }
            continue;
        }
        if leafset.is_empty() {
            continue;
        }
        let all_inputs_gone = entry.input_ids.iter().all(|id_hex| {
            let Some(id) = decode_output_id(id_hex) else {
                return false;
            };
            match db.get(&id).or_else(|| db.get_spent(&id)) {
                // Absent after a store wipe: a confirmed-spent coin is never
                // re-found by sync, while an unconfirmed spend's coin would be.
                None => true,
                Some(coin) => coin
                    .leaf_index
                    .is_some_and(|leaf| !leafset_has_leaf(leafset, leaf)),
            }
        });
        if all_inputs_gone {
            entry.confirmed_height = Some(tip);
            date_undated_outputs(db, &entry.output_ids, tip);
        }
    }

    forget_stale_unlanded_outgoing(history, db, now);
}

fn decode_output_id(id_hex: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(id_hex).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_mweb::MwebCoin;

    #[test]
    fn header_peers_keep_the_configured_node_ahead_of_public_ones() {
        let local: std::net::SocketAddr = "127.0.0.1:9333".parse().unwrap();
        let public: std::net::SocketAddr = "64.23.156.63:9333".parse().unwrap();
        assert_eq!(merge_header_peers(&[local], &[public]), vec![local, public]);
        assert_eq!(merge_header_peers(&[], &[public]), vec![public]);
        assert_eq!(merge_header_peers(&[local], &[local]), vec![local]);
    }

    const TIP: u32 = 200;

    /// A peer that will not serve us is not a peer that is down, and the
    /// difference decides both what the user reads and whether we hand our
    /// queries to a stranger.
    #[test]
    fn a_rate_limited_peer_is_not_reported_as_unreachable() {
        let failure = classify_pass_failure(&bdk_mweb::Error::throttled(
            "peer served none of 7 outstanding getmwebutxos request(s)",
        ));
        assert!(
            !failure.status.contains("unreachable"),
            "the peer answered; calling it unreachable sends the user \
             debugging their network: {}",
            failure.status
        );
        assert!(
            failure.status.contains("-whitelist"),
            "the status line is the only channel the user has, so it must \
             name the fix: {}",
            failure.status
        );
    }

    /// With the fallback suppressed, the status line is the sole explanation
    /// for a balance that stops advancing.
    #[test]
    fn a_rate_limited_peer_does_not_send_us_to_public_peers() {
        let failure = classify_pass_failure(&bdk_mweb::Error::throttled("rate limited"));
        assert!(
            !failure.allow_public_fallback,
            "public peers share the same node-wide bucket and would see \
             queries our own node keeps private"
        );
    }

    /// Everything that is not a throttle keeps the old behavior: a node that
    /// is genuinely down should not leave MWEB dark.
    #[test]
    fn other_peer_failures_still_fall_back_and_read_as_unreachable() {
        for err in [
            bdk_mweb::Error::transport("connection reset"),
            bdk_mweb::Error::bad_proof("leafset root mismatch"),
            bdk_mweb::Error::protocol("unsorted batch"),
        ] {
            let failure = classify_pass_failure(&err);
            assert!(
                failure.allow_public_fallback,
                "{err} should still permit the public-peer fallback"
            );
            assert!(
                failure.status.contains("unreachable"),
                "{err} should read as unreachable, got {}",
                failure.status
            );
        }
    }

    fn coin(id: u8, height: Option<u32>, leaf_index: Option<u64>) -> MwebCoin {
        MwebCoin {
            output_id: [id; 32],
            commitment: [0; 33],
            amount: 1_000,
            address_index: 0,
            blind: [0; 32],
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
            block_height: height,
            is_pegin: false,
            leaf_index,
        }
    }

    fn id_hex(id: u8) -> String {
        hex::encode([id; 32])
    }

    fn entry(kind: TxKind, outputs: &[u8], inputs: &[u8]) -> MwebHistoryEntry {
        MwebHistoryEntry {
            id: "tx".into(),
            kind,
            net_sats: -1_000,
            fee_sats: Some(100),
            timestamp: 1_700_000_000,
            output_ids: outputs.iter().map(|&b| id_hex(b)).collect(),
            input_ids: inputs.iter().map(|&b| id_hex(b)).collect(),
            confirmed_height: None,
        }
    }

    /// MSB-first leafset with the given leaves set (never empty).
    fn leafset(leaves: &[u64]) -> Vec<u8> {
        let max = leaves.iter().copied().max().unwrap_or(0);
        let mut out = vec![0u8; (max / 8 + 1) as usize];
        for &l in leaves {
            out[(l / 8) as usize] |= 1 << (7 - (l % 8) as u8);
        }
        out
    }

    fn run_at(
        entries: Vec<MwebHistoryEntry>,
        db: &mut MwebCoinDatabase,
        leaves: &[u64],
        now: u64,
    ) -> (Vec<Option<u32>>, MwebHistory) {
        let mut history = MwebHistory::default();
        for e in entries {
            history.record(e);
        }
        update_outgoing_confirmations_at(&mut history, db, &leafset(leaves), TIP, now);
        let heights = history.entries.iter().map(|e| e.confirmed_height).collect();
        (heights, history)
    }

    fn run(
        entries: Vec<MwebHistoryEntry>,
        db: &mut MwebCoinDatabase,
        leaves: &[u64],
    ) -> Vec<Option<u32>> {
        // One hour after the fixture timestamp — still inside the revert window.
        run_at(entries, db, leaves, 1_700_000_000 + 3600).0
    }

    #[test]
    fn change_coin_height_gives_exact_confirmation() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, Some(150), Some(7)));
        // Inputs still in the leafset must not matter once change is dated.
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::Pegout, &[1], &[2])], &mut db, &[3, 7]);
        assert_eq!(got, vec![Some(150)]);
    }

    #[test]
    fn exact_pegout_confirms_when_input_leaves_leave_leafset() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::Pegout, &[], &[2])], &mut db, &[9]);
        assert_eq!(got, vec![Some(TIP)]);
    }

    #[test]
    fn exact_pegout_stays_pending_while_input_leaf_present() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::MwebSend, &[], &[2])], &mut db, &[3]);
        assert_eq!(got, vec![None]);
        assert!(
            db.get(&[2; 32]).is_none(),
            "recent pending spend stays spent"
        );
        assert!(db.get_spent(&[2; 32]).is_some());
    }

    #[test]
    fn input_missing_from_store_counts_as_confirmed_spent() {
        // After an MWEB wipe/resync a confirmed-spent coin is never re-found.
        let mut db = MwebCoinDatabase::default();
        let got = run(vec![entry(TxKind::Pegout, &[], &[2])], &mut db, &[9]);
        assert_eq!(got, vec![Some(TIP)]);
    }

    #[test]
    fn input_without_leaf_index_is_unverifiable() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(2, None, None));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::Pegout, &[], &[2])], &mut db, &[9]);
        assert_eq!(got, vec![None]);
        assert!(pending_unverifiable_outgoing(
            &{
                let mut h = MwebHistory::default();
                h.record(entry(TxKind::Pegout, &[], &[2]));
                h
            },
            &db
        ));
    }

    #[test]
    fn recall_restores_the_spent_input_and_drops_the_unconfirmed_output() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, Some(50), Some(4)));
        db.mark_spent(&[1; 32]);
        db.insert(coin(2, None, None));
        let mut history = MwebHistory::default();
        history.record(entry(TxKind::MwebChurn, &[2], &[1]));
        let restored = recall_unlanded_spend(&mut history, &mut db, "tx").unwrap();
        assert_eq!(restored, id_hex(1));
        assert!(db.get(&[1; 32]).is_some());
        assert!(db.get(&[2; 32]).is_none());
        assert!(history.entries.is_empty());
    }

    #[test]
    fn recall_leaves_a_landed_output_alone() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, Some(50), Some(4)));
        db.mark_spent(&[1; 32]);
        db.insert(coin(2, None, Some(9)));
        let mut history = MwebHistory::default();
        history.record(entry(TxKind::MwebChurn, &[2], &[1]));
        assert!(recall_unlanded_spend(&mut history, &mut db, "tx").is_none());
        assert!(db.get(&[2; 32]).is_some());
        assert!(db.get_spent(&[1; 32]).is_some());
    }

    #[test]
    fn undated_change_with_present_inputs_stays_pending() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, None, None));
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::Pegout, &[1], &[2])], &mut db, &[3]);
        assert_eq!(got, vec![None]);
    }

    #[test]
    fn legacy_trackless_entry_resolves_at_tip() {
        let mut db = MwebCoinDatabase::default();
        let got = run(vec![entry(TxKind::Pegout, &[], &[])], &mut db, &[0]);
        assert_eq!(got, vec![Some(TIP)]);
    }

    #[test]
    fn confirmed_split_dates_undated_outputs() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, None, None));
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let got = run(vec![entry(TxKind::MwebSplit, &[1], &[2])], &mut db, &[9]);
        assert_eq!(got, vec![Some(TIP)]);
        assert_eq!(db.get(&[1; 32]).unwrap().block_height, Some(TIP));
        assert!(db.get(&[1; 32]).unwrap().is_spendable(TIP, 6));
    }

    #[test]
    fn stale_unconfirmed_split_restores_input() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, None, None));
        db.insert(coin(2, Some(100), Some(3)));
        db.mark_spent(&[2; 32]);
        let now = 1_700_000_000 + UNCONFIRMED_MWEB_REVERT_SECS + 1;
        let (heights, history) = run_at(
            vec![entry(TxKind::MwebSplit, &[1], &[2])],
            &mut db,
            &[3, 9],
            now,
        );
        assert!(
            heights.is_empty(),
            "dropped split must leave history: {heights:?}"
        );
        assert!(history.entries.is_empty());
        assert!(
            db.get(&[2; 32]).is_some(),
            "original coin must be spendable again"
        );
        assert!(
            db.get(&[1; 32]).is_none(),
            "optimistic split outputs must not stay in the unspent set"
        );
    }

    #[test]
    fn non_outgoing_kinds_are_untouched() {
        let got = run(
            vec![
                entry(TxKind::Pegin, &[], &[]),
                entry(TxKind::MwebReceive, &[], &[]),
            ],
            &mut MwebCoinDatabase::default(),
            &[0],
        );
        assert_eq!(got, vec![None, None]);
    }

    #[test]
    fn select_split_coin_picks_known_id_not_another() {
        let mut db = MwebCoinDatabase::default();
        let mut a = coin(1, Some(100), Some(1));
        a.amount = 30_000_000;
        let mut b = coin(2, Some(100), Some(2));
        b.amount = 50_000_000;
        db.insert(a);
        db.insert(b);
        let got = select_split_coin(&db, &id_hex(2), TIP, &BTreeSet::new()).unwrap();
        assert_eq!(got.output_id, [2; 32]);
        assert_eq!(got.amount, 50_000_000);
        let err = select_split_coin(&db, &id_hex(9), TIP, &BTreeSet::new()).unwrap_err();
        assert!(err.to_string().contains("not an unspent"));
    }

    #[test]
    fn select_split_coin_refuses_immature_pegin() {
        let mut db = MwebCoinDatabase::default();
        let mut c = coin(3, Some(TIP), Some(1));
        c.is_pegin = true;
        db.insert(c);
        let err = select_split_coin(&db, &id_hex(3), TIP, &BTreeSet::new()).unwrap_err();
        assert!(err.to_string().contains("not yet spendable"));
    }

    #[test]
    fn select_split_coin_refuses_frozen() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(4, Some(100), Some(1)));
        let mut frozen = BTreeSet::new();
        frozen.insert(id_hex(4));
        let err = select_split_coin(&db, &id_hex(4), TIP, &frozen).unwrap_err();
        assert!(err.to_string().contains("frozen"));
        assert!(err.to_string().contains("splitting"));
    }

    #[test]
    fn spendable_pool_skips_frozen() {
        let mut db = MwebCoinDatabase::default();
        let mut small = coin(1, Some(100), Some(1));
        small.amount = 1_000_000;
        let mut big = coin(2, Some(100), Some(2));
        big.amount = 50_000_000;
        db.insert(small);
        db.insert(big);
        let mut frozen = BTreeSet::new();
        frozen.insert(id_hex(2));
        let pool = spendable_pool(&db, TIP, &frozen);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool[0].output_id, [1; 32]);
        let needed = 900_000;
        let selected = resolve_spend_coins(&db, TIP, &frozen, None, needed, "spending").unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].output_id, [1; 32]);
    }

    #[test]
    fn resolve_spend_coins_uses_exact_ids() {
        let mut db = MwebCoinDatabase::default();
        let mut a = coin(1, Some(100), Some(1));
        a.amount = 10_000_000;
        let mut b = coin(2, Some(100), Some(2));
        b.amount = 50_000_000;
        db.insert(a);
        db.insert(b);
        let ids = vec![id_hex(1)];
        let selected = resolve_spend_coins(
            &db,
            TIP,
            &BTreeSet::new(),
            Some(&ids),
            1_000_000,
            "spending",
        )
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].output_id, [1; 32]);
        let frozen = BTreeSet::from([id_hex(1)]);
        let err =
            resolve_spend_coins(&db, TIP, &frozen, Some(&ids), 1_000_000, "spending").unwrap_err();
        assert!(err.to_string().contains("frozen"));
        let mut immature = coin(3, Some(TIP), Some(1));
        immature.is_pegin = true;
        db.insert(immature);
        let immature_ids = vec![id_hex(3)];
        let err = resolve_spend_coins(
            &db,
            TIP,
            &BTreeSet::new(),
            Some(&immature_ids),
            1_000_000,
            "spending",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not yet spendable"));
    }

    #[test]
    fn plan_pegout_per_coin_takes_fee_from_largest() {
        let plan =
            plan_pegout_per_coin(&[5_000_000, 10_000_000, 20_000_000], 50_000, 2_940).unwrap();
        assert_eq!(plan.fee_output_index, 2);
        assert_eq!(plan.amounts, vec![5_000_000, 10_000_000, 19_950_000]);
        assert_eq!(plan.amounts.iter().sum::<u64>(), 34_950_000);
    }

    #[test]
    fn plan_pegout_per_coin_single_matches_drain() {
        let plan = plan_pegout_per_coin(&[10_000_000], 50_000, 2_940).unwrap();
        assert_eq!(plan.fee_output_index, 0);
        assert_eq!(plan.amounts, vec![9_950_000]);
    }

    #[test]
    fn plan_pegout_per_coin_refuses_dust_after_fee() {
        let err = plan_pegout_per_coin(&[51_000], 50_000, 2_940).unwrap_err();
        assert!(err.to_string().contains("below the dust limit"));
        let err = plan_pegout_per_coin(&[], 50_000, 2_940).unwrap_err();
        assert!(err.to_string().contains("no spendable private coins"));
    }

    #[test]
    fn plan_pegout_per_coin_two_selected_skips_frozen_pool() {
        let mut db = MwebCoinDatabase::default();
        let mut small = coin(1, Some(100), Some(1));
        small.amount = 5_000_000;
        let mut mid = coin(2, Some(100), Some(2));
        mid.amount = 10_000_000;
        let mut frozen_coin = coin(3, Some(100), Some(3));
        frozen_coin.amount = 50_000_000;
        db.insert(small);
        db.insert(mid);
        db.insert(frozen_coin);
        let frozen = BTreeSet::from([id_hex(3)]);
        let pool = spendable_pool(&db, TIP, &frozen);
        let amounts: Vec<u64> = pool.iter().map(|c| c.amount).collect();
        assert_eq!(amounts.len(), 2);
        let plan = plan_pegout_per_coin(&amounts, 50_000, 2_940).unwrap();
        assert_eq!(plan.amounts.len(), 2);
        assert_eq!(plan.amounts[plan.fee_output_index], 9_950_000);
        assert!(plan.amounts.contains(&5_000_000));
    }

    #[test]
    fn list_mweb_unspent_shows_locked_and_label() {
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let mut runtime = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            crate::dto::MwebScheme::default().to_master_scheme(),
            None,
        )
        .unwrap();
        runtime.store.db_mut().insert(coin(5, Some(100), Some(1)));
        let id = id_hex(5);
        mweb_frozen::set_locked(dir.path(), &id, true).unwrap();
        crate::utxo_labels::set_label(dir.path(), &id, "savings").unwrap();
        let rows = list_mweb_unspent(&runtime, TIP, dir.path());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].locked);
        assert_eq!(rows[0].label, "savings");
    }

    #[test]
    fn fund_mweb_split_spends_only_the_selected_coin() {
        use crate::descriptors;
        use crate::dto::MwebScheme;
        use crate::seed::MasterSecret;
        let dir = tempfile::tempdir().unwrap();
        let secret = MasterSecret::parse(&descriptors::generate_mnemonic().unwrap(), None).unwrap();
        let runtime = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            MwebScheme::default().to_master_scheme(),
            None,
        )
        .unwrap();
        let mut big = coin(2, Some(100), Some(2));
        big.amount = 50_000_000;
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, Some(100), Some(1)));
        db.insert(big.clone());
        let selected = select_split_coin(&db, &id_hex(2), TIP, &BTreeSet::new()).unwrap();
        assert_eq!(selected.output_id, [2; 32]);
        let kind = NetworkKind::Test;
        let addr0 = runtime.keys.address(0, kind, &runtime.secp).unwrap();
        let addr1 = runtime.keys.address(1, kind, &runtime.secp).unwrap();
        // Dummy coin secrets will not produce a valid spend, but funding must
        // still take exactly the selected input rather than the whole pool.
        let funded = bdk_mweb::fund_mweb_spend(
            vec![selected],
            vec![(addr0, 10_000_000), (addr1, 10_000_000)],
            vec![],
            50_000,
            &runtime.keys,
            CHANGE_ADDRESS_INDEX,
            kind,
            &runtime.secp,
        );
        match funded {
            Ok(funded) => {
                assert_eq!(funded.spent_coins.len(), 1);
                assert_eq!(funded.spent_coins[0].output_id, [2; 32]);
            }
            Err(e) => {
                // Funding may reject stub coin secrets; selection still pinned one coin.
                let msg = e.to_string();
                assert!(
                    !msg.to_lowercase().contains("insufficient"),
                    "should not pull a second coin from the pool: {msg}"
                );
            }
        }
    }

    #[test]
    fn already_resolved_entry_is_not_rewritten() {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(1, Some(150), Some(7)));
        let mut e = entry(TxKind::Pegout, &[1], &[]);
        e.confirmed_height = Some(50);
        let got = run(vec![e], &mut db, &[7]);
        assert_eq!(got, vec![Some(50)]);
    }

    #[test]
    fn sealed_persistence_round_trips_and_migrates() {
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let key = [9u8; 32];
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();

        // Start plaintext (legacy wallet), write a coin + history entry.
        let mut legacy =
            MwebRuntime::open(dir.path(), &secret, WalletNetwork::Testnet, scheme, None).unwrap();
        legacy.store.db_mut().insert(coin(1, Some(100), Some(4)));
        legacy.receive_index = 7;
        legacy.history.record(entry(TxKind::MwebSend, &[1], &[]));
        legacy.persist(dir.path()).unwrap();
        assert!(meta::mweb_db_path(dir.path()).is_file());

        // Reopen with a sealing key: legacy sqlite is read, next persist seals
        // everything and removes the plaintext files.
        let mut sealed = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        )
        .unwrap();
        assert_eq!(sealed.store.db().unspent_count(), 1);
        assert_eq!(sealed.receive_index, 7);
        assert_eq!(sealed.history.entries.len(), 1);
        sealed.persist(dir.path()).unwrap();
        assert!(meta::mweb_coins_enc_path(dir.path()).is_file());
        assert!(!meta::mweb_db_path(dir.path()).is_file());
        assert!(!meta::mweb_history_path(dir.path()).is_file());

        // Sealed reload sees the same state; the sealed blob is not plaintext.
        let reloaded = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        )
        .unwrap();
        assert_eq!(reloaded.store.db().unspent_count(), 1);
        assert_eq!(reloaded.receive_index, 7);
        assert_eq!(reloaded.history.entries.len(), 1);
        let blob = std::fs::read(meta::mweb_history_enc_path(dir.path())).unwrap();
        assert!(!blob.windows(2).any(|w| w == b"tx"));

        // Wrong key must fail loudly, not fall back to empty state.
        let wrong = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some([0u8; 32]),
        );
        assert!(wrong.is_err());
    }

    /// Set up a sealed wallet directory and return its dir, secret, and key.
    fn sealed_fixture() -> (tempfile::TempDir, crate::seed::MasterSecret, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let key = [0x5au8; 32];
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();

        let mut rt = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        )
        .unwrap();
        rt.store.db_mut().insert(coin(1, Some(100), Some(4)));
        rt.receive_index = 3;
        rt.history.record(entry(TxKind::MwebSend, &[1], &[]));
        rt.persist(dir.path()).unwrap();
        (dir, secret, key)
    }

    #[test]
    fn sealed_blobs_cannot_be_swapped_between_files() {
        // Before the v2 envelope, all four blobs were sealed under one key with
        // no associated data, so any of them opened as any other. An attacker
        // with write access to the data directory could substitute the history
        // for the coin database and authentication still passed.
        let (dir, secret, key) = sealed_fixture();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();

        let history = std::fs::read(meta::mweb_history_enc_path(dir.path())).unwrap();
        std::fs::write(meta::mweb_coins_enc_path(dir.path()), &history).unwrap();

        let swapped = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        );
        assert!(
            swapped.is_err(),
            "history.enc was accepted in place of coins.enc"
        );
    }

    #[test]
    fn every_sealed_blob_is_a_v2_envelope_bound_to_its_own_context() {
        let (dir, _secret, key) = sealed_fixture();
        for (path, ctx) in [
            (meta::mweb_coins_enc_path(dir.path()), SealContext::Coins),
            (meta::mweb_sync_enc_path(dir.path()), SealContext::SyncState),
            (meta::mweb_index_enc_path(dir.path()), SealContext::Index),
            (
                meta::mweb_history_enc_path(dir.path()),
                SealContext::History,
            ),
        ] {
            let blob = std::fs::read(&path).unwrap();
            assert!(
                bdk_mweb::is_v2(&blob),
                "{} is not a v2 envelope",
                path.display()
            );
            assert!(
                bdk_mweb::open_with_context(&key, &blob, ctx).is_ok(),
                "{} does not open under its own context",
                path.display()
            );
            // Every other context must be rejected, so the tag is load-bearing
            // rather than merely present.
            for other in [
                SealContext::Coins,
                SealContext::SyncState,
                SealContext::Index,
                SealContext::History,
            ] {
                if other == ctx {
                    continue;
                }
                assert!(
                    bdk_mweb::open_with_context(&key, &blob, other).is_err(),
                    "{} opened under the wrong context",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn the_persist_counter_advances_and_is_shared_by_every_blob() {
        let (dir, secret, key) = sealed_fixture();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        assert_eq!(load_seal_counter(dir.path()), 1);

        let mut rt = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        )
        .unwrap();
        rt.persist(dir.path()).unwrap();
        assert_eq!(load_seal_counter(dir.path()), 2);

        // All four blobs must carry the same counter, otherwise mixing files
        // from different persists would not be detectable.
        for path in [
            meta::mweb_coins_enc_path(dir.path()),
            meta::mweb_sync_enc_path(dir.path()),
            meta::mweb_index_enc_path(dir.path()),
            meta::mweb_history_enc_path(dir.path()),
        ] {
            let blob = std::fs::read(&path).unwrap();
            // Counter is bytes 10..18 of the v2 header, little-endian.
            let counter = u64::from_le_bytes(blob[10..18].try_into().unwrap());
            assert_eq!(counter, 2, "{} carries a stale counter", path.display());
        }
    }

    #[test]
    fn legacy_sealed_blobs_still_open() {
        // Wallets written before the v2 envelope must keep working with no
        // migration step; the next persist rewrites them as v2.
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let key = [0x77u8; 32];
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();

        // Write all four files in the legacy format by hand.
        let mut cs = ChangeSet::default();
        cs.coins.insert([1; 32], coin(1, Some(100), Some(4)));
        std::fs::write(
            meta::mweb_coins_enc_path(dir.path()),
            bdk_mweb::seal_changeset(&key, &cs).unwrap(),
        )
        .unwrap();
        std::fs::write(
            meta::mweb_sync_enc_path(dir.path()),
            bdk_mweb::seal(&key, &serde_json::to_vec(&SyncState::default()).unwrap()).unwrap(),
        )
        .unwrap();
        std::fs::write(
            meta::mweb_index_enc_path(dir.path()),
            bdk_mweb::seal(&key, b"9").unwrap(),
        )
        .unwrap();
        std::fs::write(
            meta::mweb_history_enc_path(dir.path()),
            bdk_mweb::seal(&key, &serde_json::to_vec(&MwebHistory::default()).unwrap()).unwrap(),
        )
        .unwrap();

        let mut rt = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            Some(key),
        )
        .unwrap();
        assert_eq!(rt.store.db().unspent_count(), 1);
        assert_eq!(rt.receive_index, 9);

        rt.persist(dir.path()).unwrap();
        let upgraded = std::fs::read(meta::mweb_coins_enc_path(dir.path())).unwrap();
        assert!(bdk_mweb::is_v2(&upgraded), "persist did not upgrade to v2");
    }

    #[test]
    fn empty_leafset_defers_input_based_resolution() {
        let mut history = MwebHistory::default();
        history.record(entry(TxKind::Pegout, &[], &[2]));
        let mut db = MwebCoinDatabase::default();
        update_outgoing_confirmations(&mut history, &mut db, &[], TIP);
        assert_eq!(history.entries[0].confirmed_height, None);
    }
}

/// Remove MWEB store/sync/index files for a from-scratch resync.
///
/// Deliberately keeps the history log (plain and sealed): entries stay visible
/// across a resync, and `known_outputs` stops re-found coins from duplicating
/// receive entries.
pub fn wipe_mweb_files(data_dir: &Path) -> Result<(), WalletError> {
    for path in [
        meta::mweb_db_path(data_dir),
        meta::mweb_sync_path(data_dir),
        meta::mweb_index_path(data_dir),
        meta::mweb_coins_enc_path(data_dir),
        meta::mweb_sync_enc_path(data_dir),
        meta::mweb_index_enc_path(data_dir),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(WalletError::Io(e)),
        }
    }
    Ok(())
}

/// AEAD-seal `plain` under the wallet sealing key, bound to `context`.
///
/// All four MWEB blobs are sealed under one key. Without the context binding
/// they are interchangeable: an attacker with write access to the data
/// directory can copy `mweb_history.enc` over `mweb_coins.enc` and the AEAD tag
/// still verifies, because nothing in the ciphertext says which file it is.
/// `bdk_mweb`'s v2 envelope binds the context tag as associated data, so
/// opening under the wrong one fails.
fn seal_bytes(
    key: &[u8; 32],
    plain: &[u8],
    context: SealContext,
    counter: u64,
) -> Result<Vec<u8>, WalletError> {
    bdk_mweb::seal_with_context_and_counter(key, plain, context, counter)
        .map_err(|e| WalletError::Mweb(e.to_string()))
}

/// Open a sealed file; `Ok(None)` when the file does not exist.
///
/// Reads both envelope versions. A v2 blob must carry `context`; a legacy blob
/// predates the tag and is accepted as-is, so wallets written by an older build
/// keep opening with no migration step. The next `persist` rewrites it as v2.
fn read_sealed(
    path: &Path,
    key: &[u8; 32],
    context: SealContext,
) -> Result<Option<Vec<u8>>, WalletError> {
    match fs::read(path) {
        Ok(blob) => open_sealed_blob(&blob, key, context)
            .map(Some)
            .map_err(|e| WalletError::Mweb(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(WalletError::Io(e)),
    }
}

fn open_sealed_blob(
    blob: &[u8],
    key: &[u8; 32],
    context: SealContext,
) -> Result<Vec<u8>, bdk_mweb::Error> {
    if bdk_mweb::is_v2(blob) {
        bdk_mweb::open_with_context(key, blob, context)
    } else {
        bdk_mweb::open(key, blob)
    }
}

/// Monotonic persist counter, bound into every v2 envelope this wallet writes.
///
/// The four MWEB blobs are written together and must be read together. Sealing
/// them all under the same counter turns a *partial* rollback — restoring only
/// `mweb_coins.enc` from an older backup while sync state and history stay
/// current — into a detectable mismatch. That is the realistic attack, since
/// the files are separate and independently replaceable.
///
/// It does not detect a rollback of the whole directory at once. Doing that
/// needs a high-water mark somewhere the attacker cannot roll back with the
/// files, which means inside the Argon2-sealed secrets blob; see
/// `docs/AUDIT_NOTES.md`.
fn load_seal_counter(data_dir: &Path) -> u64 {
    fs::read_to_string(meta::mweb_seal_counter_path(data_dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_seal_counter(data_dir: &Path, counter: u64) -> Result<(), WalletError> {
    fs::write(
        meta::mweb_seal_counter_path(data_dir),
        format!("{counter}\n"),
    )?;
    Ok(())
}

fn write_sealed(path: &Path, blob: Vec<u8>) -> Result<(), WalletError> {
    crate::secrets::write_bytes(path, &blob)
        .map_err(|e| WalletError::Mweb(format!("{}: {e}", path.display())))
}

/// Delete plaintext-era MWEB files once their sealed replacements are written.
fn remove_legacy_plaintext_files(data_dir: &Path) {
    let db = meta::mweb_db_path(data_dir);
    for path in [
        db.clone(),
        std::path::PathBuf::from(format!("{}-wal", db.display())),
        std::path::PathBuf::from(format!("{}-shm", db.display())),
        meta::mweb_sync_path(data_dir),
        meta::mweb_index_path(data_dir),
        meta::mweb_history_path(data_dir),
    ] {
        let _ = fs::remove_file(&path);
    }
}

/// Load the coin store and its aggregate changeset. Preference order: sealed
/// file (when a key is available), legacy sqlite (migrated to sealed on the
/// next persist), empty.
fn load_store(
    data_dir: &Path,
    sealing_key: Option<&[u8; 32]>,
) -> Result<(MwebStore, ChangeSet), WalletError> {
    if let Some(key) = sealing_key {
        let path = meta::mweb_coins_enc_path(data_dir);
        if path.is_file() {
            let blob = fs::read(&path)?;
            let cs = if bdk_mweb::is_v2(&blob) {
                bdk_mweb::open_changeset_with_context(key, &blob, SealContext::Coins, 0)
                    .map(|(cs, _counter)| cs)
            } else {
                bdk_mweb::open_changeset(key, &blob)
            }
            .map_err(|e| WalletError::Mweb(format!("sealed MWEB store: {e}")))?;
            return Ok((MwebStore::from_changeset(cs.clone()), cs));
        }
    }
    let path = meta::mweb_db_path(data_dir);
    if !path.is_file() {
        return Ok((MwebStore::new(), ChangeSet::default()));
    }
    let mut conn = Connection::open(&path).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let tx = conn
        .transaction()
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    ChangeSet::init_sqlite_tables(&tx).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let cs = ChangeSet::from_sqlite(&tx).map_err(|e| WalletError::Mweb(e.to_string()))?;
    tx.commit().map_err(|e| WalletError::Mweb(e.to_string()))?;
    Ok((MwebStore::from_changeset(cs.clone()), cs))
}

fn persist_store(data_dir: &Path, store: &mut MwebStore) -> Result<(), WalletError> {
    let path = meta::mweb_db_path(data_dir);
    let mut conn = Connection::open(&path).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let tx = conn
        .transaction()
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    store
        .persist_sqlite(&tx)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    tx.commit().map_err(|e| WalletError::Mweb(e.to_string()))?;
    Ok(())
}

fn load_sync_state(
    data_dir: &Path,
    sealing_key: Option<&[u8; 32]>,
) -> Result<SyncState, WalletError> {
    if let Some(key) = sealing_key {
        if let Some(plain) = read_sealed(
            &meta::mweb_sync_enc_path(data_dir),
            key,
            SealContext::SyncState,
        )? {
            return serde_json::from_slice(&plain).map_err(|e| WalletError::Mweb(e.to_string()));
        }
    }
    let path = meta::mweb_sync_path(data_dir);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| WalletError::Mweb(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SyncState::default()),
        Err(e) => Err(WalletError::Io(e)),
    }
}

fn save_sync_state(data_dir: &Path, state: &SyncState) -> Result<(), WalletError> {
    let json = serde_json::to_string_pretty(state).map_err(|e| WalletError::Mweb(e.to_string()))?;
    fs::write(meta::mweb_sync_path(data_dir), json)?;
    Ok(())
}

fn load_receive_index(data_dir: &Path, sealing_key: Option<&[u8; 32]>) -> Result<u32, WalletError> {
    if let Some(key) = sealing_key {
        if let Some(plain) = read_sealed(
            &meta::mweb_index_enc_path(data_dir),
            key,
            SealContext::Index,
        )? {
            let s = String::from_utf8_lossy(&plain);
            return Ok(s.trim().parse().unwrap_or(0));
        }
    }
    let path = meta::mweb_index_path(data_dir);
    match fs::read_to_string(&path) {
        Ok(s) => Ok(s.trim().parse().unwrap_or(0)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(WalletError::Io(e)),
    }
}

fn save_receive_index(data_dir: &Path, index: u32) -> Result<(), WalletError> {
    fs::write(meta::mweb_index_path(data_dir), format!("{index}\n"))?;
    Ok(())
}

fn load_history(
    data_dir: &Path,
    sealing_key: Option<&[u8; 32]>,
) -> Result<MwebHistory, WalletError> {
    if let Some(key) = sealing_key {
        if let Some(plain) = read_sealed(
            &meta::mweb_history_enc_path(data_dir),
            key,
            SealContext::History,
        )? {
            return serde_json::from_slice(&plain).map_err(|e| WalletError::Mweb(e.to_string()));
        }
    }
    MwebHistory::load(&meta::mweb_history_path(data_dir))
}

fn resolve_peers(peers: &[String]) -> Result<Vec<std::net::SocketAddr>, WalletError> {
    let mut out = Vec::new();
    for p in peers {
        match p.to_socket_addrs() {
            Ok(iter) => out.extend(iter),
            Err(e) => {
                // Keep going; sync_at_tip will report if none resolve.
                let _ = e;
            }
        }
    }
    Ok(out)
}

/// TCP connect probe before a full LIP handshake. Skips dead configured peers
/// (especially the old default `127.0.0.1:9333`) so sync/broadcast fall through
/// to DNS discovery instead of hanging on OS connect timeouts.
const PEER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn probe_reachable(addrs: Vec<std::net::SocketAddr>) -> Vec<std::net::SocketAddr> {
    addrs
        .into_iter()
        .filter(|addr| {
            match std::net::TcpStream::connect_timeout(addr, PEER_PROBE_TIMEOUT) {
                Ok(stream) => {
                    // Drop immediately — TcpMwebPeer will reconnect + handshake.
                    drop(stream);
                    true
                }
                Err(_) => {
                    crate::diag::log(format!("mweb peer probe: {addr} unreachable, skipping"));
                    false
                }
            }
        })
        .collect()
}

fn resolve_reachable_peers(peers: &[String]) -> Result<Vec<std::net::SocketAddr>, WalletError> {
    Ok(probe_reachable(resolve_peers(peers)?))
}

pub fn pegin(
    wallet: &mut PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    rpc_url: Option<&str>,
    peers: &[String],
    req: PeginRequest,
    network: WalletNetwork,
) -> Result<PeginResult, WalletError> {
    let selected = req
        .selected_outpoints
        .as_ref()
        .map(|v| {
            v.iter()
                .filter(|s| !s.trim().is_empty())
                .map(|s| {
                    use std::str::FromStr;
                    bdk_wallet::bitcoin::OutPoint::from_str(s.trim()).map_err(|e| {
                        WalletError::BuildTx(format!(
                            "invalid outpoint '{s}' (expected txid:vout): {e}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

    let mut prepared = wallet
        .prepare_mweb_pegin_with_utxos(
            &runtime.keys,
            runtime.receive_index,
            Amount::from_sat(req.amount_sats),
            Amount::from_sat(req.mweb_fee_sats),
            Amount::from_sat(req.transparent_fee_sats),
            &selected,
            &runtime.secp,
        )
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    let signed = wallet
        .sign(&mut prepared.psbt, SignOptions::default())
        .map_err(|e| WalletError::Sign(e.to_string()))?;
    if !signed {
        return Err(WalletError::Sign("peg-in not fully signed".into()));
    }
    let tx = extract_prepared_mweb_pegin(&prepared.psbt)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    // A peg-in tx carries MWEB extension data that Electrum servers reject
    // ("TX decode failed"), so it must take the RPC/P2P path like other MWEB txs.
    broadcast_mweb_tx(&tx, rpc_url, peers, network)?;
    apply_pegin_locally(wallet, runtime, &tx, prepared.outputs, &req)
}

/// Credit MWEB outputs and debit transparent inputs for a peg-in we just built
/// (or repaired from RPC). Electrum never serves these txs, so the local apply
/// is the only way the transparent balance stays honest.
pub(crate) fn apply_pegin_locally(
    wallet: &mut PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    tx: &bdk_wallet::bitcoin::Transaction,
    outputs: Vec<bdk_mweb::MwebCoin>,
    req: &PeginRequest,
) -> Result<PeginResult, WalletError> {
    let tip = wallet.latest_checkpoint().height();
    let ts = now_ts();
    let mut output_ids = Vec::new();
    for mut coin in outputs {
        coin.is_pegin = true;
        coin.block_height = Some(tip);
        output_ids.push(hex::encode(coin.output_id));
        runtime.store.db_mut().insert(coin);
    }
    runtime.advance_receive_index();
    // Spend transparent inputs immediately. Without this, MWEB balance rises
    // while transparent UTXOs remain, and Total roughly doubles.
    wallet.apply_unconfirmed_txs([(tx.clone(), ts)]);
    let txid = tx.compute_txid().to_string();
    let fee_sats = req.transparent_fee_sats.saturating_add(req.mweb_fee_sats);
    // Net matches the transparent spend: peg-in amount + both fees. Deduped
    // against the BDK history row by txid once the graph has the tx.
    if !runtime.history.entries.iter().any(|e| e.id == txid) {
        runtime.history.record(MwebHistoryEntry {
            id: txid.clone(),
            kind: TxKind::Pegin,
            net_sats: -((req.amount_sats.saturating_add(fee_sats)) as i64),
            fee_sats: Some(fee_sats),
            timestamp: ts,
            output_ids,
            input_ids: Vec::new(),
            confirmed_height: None,
        });
    }
    Ok(PeginResult {
        txid,
        fee_sats,
        maturity_blocks: MWEB_PEGIN_MATURITY,
    })
}

/// Apply a peg-in transaction fetched from RPC into the transparent graph only
/// (MWEB coins are already in the store from broadcast / sync). Used to repair
/// wallets that pegged in before local apply existed.
pub(crate) fn apply_pegin_transparent_spend(
    wallet: &mut PersistedWallet<Connection>,
    tx: bdk_wallet::bitcoin::Transaction,
) {
    let txid = tx.compute_txid();
    if wallet.get_tx(txid).is_some() {
        return;
    }
    wallet.apply_unconfirmed_txs([(tx, now_ts())]);
}

/// Broadcast a transaction that carries MWEB data (peg-in, peg-out, MWEB send).
/// Electrum servers cannot relay these, so they never take the Electrum path.
///
/// P2P goes first: a peer relays the tx through the Dandelion++ stem phase,
/// while litecoind RPC submits it as our own and gives up that origin privacy.
/// RPC is the fallback when no peer accepts it.
fn broadcast_mweb_tx(
    tx: &bdk_wallet::bitcoin::Transaction,
    rpc_url: Option<&str>,
    peers: &[String],
    network: WalletNetwork,
) -> Result<(), WalletError> {
    let p2p_err = match broadcast_via_p2p(tx, resolve_reachable_peers(peers)?, network) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    // Still prefer a stranger's node over our own RPC: relaying through a peer
    // we did not author the tx on is the whole point of the P2P path.
    let discovered = crate::discovery::discover_mweb_peers(network);
    if !discovered.is_empty() {
        match broadcast_via_p2p(tx, discovered, network) {
            Ok(()) => return Ok(()),
            Err(e) => crate::diag::log(format!(
                "MWEB broadcast: discovered peers also failed ({e})"
            )),
        }
    }
    let Some(url) = rpc_url else {
        return Err(WalletError::Mweb(format!(
            "could not reach any MWEB peer to broadcast this transaction ({p2p_err}) — \
             check your connection, or set a Litecoin RPC URL in Settings"
        )));
    };
    match rpc::send_raw_transaction(url, &serialize_hex(tx)) {
        Ok(_) => {
            crate::diag::log(format!(
                "MWEB broadcast: fell back to litecoind RPC ({p2p_err})"
            ));
            Ok(())
        }
        Err(rpc_err) => Err(WalletError::Mweb(format!(
            "could not broadcast over P2P ({p2p_err}) or litecoind RPC ({rpc_err})"
        ))),
    }
}

/// Offer the tx to each peer in turn until one confirms acceptance.
///
/// [`BroadcastAck::Sent`] is optimistic (peer may not have relayed). Keep
/// trying other peers for a Confirmed ack before accepting a bare Sent.
fn broadcast_via_p2p(
    tx: &bdk_wallet::bitcoin::Transaction,
    addrs: Vec<std::net::SocketAddr>,
    network: WalletNetwork,
) -> Result<(), WalletError> {
    if addrs.is_empty() {
        return Err(WalletError::Mweb("no MWEB P2P peers reachable".into()));
    }
    let bdk_net = network.to_bitcoin_network();
    let mut last_err = String::from("no MWEB peers reachable");
    let mut sent_ok: Option<std::net::SocketAddr> = None;
    for addr in addrs {
        match TcpMwebPeer::connect(addr, bdk_net) {
            Ok(mut peer) => match peer.broadcast_tx(tx) {
                Ok(BroadcastAck::Confirmed) => {
                    crate::diag::log(format!("MWEB broadcast: {addr} accepted the transaction"));
                    return Ok(());
                }
                Ok(BroadcastAck::Sent) => {
                    crate::diag::log(format!(
                        "MWEB broadcast: sent to {addr}; acceptance not confirmed before deadline — trying more peers"
                    ));
                    if sent_ok.is_none() {
                        sent_ok = Some(addr);
                    }
                }
                Err(e) => {
                    last_err = format!(
                        "{addr}: {}",
                        crate::error::humanize_broadcast_error(&e.to_string())
                    )
                }
            },
            Err(e) => last_err = format!("{addr}: {e}"),
        }
    }
    if let Some(addr) = sent_ok {
        crate::diag::log(format!(
            "MWEB broadcast: no peer confirmed acceptance; keeping optimistic send via {addr}"
        ));
        return Ok(());
    }
    Err(WalletError::Mweb(format!(
        "P2P broadcast failed: {last_err}"
    )))
}

pub fn mweb_send(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    rpc_url: Option<&str>,
    peers: &[String],
    req: MwebSendRequest,
    network: WalletNetwork,
) -> Result<MwebBroadcastResult, WalletError> {
    let net = network.to_bitcoin_network();
    let dest = Address::from_str(&req.address)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .require_network(net)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(data_dir)?.ids;
    let selected = normalize_selected_ids(req.selected_output_ids.as_deref());
    let needed = req.amount_sats.saturating_add(req.fee_sats);
    let coins = resolve_spend_coins(
        runtime.store.db(),
        tip,
        &frozen,
        selected.as_deref(),
        needed,
        "spending",
    )?;
    let kind = match network {
        WalletNetwork::Mainnet => NetworkKind::Main,
        WalletNetwork::Testnet => NetworkKind::Test,
    };
    let mut funded = bdk_mweb::fund_mweb_spend(
        coins,
        vec![(dest, req.amount_sats)],
        vec![],
        req.fee_sats,
        &runtime.keys,
        CHANGE_ADDRESS_INDEX,
        kind,
        &runtime.secp,
    )
    .map_err(|e| WalletError::Mweb(e.to_string()))?;
    let spent_ids: Vec<_> = funded.spent_coins.iter().map(|c| c.output_id).collect();
    let (tx, change) = wallet
        .sign_and_extract_funded_mweb(&mut funded, &runtime.keys, &runtime.secp)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    broadcast_mweb_tx(&tx, rpc_url, peers, network)?;
    let wtxid = tx.compute_wtxid().to_string();
    for id in &spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::new();
    if let Some(mut change) = change {
        change.block_height = None;
        output_ids.push(hex::encode(change.output_id));
        runtime.store.db_mut().insert(change);
    }
    runtime.history.record(MwebHistoryEntry {
        id: wtxid.clone(),
        kind: TxKind::MwebSend,
        net_sats: -((req.amount_sats.saturating_add(req.fee_sats)) as i64),
        fee_sats: Some(req.fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: spent_ids.iter().map(hex::encode).collect(),
        confirmed_height: None,
    });
    Ok(MwebBroadcastResult {
        wtxid,
        fee_sats: req.fee_sats,
        addresses: Vec::new(),
    })
}

/// List unspent MWEB coins (including immature / unconfirmed) for the Coins screen.
pub fn list_mweb_unspent(
    runtime: &MwebRuntime,
    tip_height: u32,
    data_dir: &Path,
) -> Vec<MwebUtxoRecord> {
    let frozen = mweb_frozen::read_ids(data_dir)
        .map(|f| f.ids)
        .unwrap_or_default();
    let labels = utxo_labels::read_labels(data_dir)
        .map(|f| f.labels)
        .unwrap_or_default();
    let (depth, job) = crate::churn::annotations(data_dir)
        .unwrap_or_else(|_| (std::collections::BTreeMap::new(), None));
    let mut rows: Vec<MwebUtxoRecord> = runtime
        .store
        .db()
        .unspent_vec()
        .into_iter()
        .map(|c| {
            let confirmations = match c.block_height {
                Some(h) if tip_height >= h => tip_height.saturating_sub(h).saturating_add(1),
                _ => 0,
            };
            let mature = c.is_spendable(tip_height, MWEB_PEGIN_MATURITY);
            let maturity_blocks_left = if mature {
                0
            } else if c.is_pegin {
                match c.block_height {
                    Some(h) => {
                        let confs = tip_height.saturating_add(1).saturating_sub(h);
                        MWEB_PEGIN_MATURITY.saturating_sub(confs)
                    }
                    None => MWEB_PEGIN_MATURITY,
                }
            } else {
                1
            };
            let output_id = hex::encode(c.output_id);
            let locked = frozen.contains(&output_id);
            let label = labels.get(&output_id).cloned().unwrap_or_default();
            let fields = churn_fields(&output_id, c.is_pegin, &depth, job.as_ref());
            MwebUtxoRecord {
                output_id,
                amount_sats: c.amount,
                confirmations,
                mature,
                maturity_blocks_left,
                locked,
                label,
                from_pegin: fields.from_pegin,
                non_solo_blocks: fields.non_solo_blocks,
                last_other_kernels: fields.last_other_kernels,
                last_other_outputs: fields.last_other_outputs,
                hops: fields.hops,
                churn_phase: fields.churn_phase,
                churn_error: fields.churn_error,
                churn_target: fields.churn_target,
                churn_counted: fields.churn_counted,
                churn_cover_hold: fields.churn_cover_hold,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.confirmations
            .cmp(&a.confirmations)
            .then_with(|| b.amount_sats.cmp(&a.amount_sats))
            .then_with(|| a.output_id.cmp(&b.output_id))
    });
    rows
}

struct ChurnFields {
    from_pegin: bool,
    non_solo_blocks: Option<u32>,
    last_other_kernels: Option<u64>,
    last_other_outputs: Option<u64>,
    hops: Vec<crate::dto::ChurnHop>,
    churn_phase: Option<crate::dto::ChurnPhase>,
    churn_error: Option<String>,
    churn_target: Option<u32>,
    churn_counted: Option<u32>,
    churn_cover_hold: Option<crate::dto::CoverHold>,
}

fn churn_fields(
    output_id: &str,
    is_pegin: bool,
    depth: &std::collections::BTreeMap<String, crate::dto::ChurnDepthRecord>,
    job: Option<&crate::churn::ChurnJob>,
) -> ChurnFields {
    let record = depth.get(output_id);
    let from_pegin = is_pegin || record.is_some_and(|r| r.from_pegin);
    let non_solo_blocks = if let Some(record) = record {
        Some(record.non_solo_blocks)
    } else if is_pegin {
        Some(0)
    } else {
        None
    };
    let (churn_phase, churn_error, churn_target, churn_counted, churn_cover_hold) = match job {
        Some(job) if job.current_output_id == output_id && job.phase.is_active() => (
            Some(job.phase),
            job.last_error.clone(),
            Some(job.target_depth),
            Some(job.effective_depth),
            job.cover_hold,
        ),
        Some(job)
            if job.current_output_id == output_id && job.phase == crate::dto::ChurnPhase::Done =>
        {
            (
                None,
                None,
                Some(job.target_depth),
                Some(job.effective_depth),
                None,
            )
        }
        _ => (None, None, None, None, None),
    };
    ChurnFields {
        from_pegin,
        non_solo_blocks,
        last_other_kernels: record.and_then(|r| r.last_other_kernels),
        last_other_outputs: record.and_then(|r| r.last_other_outputs),
        hops: record.map(|r| r.hops.clone()).unwrap_or_default(),
        churn_phase,
        churn_error,
        churn_target,
        churn_counted,
        churn_cover_hold,
    }
}

/// Height and output-MMR leaf of an unspent coin. Either may still be unknown.
#[derive(Debug, Clone, Copy)]
pub struct CoinAnchor {
    pub height: Option<u32>,
    pub leaf_index: Option<u64>,
}

pub fn coin_anchor(runtime: &MwebRuntime, output_id_hex: &str) -> Option<CoinAnchor> {
    let id = decode_output_id(output_id_hex)?;
    let coin = runtime.store.db().get(&id)?;
    Some(CoinAnchor {
        height: coin.block_height,
        leaf_index: coin.leaf_index,
    })
}

/// Replace the height stamped at detection time with the block that contains the coin.
pub fn set_coin_block_height(runtime: &mut MwebRuntime, output_id_hex: &str, height: u32) -> bool {
    let Some(id) = decode_output_id(output_id_hex) else {
        return false;
    };
    let db = runtime.store.db_mut();
    if db.get(&id).is_none() {
        return false;
    }
    db.set_block_height(&id, height);
    true
}

/// Remember the output-MMR leaf once a peer has shown which UTXO this coin is.
pub fn set_coin_leaf_index(
    runtime: &mut MwebRuntime,
    output_id_hex: &str,
    leaf_index: u64,
) -> bool {
    let Some(id) = decode_output_id(output_id_hex) else {
        return false;
    };
    runtime.store.db_mut().set_leaf_index(&id, leaf_index)
}

/// Put a self-spend that never landed back on the coin it spent.
///
/// Returns that coin's id. Refuses when an output from the spend already has a
/// height or leaf, which means the transaction is on chain.
pub fn recall_unlanded_spend(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    wtxid: &str,
) -> Option<String> {
    let entry = history.entries.iter().find(|e| e.id == wtxid)?.clone();
    if entry.confirmed_height.is_some() || entry.input_ids.is_empty() {
        return None;
    }
    for id_hex in &entry.output_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        if db
            .get(&id)
            .is_some_and(|coin| coin.block_height.is_some() || coin.leaf_index.is_some())
        {
            return None;
        }
    }
    let restored = entry.input_ids[0].clone();
    for id_hex in &entry.input_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        if let Some(coin) = db.get_spent(&id).cloned() {
            db.insert(coin);
        }
    }
    for id_hex in &entry.output_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        let _ = db.mark_spent(&id);
    }
    history.forget_ids(std::slice::from_ref(&entry.id));
    Some(restored)
}

/// `Some(true)` when every input that has a leaf index is still in the leafset.
/// `Some(false)` when one of those leaves has been spent. `None` when the
/// leafset or the input leaves cannot answer.
pub fn churn_inputs_still_unspent(runtime: &MwebRuntime, wtxid: &str) -> Option<bool> {
    if runtime.sync_state.leafset.is_empty() {
        return None;
    }
    let entry = runtime.history.entries.iter().find(|e| e.id == wtxid)?;
    let mut saw_leaf = false;
    for id_hex in &entry.input_ids {
        let Some(id) = decode_output_id(id_hex) else {
            continue;
        };
        let Some(coin) = runtime
            .store
            .db()
            .get(&id)
            .or_else(|| runtime.store.db().get_spent(&id))
        else {
            continue;
        };
        let Some(leaf) = coin.leaf_index else {
            continue;
        };
        saw_leaf = true;
        if !leafset_has_leaf(&runtime.sync_state.leafset, leaf) {
            return Some(false);
        }
    }
    if saw_leaf {
        Some(true)
    } else {
        None
    }
}

/// Amount and maturity for a self-spend preview. Does not apply the freeze list.
pub struct ChurnCoinInfo {
    pub amount: u64,
    pub mature: bool,
    pub is_pegin: bool,
}

pub fn churn_coin_info(
    runtime: &MwebRuntime,
    tip_height: u32,
    output_id_hex: &str,
) -> Result<ChurnCoinInfo, WalletError> {
    let id = decode_output_id(output_id_hex.trim()).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "invalid MWEB output id '{output_id_hex}' (expected 32-byte hex)"
        ))
    })?;
    let coin = runtime.store.db().get(&id).cloned().ok_or_else(|| {
        WalletError::BuildTx(format!(
            "selected MWEB coin {output_id_hex} is not an unspent output in this wallet"
        ))
    })?;
    Ok(ChurnCoinInfo {
        amount: coin.amount,
        mature: coin.is_spendable(tip_height, MWEB_PEGIN_MATURITY),
        is_pegin: coin.is_pegin,
    })
}

/// Configured peers first, then any public peers not already in that list.
///
/// A configured node that is down must not be the only place scoring can look.
/// Sync and broadcast already fall through to DNS seeds in that case.
pub(crate) fn merge_header_peers(
    configured: &[std::net::SocketAddr],
    discovered: &[std::net::SocketAddr],
) -> Vec<std::net::SocketAddr> {
    let mut addrs = configured.to_vec();
    for addr in discovered {
        if !addrs.contains(addr) {
            addrs.push(*addr);
        }
    }
    addrs
}

/// Peers to ask for an MWEB header: the peer that served the last sync, the
/// user's node, then public seeds.
pub fn peers_for_headers(
    peers: &[String],
    network: WalletNetwork,
    preferred: Option<std::net::SocketAddr>,
) -> Vec<std::net::SocketAddr> {
    let mut configured = probe_reachable(resolve_peers(peers).unwrap_or_default());
    if let Some(first) = preferred {
        configured.retain(|addr| *addr != first);
        configured.insert(0, first);
    }
    let discovered = crate::discovery::discover_mweb_peers(network);
    merge_header_peers(&configured, &discovered)
}

/// MMR sizes for several blocks. One connection serves as many as it can; the next peer fills gaps.
pub fn fetch_mmr_sizes_many(
    addrs: &[std::net::SocketAddr],
    network: WalletNetwork,
    hashes: &[bdk_wallet::bitcoin::BlockHash],
) -> Vec<Option<crate::churn::MmrSizes>> {
    let mut out = vec![None; hashes.len()];
    if hashes.is_empty() {
        return out;
    }
    let bdk_net = network.to_bitcoin_network();
    for addr in addrs {
        if out.iter().all(|slot| slot.is_some()) {
            break;
        }
        let Ok(mut peer) = TcpMwebPeer::connect(*addr, bdk_net) else {
            continue;
        };
        for (i, hash) in hashes.iter().enumerate() {
            if out[i].is_some() {
                continue;
            }
            let Ok(hdr) = MwebUtxoSource::get_header(&mut peer, *hash) else {
                break;
            };
            out[i] = Some(crate::churn::MmrSizes {
                kernel_mmr_size: hdr.mweb_header.kernel_mmr_size,
                output_mmr_size: hdr.mweb_header.output_mmr_size,
            });
        }
    }
    out
}

/// One peer connection reused across the header reads for a single hop.
pub struct MmrLookup {
    addrs: Vec<std::net::SocketAddr>,
    network: WalletNetwork,
    peer_at: usize,
    peer: Option<TcpMwebPeer>,
    cache: HashMap<bdk_wallet::bitcoin::BlockHash, crate::churn::MmrSizes>,
}

impl MmrLookup {
    pub fn new(addrs: Vec<std::net::SocketAddr>, network: WalletNetwork) -> Self {
        Self {
            addrs,
            network,
            peer_at: 0,
            peer: None,
            cache: HashMap::new(),
        }
    }

    /// Peers this lookup will try, in order.
    pub fn peers(&self) -> &[std::net::SocketAddr] {
        &self.addrs
    }

    pub fn get(&mut self, hash: bdk_wallet::bitcoin::BlockHash) -> Option<crate::churn::MmrSizes> {
        if let Some(hit) = self.cache.get(&hash) {
            return Some(*hit);
        }
        let bdk_net = self.network.to_bitcoin_network();
        while self.peer_at < self.addrs.len() {
            if self.peer.is_none() {
                match TcpMwebPeer::connect(self.addrs[self.peer_at], bdk_net) {
                    Ok(peer) => self.peer = Some(peer),
                    Err(_) => {
                        self.peer_at += 1;
                        continue;
                    }
                }
            }
            let peer = self.peer.as_mut().expect("peer was just connected");
            match MwebUtxoSource::get_header(peer, hash) {
                Ok(hdr) => {
                    let sizes = crate::churn::MmrSizes {
                        kernel_mmr_size: hdr.mweb_header.kernel_mmr_size,
                        output_mmr_size: hdr.mweb_header.output_mmr_size,
                    };
                    self.cache.insert(hash, sizes);
                    return Some(sizes);
                }
                Err(_) => {
                    self.peer = None;
                    self.peer_at += 1;
                }
            }
        }
        None
    }
}

/// Whether a scan of unspent leaves after broadcast found our output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainLeaf {
    Found(u64),
    Absent,
    Unread,
}

/// Look for `output_id_hex` among unspent leaves in `[start_index, end_output_mmr)`.
///
/// A short or empty batch means the peer has no further unspent leaves. A full
/// batch that never reaches `end_output_mmr` is unread, so the caller does not
/// treat a truncated reply as proof the output is missing.
pub fn find_output_leaf(
    addrs: &[std::net::SocketAddr],
    network: WalletNetwork,
    tip_hash: bdk_wallet::bitcoin::BlockHash,
    start_index: u64,
    end_output_mmr: u64,
    output_id_hex: &str,
) -> ChainLeaf {
    if start_index >= end_output_mmr {
        return ChainLeaf::Absent;
    }
    let Some(want) = decode_output_id(output_id_hex) else {
        return ChainLeaf::Unread;
    };
    let bdk_net = network.to_bitcoin_network();
    for addr in addrs {
        let Ok(mut peer) = TcpMwebPeer::connect(*addr, bdk_net) else {
            continue;
        };
        let mut start = start_index;
        let mut covered = true;
        for _ in 0..4 {
            let req = GetMwebUtxos {
                block_hash: tip_hash,
                start_index: start,
                num_requested: MAX_REQUESTED_MWEB_UTXOS,
                output_format: OUTPUT_FORMAT_FULL,
            };
            let Ok(batch) = MwebUtxoSource::get_utxos(&mut peer, req) else {
                covered = false;
                break;
            };
            if batch.output_format != OUTPUT_FORMAT_FULL {
                covered = false;
                break;
            }
            if batch.utxos.is_empty() {
                return ChainLeaf::Absent;
            }
            for entry in &batch.utxos {
                if bdk_mweb::scan::output_id(&entry.output) == want {
                    return ChainLeaf::Found(entry.leaf_index);
                }
            }
            let last = batch
                .utxos
                .last()
                .map(|entry| entry.leaf_index)
                .unwrap_or(start);
            if (batch.utxos.len() as u16) < MAX_REQUESTED_MWEB_UTXOS
                || last.saturating_add(1) >= end_output_mmr
            {
                return ChainLeaf::Absent;
            }
            start = last.saturating_add(1);
        }
        if covered {
            return ChainLeaf::Unread;
        }
    }
    ChainLeaf::Unread
}

/// Resolve one mature, unfrozen MWEB coin by output id.
pub fn select_mweb_coin(
    db: &MwebCoinDatabase,
    output_id_hex: &str,
    tip_height: u32,
    frozen: &BTreeSet<String>,
    action: &str,
) -> Result<bdk_mweb::MwebCoin, WalletError> {
    let id = decode_output_id(output_id_hex.trim()).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "invalid MWEB output id '{output_id_hex}' (expected 32-byte hex)"
        ))
    })?;
    let coin = db.get(&id).cloned().ok_or_else(|| {
        WalletError::BuildTx(format!(
            "selected MWEB coin {output_id_hex} is not an unspent output in this wallet"
        ))
    })?;
    let id_hex = hex::encode(coin.output_id);
    if frozen.contains(&id_hex) {
        return Err(WalletError::BuildTx(format!(
            "selected private coin is frozen — unfreeze it before {action}"
        )));
    }
    if !coin.is_spendable(tip_height, MWEB_PEGIN_MATURITY) {
        return Err(WalletError::BuildTx(
            "selected private coin is not yet spendable (unconfirmed or maturing peg-in)".into(),
        ));
    }
    Ok(coin)
}

/// Resolve one mature MWEB coin by output id. Refuses greedy multi-coin selection.
pub fn select_split_coin(
    db: &MwebCoinDatabase,
    output_id_hex: &str,
    tip_height: u32,
    frozen: &BTreeSet<String>,
) -> Result<bdk_mweb::MwebCoin, WalletError> {
    select_mweb_coin(db, output_id_hex, tip_height, frozen, "splitting")
}

fn owned_coin_from_staged(
    staged: &bdk_mweb::StagedMwebOutput,
    index: u32,
    keys: &MasterKeys,
    secp: &Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
) -> Result<bdk_mweb::MwebCoin, WalletError> {
    let ke = staged
        .output
        .message
        .standard_fields
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("missing standard fields".into()))?
        .key_exchange_pubkey;
    let (t, spend) = bdk_mweb::tx_builder::shared_secret_and_spend_for_owned(
        keys,
        index,
        &ke,
        &staged.output.receiver_public_key,
        secp,
    )
    .map_err(|e| WalletError::Mweb(e.to_string()))?;
    Ok(bdk_mweb::MwebCoin {
        output_id: bdk_mweb::output_id(&staged.output),
        commitment: staged.output.commitment,
        amount: staged.amount,
        address_index: index,
        blind: staged.raw_blind,
        shared_secret: t,
        spend_key: Some(spend),
        block_height: None,
        is_pegin: false,
        leaf_index: None,
    })
}

/// 1-in-N-out MWEB self-split. Persists `receive_index` before broadcast.
pub fn mweb_split(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    rpc_url: Option<&str>,
    peers: &[String],
    output_id_hex: &str,
    recipient_amounts: &[u64],
    fee_sats: u64,
    network: WalletNetwork,
) -> Result<SplitResult, WalletError> {
    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(data_dir)?.ids;
    let coin = select_split_coin(runtime.store.db(), output_id_hex, tip, &frozen)?;
    if recipient_amounts.is_empty() {
        return Err(WalletError::BuildTx(
            "split needs at least one output".into(),
        ));
    }
    let kind = match network {
        WalletNetwork::Mainnet => NetworkKind::Main,
        WalletNetwork::Testnet => NetworkKind::Test,
    };
    let start = runtime.receive_index;
    let mut recipients = Vec::with_capacity(recipient_amounts.len());
    let mut indexes = Vec::with_capacity(recipient_amounts.len());
    for (i, amount) in recipient_amounts.iter().enumerate() {
        let idx = start.saturating_add(i as u32);
        let addr = runtime
            .keys
            .address(idx, kind, &runtime.secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        recipients.push((addr, *amount));
        indexes.push(idx);
    }
    runtime.receive_index = start.saturating_add(recipient_amounts.len() as u32);
    // Persist indexes before broadcast so a landed tx cannot reuse them.
    runtime.persist(data_dir)?;

    let mut funded = bdk_mweb::fund_mweb_spend(
        vec![coin],
        recipients,
        vec![],
        fee_sats,
        &runtime.keys,
        CHANGE_ADDRESS_INDEX,
        kind,
        &runtime.secp,
    )
    .map_err(|e| WalletError::Mweb(e.to_string()))?;
    if funded.spent_coins.len() != 1 {
        return Err(WalletError::BuildTx("Split uses exactly one coin".into()));
    }
    let spent_ids: Vec<_> = funded.spent_coins.iter().map(|c| c.output_id).collect();
    let (tx, _change) = wallet
        .sign_and_extract_funded_mweb(&mut funded, &runtime.keys, &runtime.secp)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    broadcast_mweb_tx(&tx, rpc_url, peers, network)?;
    let wtxid = tx.compute_wtxid().to_string();
    for id in &spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::new();
    let mut recip_i = 0usize;
    for staged in &funded.staged_outputs {
        let index = if let Some(ci) = staged.change_index {
            ci
        } else {
            let idx = *indexes
                .get(recip_i)
                .ok_or_else(|| WalletError::Mweb("split staged output count mismatch".into()))?;
            recip_i += 1;
            idx
        };
        let mut owned = owned_coin_from_staged(staged, index, &runtime.keys, &runtime.secp)?;
        owned.block_height = None;
        output_ids.push(hex::encode(owned.output_id));
        runtime.store.db_mut().insert(owned);
    }
    runtime.history.record(MwebHistoryEntry {
        id: wtxid.clone(),
        kind: TxKind::MwebSplit,
        net_sats: -(fee_sats as i64),
        fee_sats: Some(fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: spent_ids.iter().map(hex::encode).collect(),
        confirmed_height: None,
    });
    Ok(SplitResult {
        txid: wtxid,
        fee_sats,
        output_count: recipient_amounts.len() as u32,
    })
}

/// One signed 1-in-1 self-spend, not yet broadcast.
#[derive(Clone)]
pub struct PreparedHop {
    pub raw_hex: String,
    pub txid: String,
    pub wtxid: String,
    pub spent_output_id: String,
    pub created_output_id: String,
    pub receive_index: u32,
    pub fee_sats: u64,
    pub created: bdk_mweb::MwebCoin,
}

/// Sign `hops` dependent self-spends. The receive index advances and is persisted
/// before the function returns, including when a later hop fails to build.
pub fn sign_self_spend_hops(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    mut coin: bdk_mweb::MwebCoin,
    hops: u32,
    fee_sats: u64,
    network: WalletNetwork,
) -> Result<Vec<PreparedHop>, WalletError> {
    if hops == 0 {
        return Err(WalletError::BuildTx(
            "Choose at least one self-spend.".into(),
        ));
    }
    let kind = match network {
        WalletNetwork::Mainnet => NetworkKind::Main,
        WalletNetwork::Testnet => NetworkKind::Test,
    };
    let start = runtime.receive_index;
    runtime.receive_index = start.saturating_add(hops);
    runtime.persist(data_dir)?;

    let mut prepared = Vec::with_capacity(hops as usize);
    for offset in 0..hops {
        if coin.amount <= fee_sats {
            return Err(WalletError::BuildTx(
                "This coin is too small to pay the fee.".into(),
            ));
        }
        let index = start.saturating_add(offset);
        let amount = coin.amount - fee_sats;
        let spent_output_id = hex::encode(coin.output_id);
        let addr = runtime
            .keys
            .address(index, kind, &runtime.secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        let mut funded = bdk_mweb::fund_mweb_spend(
            vec![coin],
            vec![(addr, amount)],
            vec![],
            fee_sats,
            &runtime.keys,
            CHANGE_ADDRESS_INDEX,
            kind,
            &runtime.secp,
        )
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
        if funded.spent_coins.len() != 1 || funded.staged_outputs.len() != 1 {
            return Err(WalletError::BuildTx(
                "A self-spend must spend one coin and create one output.".into(),
            ));
        }
        let (tx, _change) = wallet
            .sign_and_extract_funded_mweb(&mut funded, &runtime.keys, &runtime.secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        let staged = &funded.staged_outputs[0];
        let mut owned = owned_coin_from_staged(staged, index, &runtime.keys, &runtime.secp)?;
        owned.block_height = None;
        let created_output_id = hex::encode(owned.output_id);
        prepared.push(PreparedHop {
            raw_hex: serialize_hex(&tx),
            txid: tx.compute_txid().to_string(),
            wtxid: tx.compute_wtxid().to_string(),
            spent_output_id,
            created_output_id,
            receive_index: index,
            fee_sats,
            created: owned.clone(),
        });
        coin = owned;
    }
    Ok(prepared)
}

/// Mark the spent coin and remember the created output. Does not broadcast.
pub fn apply_prepared_output(
    runtime: &mut MwebRuntime,
    wtxid: &str,
    spent_output_id: &str,
    created: bdk_mweb::MwebCoin,
    fee_sats: u64,
) -> Result<(), WalletError> {
    let spent = decode_output_id(spent_output_id).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "invalid MWEB output id '{spent_output_id}' (expected 32-byte hex)"
        ))
    })?;
    let _ = runtime.store.db_mut().mark_spent(&spent);
    let output_id = hex::encode(created.output_id);
    runtime.store.db_mut().insert(created);
    if !runtime
        .history
        .entries
        .iter()
        .any(|entry| entry.id == wtxid)
    {
        runtime.history.record(MwebHistoryEntry {
            id: wtxid.to_string(),
            kind: TxKind::MwebChurn,
            net_sats: -(fee_sats as i64),
            fee_sats: Some(fee_sats),
            timestamp: now_ts(),
            output_ids: vec![output_id],
            input_ids: vec![spent_output_id.to_string()],
            confirmed_height: None,
        });
    }
    Ok(())
}

/// Broadcast a transaction that was signed earlier.
pub fn broadcast_prepared_raw(
    raw_hex: &str,
    rpc_url: Option<&str>,
    peers: &[String],
    network: WalletNetwork,
) -> Result<(), WalletError> {
    let bytes = hex::decode(raw_hex).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let tx: Transaction = deserialize(&bytes).map_err(|e| WalletError::Mweb(e.to_string()))?;
    broadcast_mweb_tx(&tx, rpc_url, peers, network)
}

/// Other people's MWEB transactions in the node mempool.
///
/// A transaction counts when it carries an MWEB payload or is a HogEx integration.
/// Ids in `own` (txid or wtxid) are skipped, including this wallet's other spends.
pub fn count_foreign_mweb_mempool(
    rpc_url: &str,
    own: &BTreeSet<String>,
) -> Result<u64, WalletError> {
    let ids = crate::rpc::get_raw_mempool(rpc_url)?;
    let mut count = 0u64;
    for txid in ids {
        let hex_tx = match crate::rpc::get_raw_transaction_hex(rpc_url, &txid) {
            Ok(hex_tx) => hex_tx,
            Err(_) => continue,
        };
        let Ok(bytes) = hex::decode(&hex_tx) else {
            continue;
        };
        let Ok(tx) = deserialize::<Transaction>(&bytes) else {
            continue;
        };
        if tx.mw_tx.is_none() && !tx.is_hog_ex {
            continue;
        }
        let id = tx.compute_txid().to_string();
        let wtxid = tx.compute_wtxid().to_string();
        if crate::churn::is_foreign_id(&id, &wtxid, own) {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

/// The armed hop still spends a coin this wallet can send.
///
/// A local mark (spent in the coin db, still in the leafset) counts as ours.
/// A leaf that has left the leafset before we broadcast means someone else spent it.
pub fn prepared_input_ok(
    runtime: &MwebRuntime,
    spent_output_id: &str,
    broadcast: bool,
    wtxid: &str,
) -> bool {
    if broadcast {
        return churn_inputs_still_unspent(runtime, wtxid) != Some(false);
    }
    let Some(id) = decode_output_id(spent_output_id) else {
        return false;
    };
    if runtime.store.db().get(&id).is_some() {
        return true;
    }
    let Some(coin) = runtime.store.db().get_spent(&id) else {
        return false;
    };
    let Some(leaf) = coin.leaf_index else {
        return true;
    };
    if runtime.sync_state.leafset.is_empty() {
        return true;
    }
    leafset_has_leaf(&runtime.sync_state.leafset, leaf)
}

/// Forget a created output that was never broadcast after the input was spent elsewhere.
pub fn drop_unbroadcast_output(runtime: &mut MwebRuntime, wtxid: &str, created_output_id: &str) {
    if let Some(id) = decode_output_id(created_output_id) {
        let _ = runtime.store.db_mut().mark_spent(&id);
    }
    runtime.history.forget_ids(&[wtxid.to_string()]);
}

pub fn coin_from_value(value: &serde_json::Value) -> Result<bdk_mweb::MwebCoin, WalletError> {
    serde_json::from_value(value.clone()).map_err(|e| WalletError::Mweb(e.to_string()))
}

pub fn pegout(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    rpc_url: Option<&str>,
    peers: &[String],
    req: PegoutRequest,
    network: WalletNetwork,
) -> Result<MwebBroadcastResult, WalletError> {
    let net = network.to_bitcoin_network();
    let dust_relay = FeeRate::from_sat_per_vb(30)
        .ok_or_else(|| WalletError::BuildTx("internal dust fee rate".into()))?;

    let parse_dest = |raw: &str| -> Result<Address, WalletError> {
        Address::from_str(raw)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .require_network(net)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))
    };

    let pegouts: Vec<(ScriptBuf, u64)> = if req.per_coin {
        if req.addresses.len() != req.output_amounts.len() || req.output_amounts.is_empty() {
            return Err(WalletError::BuildTx(
                "per-coin peg-out needs one fresh public address per private coin".into(),
            ));
        }
        let mut out = Vec::with_capacity(req.output_amounts.len());
        for (addr, amount) in req.addresses.iter().zip(req.output_amounts.iter()) {
            let dest = parse_dest(addr)?;
            let min_non_dust = dest.script_pubkey().minimal_non_dust_custom(dust_relay);
            if Amount::from_sat(*amount) < min_non_dust {
                return Err(WalletError::BuildTx(format!(
                    "peg-out amount {} litoshis is below dust limit ({})",
                    amount,
                    min_non_dust.to_sat()
                )));
            }
            out.push((dest.script_pubkey(), *amount));
        }
        out
    } else {
        let dest = parse_dest(&req.address)?;
        let min_non_dust = dest.script_pubkey().minimal_non_dust_custom(dust_relay);
        if Amount::from_sat(req.amount_sats) < min_non_dust {
            return Err(WalletError::BuildTx(format!(
                "peg-out amount {} litoshis is below dust limit ({})",
                req.amount_sats,
                min_non_dust.to_sat()
            )));
        }
        vec![(dest.script_pubkey(), req.amount_sats)]
    };

    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(data_dir)?.ids;
    let selected = normalize_selected_ids(req.selected_output_ids.as_deref());
    let needed = req.amount_sats.saturating_add(req.fee_sats);
    let coins = resolve_spend_coins(
        runtime.store.db(),
        tip,
        &frozen,
        selected.as_deref(),
        needed,
        "swapping",
    )?;
    if req.per_coin && coins.len() != req.output_amounts.len() {
        return Err(WalletError::BuildTx(
            "per-coin peg-out coin count does not match planned public outputs".into(),
        ));
    }
    let kind = match network {
        WalletNetwork::Mainnet => NetworkKind::Main,
        WalletNetwork::Testnet => NetworkKind::Test,
    };
    let mut funded = bdk_mweb::fund_mweb_spend(
        coins,
        vec![],
        pegouts,
        req.fee_sats,
        &runtime.keys,
        CHANGE_ADDRESS_INDEX,
        kind,
        &runtime.secp,
    )
    .map_err(|e| WalletError::Mweb(e.to_string()))?;
    let spent_ids: Vec<_> = funded.spent_coins.iter().map(|c| c.output_id).collect();
    let (tx, change) = wallet
        .sign_and_extract_funded_mweb(&mut funded, &runtime.keys, &runtime.secp)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    broadcast_mweb_tx(&tx, rpc_url, peers, network)?;
    let wtxid = tx.compute_wtxid().to_string();
    for id in &spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::new();
    if let Some(mut change) = change {
        change.block_height = None;
        output_ids.push(hex::encode(change.output_id));
        runtime.store.db_mut().insert(change);
    }
    runtime.history.record(MwebHistoryEntry {
        id: wtxid.clone(),
        kind: TxKind::Pegout,
        net_sats: -((req.amount_sats.saturating_add(req.fee_sats)) as i64),
        fee_sats: Some(req.fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: spent_ids.iter().map(hex::encode).collect(),
        confirmed_height: None,
    });
    let addresses = if req.per_coin {
        req.addresses
    } else if !req.address.is_empty() {
        vec![req.address]
    } else {
        Vec::new()
    };
    Ok(MwebBroadcastResult {
        wtxid,
        fee_sats: req.fee_sats,
        addresses,
    })
}

#[cfg(test)]
mod pegin_balance_tests {
    use super::*;
    use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
    use bdk_wallet::bitcoin::hex::FromHex;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::test_utils::get_funded_wallet_wpkh;
    use bdk_wallet::{extract_prepared_mweb_pegin, SignOptions};

    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn pegin_apply_does_not_double_count_balance() {
        let (mut wallet, _) = get_funded_wallet_wpkh();
        let prior_transparent = wallet.balance().total().to_sat();
        assert!(prior_transparent > 0);

        let seed = <Vec<u8>>::from_hex(SEED_HEX).unwrap();
        let secp = Secp256k1::new();
        let keys = MasterKeys::from_seed(
            &seed,
            Network::Regtest,
            MasterKeyScheme::LitecoinCore,
            &secp,
        )
        .unwrap();

        let pegin_amount = Amount::from_sat(20_000);
        let mweb_fee = Amount::from_sat(1_000);
        let transparent_fee = Amount::from_sat(500);
        let mut prepared = wallet
            .prepare_mweb_pegin(&keys, 2, pegin_amount, mweb_fee, transparent_fee, &secp)
            .expect("prepare_mweb_pegin");
        assert!(wallet
            .sign(&mut prepared.psbt, SignOptions::default())
            .expect("sign"));
        let tx = extract_prepared_mweb_pegin(&prepared.psbt).expect("extract");

        let mut db = MwebCoinDatabase::new();
        let tip = wallet.latest_checkpoint().height();
        for mut coin in prepared.outputs {
            coin.is_pegin = true;
            coin.block_height = Some(tip);
            db.insert(coin);
        }
        // The critical apply that production peg-in must perform.
        wallet.apply_unconfirmed_txs([(tx, 1u64)]);

        let transparent = wallet.balance().total().to_sat();
        let mweb_total = db.balance();
        let combined = transparent + mweb_total;
        // Combined must not exceed prior (fees burn sats).
        assert!(
            combined <= prior_transparent,
            "double-count: prior={prior_transparent} transparent={transparent} mweb={mweb_total}"
        );
        assert!(
            transparent < prior_transparent,
            "transparent should drop after peg-in apply"
        );
        assert!(mweb_total > 0, "mweb should hold peg-in output");
    }
}

#[cfg(test)]
mod churn_field_tests {
    use super::churn_fields;
    use crate::churn;
    use crate::dto::ChurnPhase;
    use std::collections::BTreeMap;

    fn output_id() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn active_job_stamps_target_and_counted() {
        let id = output_id();
        let mut job = churn::new_job(&id, true, 4, 50_000).unwrap();
        job.effective_depth = 2;
        job.phase = ChurnPhase::PausedSolo;
        let fields = churn_fields(&id, true, &BTreeMap::new(), Some(&job));
        assert_eq!(fields.churn_phase, Some(ChurnPhase::PausedSolo));
        assert_eq!(fields.churn_target, Some(4));
        assert_eq!(fields.churn_counted, Some(2));
        assert!(fields.churn_error.is_none());
    }

    #[test]
    fn finished_job_does_not_stamp_progress() {
        let id = output_id();
        let mut job = churn::new_job(&id, false, 1, 50_000).unwrap();
        job.phase = ChurnPhase::Done;
        job.effective_depth = 1;
        let fields = churn_fields(&id, false, &BTreeMap::new(), Some(&job));
        assert!(fields.churn_phase.is_none());
        assert!(fields.churn_error.is_none());
        assert_eq!(fields.churn_target, Some(1));
        assert_eq!(fields.churn_counted, Some(1));
    }
}

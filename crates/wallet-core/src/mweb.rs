//! MWEB orchestration beside the transparent wallet.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::ToSocketAddrs;
use std::path::Path;

use std::sync::Arc;

use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
use bdk_mweb::limits::MAX_REQUESTED_MWEB_UTXOS;
use bdk_mweb::lip0006::MwebUtxoSource;
use bdk_mweb::lip0006_tcp::{BroadcastAck, PeerPolicy, TcpMwebPeer};
use bdk_mweb::mweb_sync::{
    leafset_has_leaf, FixedHeaderProvider, MwebSyncer, ReadyNotifier, SyncProgress, SyncState,
};
use bdk_mweb::p2p::{GetMwebUtxos, MwebLeafset, OUTPUT_FORMAT_FULL};
use bdk_mweb::pmmr::verify_leafset;
use bdk_mweb::tx_builder::CHANGE_ADDRESS_INDEX;
use bdk_mweb::MwebCoinDatabase;
use bdk_mweb::{AddressBook, BanReason, ChangeSet, SealContext, MWEB_PEGIN_MATURITY};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize_hex};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::All;
use bdk_wallet::bitcoin::{Amount, NetworkKind, ScriptBuf, Transaction};
use bdk_wallet::chain::Merge;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{extract_prepared_mweb_pegin, select_mweb_coins, MwebStore, PersistedWallet};

use crate::descriptors::{sign_and_finalize, ZeroizingSigner};
use crate::dto::{
    ChurnPhase, CoinActions, CoinBlock, CoinStatus, CombinedSummary, MwebBroadcastResult,
    MwebSendRequest, MwebUtxoRecord, PeginRequest, PeginResult, PegoutRequest, SplitResult, TxKind,
    WalletSummary,
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
    crate::tx_invariants::normalize_and_dedup_ids(ids)
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
    crate::tx_invariants::check_money(needed, "private spend needed")?;
    let deduped = normalize_selected_ids(selected_ids);
    if let Some(ids) = deduped.as_deref() {
        let mut coins = Vec::with_capacity(ids.len());
        for id in ids {
            coins.push(select_mweb_coin(db, id, tip_height, frozen, action)?);
        }
        let sum = crate::tx_invariants::checked_sum_sats(
            coins.iter().map(|c| c.amount),
            "selected private coins",
        )?;
        if sum < needed {
            return Err(WalletError::BuildTx(format!(
                "need {needed} litoshis from the selected private coins but they only total {sum}"
            )));
        }
        Ok(coins)
    } else {
        let pool = spendable_pool(db, tip_height, frozen);
        crate::tx_invariants::checked_sum_sats(
            pool.iter().map(|c| c.amount),
            "spendable private pool",
        )?;
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

/// A 22-byte P2WPKH script. Per-coin peg-outs pay to fresh `ltc1` addresses of this shape.
pub fn p2wpkh_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[0u8; 20]);
    ScriptBuf::from_bytes(bytes)
}

/// P2WPKH dust at the same 30 sat/vB relay rate used for typed peg-outs.
pub fn p2wpkh_dust_sats() -> Result<u64, WalletError> {
    Ok(crate::tx_invariants::ltc_dust_threshold(&p2wpkh_script()))
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
    crate::tx_invariants::check_money(fee_sats, "peg-out fee")?;
    crate::tx_invariants::check_money(dust_sats, "peg-out dust")?;
    crate::tx_invariants::checked_sum_sats(coin_amounts.iter().copied(), "peg-out coins")?;
    let script = p2wpkh_script();
    let min_fee = crate::tx_invariants::min_kernel_fee(
        0,
        std::iter::repeat(script.as_script()).take(coin_amounts.len()),
    );
    if fee_sats < min_fee {
        return Err(WalletError::BuildTx(format!(
            "peg-out fee {fee_sats} litoshis is below the MWEB minimum of {min_fee} litoshis"
        )));
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
    /// Last tip hash whose leafset was already confirmed by a second peer.
    last_cross_checked_tip: Option<(bdk_wallet::bitcoin::BlockHash, u32)>,
    /// Full aggregate coin changeset mirrored on disk (sealed persistence).
    agg: ChangeSet,
    /// Highest v2 envelope counter observed on open or written by `persist`.
    loaded_seal_counter: u64,
    /// Key for encrypting MWEB files at rest; `None` falls back to the legacy
    /// plaintext formats (tests / plaintext-era wallets awaiting migration).
    sealing_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    secp: Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
}

impl MwebRuntime {
    /// Overwrite in-memory key material (`sealing_key` and MWEB master keys).
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        if let Some(ref mut k) = self.sealing_key {
            k.zeroize();
        }
        self.sealing_key = None;
        self.keys.wipe();
    }

    #[cfg(test)]
    pub(crate) fn has_sealing_key_for_test(&self) -> bool {
        self.sealing_key.is_some()
    }
}

impl Drop for MwebRuntime {
    fn drop(&mut self) {
        self.wipe();
    }
}

enum ProbePeerFailure {
    Lagging,
    HardFailed,
}

struct PreProbedPeer {
    addr: std::net::SocketAddr,
    header: Result<bdk_mweb::p2p::MwebHeaderMsg, ProbePeerFailure>,
}

struct PreProbedCrossCheck {
    probed: Vec<PreProbedPeer>,
}

struct CrossProbeSpec<'scope, 'env> {
    scope: &'scope std::thread::Scope<'scope, 'env>,
    backup_addrs: Vec<std::net::SocketAddr>,
    tip_hash: bdk_wallet::bitcoin::BlockHash,
    bdk_net: bdk_wallet::bitcoin::Network,
    policy: PeerPolicy,
    cancel: Option<&'env std::sync::atomic::AtomicBool>,
    pending_lock: Option<&'env std::sync::atomic::AtomicBool>,
    pass_aborted: &'env std::sync::atomic::AtomicBool,
}

fn probe_cross_check_peers(
    backup_addrs: Vec<std::net::SocketAddr>,
    tip_hash: bdk_wallet::bitcoin::BlockHash,
    bdk_net: bdk_wallet::bitcoin::Network,
    policy: PeerPolicy,
    cancel: Option<&std::sync::atomic::AtomicBool>,
    pending_lock: Option<&std::sync::atomic::AtomicBool>,
    pass_aborted: &std::sync::atomic::AtomicBool,
) -> PreProbedCrossCheck {
    let mut probed = Vec::new();
    for addr in backup_addrs {
        if CancellableMwebPeer::is_cancelled(cancel, pending_lock)
            || pass_aborted.load(std::sync::atomic::Ordering::Acquire)
        {
            break;
        }
        let attempt_started = std::time::Instant::now();
        let mut peer = match TcpMwebPeer::connect_with_policy(addr, bdk_net, policy) {
            Ok(peer) => peer,
            Err(e) => {
                let stage = connect_failure_stage(&e);
                crate::diag::log(format!(
                    "sync: mweb cross-check peer={addr} stage={stage} err={} ms={}",
                    compact_peer_err(&e, stage),
                    attempt_started.elapsed().as_millis() as u64,
                ));
                probed.push(PreProbedPeer {
                    addr,
                    header: Err(ProbePeerFailure::HardFailed),
                });
                continue;
            }
        };
        if CancellableMwebPeer::is_cancelled(cancel, pending_lock)
            || pass_aborted.load(std::sync::atomic::Ordering::Acquire)
        {
            break;
        }
        match peer.get_header(tip_hash) {
            Ok(hdr) => {
                probed.push(PreProbedPeer {
                    addr,
                    header: Ok(hdr),
                });
                break;
            }
            Err(e) => {
                let stage = peer.last_stage();
                crate::diag::log(format!(
                    "sync: mweb cross-check peer={addr} stage={stage} err={} ms={}",
                    compact_peer_err(&e, stage),
                    attempt_started.elapsed().as_millis() as u64,
                ));
                let kind = if is_clean_tip_lag(&e, stage) {
                    ProbePeerFailure::Lagging
                } else {
                    ProbePeerFailure::HardFailed
                };
                probed.push(PreProbedPeer {
                    addr,
                    header: Err(kind),
                });
            }
        }
    }
    PreProbedCrossCheck { probed }
}

/// Maximum batches sent per `get_utxos_pipelined` round so a 15s round timeout
/// is never exceeded on a healthy peer serving ~3 MB FULL_UTXO batches, while
/// updating progress and `utxo_cursor` every few seconds.
const PIPELINE_WINDOW_BATCHES: usize = 4;

fn is_shrinkable_pmmr_error(err: &bdk_mweb::Error) -> bool {
    let msg = format!("{err}");
    msg.contains("output_root mismatch")
        || msg.contains("parent_hashes len")
        || msg.contains("missing peak")
}

struct CancellableMwebPeer<'scope, 'env> {
    inner: TcpMwebPeer,
    cancel: Option<&'env std::sync::atomic::AtomicBool>,
    pending_lock: Option<&'env std::sync::atomic::AtomicBool>,
    probe_spec: Option<CrossProbeSpec<'scope, 'env>>,
    probe_handle: Option<std::thread::ScopedJoinHandle<'scope, PreProbedCrossCheck>>,
    last_progress_at: std::time::Instant,
    aborted_pipeline_err: Option<bdk_mweb::Error>,
    needs_reconnect_before_sequential: bool,
}

impl<'scope, 'env> CancellableMwebPeer<'scope, 'env> {
    fn is_cancelled(
        cancel: Option<&std::sync::atomic::AtomicBool>,
        pending_lock: Option<&std::sync::atomic::AtomicBool>,
    ) -> bool {
        use std::sync::atomic::Ordering;
        cancel.is_some_and(|c| c.load(Ordering::Acquire))
            || pending_lock.is_some_and(|p| p.load(Ordering::Acquire))
    }

    fn check_cancel(&self) -> Result<(), bdk_mweb::Error> {
        if Self::is_cancelled(self.cancel, self.pending_lock) {
            Err(bdk_mweb::Error::Crypto("MWEB sync cancelled".into()))
        } else {
            Ok(())
        }
    }

    fn maybe_spawn_cross_probe(&mut self) {
        if let Some(spec) = self.probe_spec.take() {
            #[cfg(test)]
            let test_ctx = capture_test_context();
            self.probe_handle = Some(spec.scope.spawn(move || {
                #[cfg(test)]
                install_test_context(test_ctx);
                probe_cross_check_peers(
                    spec.backup_addrs,
                    spec.tip_hash,
                    spec.bdk_net,
                    spec.policy,
                    spec.cancel,
                    spec.pending_lock,
                    spec.pass_aborted,
                )
            }));
        }
    }

    fn last_stage(&self) -> &'static str {
        self.inner.last_stage()
    }

    fn unproductive_elapsed(&self) -> std::time::Duration {
        self.last_progress_at.elapsed()
    }
}

impl MwebUtxoSource for CancellableMwebPeer<'_, '_> {
    fn get_header(
        &mut self,
        block_hash: bdk_wallet::bitcoin::BlockHash,
    ) -> Result<bdk_mweb::p2p::MwebHeaderMsg, bdk_mweb::Error> {
        self.check_cancel()?;
        let hdr = self.inner.get_header(block_hash)?;
        self.last_progress_at = std::time::Instant::now();
        if self
            .probe_spec
            .as_ref()
            .is_some_and(|s| s.tip_hash == block_hash)
            && hdr.mweb_header.output_mmr_size > 0
        {
            self.maybe_spawn_cross_probe();
        }
        Ok(hdr)
    }

    fn get_leafset(
        &mut self,
        block_hash: bdk_wallet::bitcoin::BlockHash,
    ) -> Result<MwebLeafset, bdk_mweb::Error> {
        self.check_cancel()?;
        let ls = self.inner.get_leafset(block_hash)?;
        self.last_progress_at = std::time::Instant::now();
        Ok(ls)
    }

    fn get_utxos(
        &mut self,
        req: GetMwebUtxos,
    ) -> Result<bdk_mweb::p2p::MwebUtxos, bdk_mweb::Error> {
        self.check_cancel()?;
        if let Some(err) = self.aborted_pipeline_err.take() {
            return Err(err);
        }
        if self.needs_reconnect_before_sequential {
            self.needs_reconnect_before_sequential = false;
            self.inner.reconnect()?;
            self.last_progress_at = std::time::Instant::now();
        }
        let batch = self.inner.get_utxos(req)?;
        if !batch.utxos.is_empty() {
            self.last_progress_at = std::time::Instant::now();
        }
        Ok(batch)
    }

    fn get_utxos_pipelined(
        &mut self,
        reqs: &[GetMwebUtxos],
        on_batch: &mut dyn FnMut(bdk_mweb::p2p::MwebUtxos) -> Result<(), bdk_mweb::Error>,
    ) -> Result<(), bdk_mweb::Error> {
        self.check_cancel()?;
        let cancel = self.cancel;
        let pending_lock = self.pending_lock;
        for chunk in reqs.chunks(PIPELINE_WINDOW_BATCHES.max(1)) {
            self.check_cancel()?;
            let last_progress_at = &mut self.last_progress_at;
            let mut callback_err = false;
            let res = self.inner.get_utxos_pipelined(chunk, &mut |batch| {
                if Self::is_cancelled(cancel, pending_lock) {
                    return Err(bdk_mweb::Error::Crypto("MWEB sync cancelled".into()));
                }
                if !batch.utxos.is_empty() {
                    *last_progress_at = std::time::Instant::now();
                }
                on_batch(batch).inspect_err(|_| {
                    callback_err = true;
                })
            });
            if let Err(e) = res {
                if callback_err && is_shrinkable_pmmr_error(&e) {
                    self.needs_reconnect_before_sequential = true;
                } else {
                    self.aborted_pipeline_err = Some(e.clone());
                }
                return Err(e);
            }
        }
        Ok(())
    }
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
    if err.ban_reason() == Some(BanReason::Undecodable) {
        // The peer served block data our decoder rejects. That is far more
        // likely a decoder that has drifted from Litecoin Core than a bad
        // peer, so a public peer would fail the same way while seeing our
        // queries.
        return PassFailure {
            status: "MWEB data from the peer could not be decoded; this wallet may need an \
                     update."
                .into(),
            allow_public_fallback: false,
        };
    }
    PassFailure {
        status: format!("MWEB peer unreachable: {err}"),
        allow_public_fallback: true,
    }
}

/// Outcome of a failed [`MwebRuntime::sync_pass`].
struct SyncPassFailure {
    err: bdk_mweb::Error,
    tried: usize,
    /// True when every peer tried in this pass connected cleanly and only
    /// failed because it had not yet indexed `tip_hash` (`notfound` or an
    /// empty `pong` on `get_header` / `get_leafset`).
    all_tip_lag: bool,
    hard_failed: Vec<std::net::SocketAddr>,
}

/// Maximum cumulative wall-clock time spent on *failed* peer attempts in one
/// [`MwebRuntime::sync_pass`]. Active downloads that are making forward
/// progress are never capped by this budget.
const UNPRODUCTIVE_FAILOVER_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Short pause before retrying the same peer pool when every peer answered
/// promptly with clean tip-lag (Electrum saw the new block 1–2s before P2P).
const TIP_LAG_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1500);

#[cfg(test)]
thread_local! {
    static TEST_PEER_POLICY: std::cell::Cell<Option<PeerPolicy>> = const { std::cell::Cell::new(None) };
    static TEST_UNPRODUCTIVE_BUDGET: std::cell::Cell<Option<std::time::Duration>> = const { std::cell::Cell::new(None) };
    static TEST_TIP_LAG_BACKOFF: std::cell::Cell<Option<std::time::Duration>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestMwebContext {
    peer_policy: Option<PeerPolicy>,
    unproductive_budget: Option<std::time::Duration>,
    tip_lag_backoff: Option<std::time::Duration>,
    discovery: crate::discovery::TestDiscoveryContext,
}

#[cfg(test)]
pub(crate) fn capture_test_context() -> TestMwebContext {
    TestMwebContext {
        peer_policy: TEST_PEER_POLICY.with(std::cell::Cell::get),
        unproductive_budget: TEST_UNPRODUCTIVE_BUDGET.with(std::cell::Cell::get),
        tip_lag_backoff: TEST_TIP_LAG_BACKOFF.with(std::cell::Cell::get),
        discovery: crate::discovery::capture_test_context(),
    }
}

#[cfg(test)]
pub(crate) fn install_test_context(ctx: TestMwebContext) {
    TEST_PEER_POLICY.with(|c| c.set(ctx.peer_policy));
    TEST_UNPRODUCTIVE_BUDGET.with(|c| c.set(ctx.unproductive_budget));
    TEST_TIP_LAG_BACKOFF.with(|c| c.set(ctx.tip_lag_backoff));
    crate::discovery::install_test_context(ctx.discovery);
}

fn peer_policy_for_pool(pool_size: usize) -> PeerPolicy {
    #[cfg(test)]
    if let Some(policy) = TEST_PEER_POLICY.with(std::cell::Cell::get) {
        return policy;
    }
    let mut policy = PeerPolicy::fast_failover();
    if pool_size <= 1 {
        // A single configured node has nowhere to fail over to; give its
        // serving bucket time to refill before reporting a throttle error.
        policy.max_throttled_rounds = 5;
    }
    policy
}

fn unproductive_failover_budget() -> std::time::Duration {
    #[cfg(test)]
    if let Some(budget) = TEST_UNPRODUCTIVE_BUDGET.with(std::cell::Cell::get) {
        return budget;
    }
    UNPRODUCTIVE_FAILOVER_BUDGET
}

fn tip_lag_backoff() -> std::time::Duration {
    #[cfg(test)]
    if let Some(backoff) = TEST_TIP_LAG_BACKOFF.with(std::cell::Cell::get) {
        return backoff;
    }
    TIP_LAG_RETRY_BACKOFF
}

fn connect_failure_stage(err: &bdk_mweb::Error) -> &'static str {
    let msg = format!("{err}");
    if msg.contains("handshake") {
        "handshake"
    } else {
        "connect"
    }
}

fn compact_peer_err(err: &bdk_mweb::Error, stage: &str) -> String {
    let msg = format!("{err}");
    if msg.contains("notfound") {
        "notfound".into()
    } else if is_clean_tip_lag(err, stage) {
        "tip_lag".into()
    } else if msg.contains("timed out")
        || msg.contains("did not properly respond")
        || msg.contains("Resource temporarily unavailable")
        || msg.contains("os error 35")
        || msg.contains("os error 11")
        || msg.contains("os error 10060")
    {
        "timeout".into()
    } else {
        msg
    }
}

/// True when the peer connected and answered promptly during header/leafset
/// fetch, but did not yet have `tip_hash` (`notfound` or empty `pong` flush).
///
/// These peers are healthy and merely 1–2s behind Electrum's block view, so
/// they are demoted to the back of the discovery pool rather than evicted.
fn is_clean_tip_lag(err: &bdk_mweb::Error, stage: &str) -> bool {
    if !matches!(stage, "get_header" | "get_leafset") {
        return false;
    }
    match err.ban_reason() {
        Some(BanReason::Throttled) => true,
        Some(BanReason::ProtocolViolation) => format!("{err}").contains("notfound"),
        _ => false,
    }
}

fn is_rotatable_peer_error(err: &bdk_mweb::Error) -> bool {
    err.ban_reason().is_some()
}

/// Account-aware MWEB scan/spend paths. Account 0 matches `MasterKeyScheme` defaults.
pub fn mweb_scan_spend_paths(
    scheme: MasterKeyScheme,
    account: u32,
) -> Result<(DerivationPath, DerivationPath), WalletError> {
    let map = |e: bdk_wallet::bitcoin::bip32::Error| WalletError::Mweb(e.to_string());
    match scheme {
        MasterKeyScheme::LitecoinCore => Ok((
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(100).map_err(map)?,
                ChildNumber::from_hardened_idx(0).map_err(map)?,
            ]),
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(100).map_err(map)?,
                ChildNumber::from_hardened_idx(1).map_err(map)?,
            ]),
        )),
        MasterKeyScheme::Lip0004 => Ok((
            DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(map)?,
                ChildNumber::from_normal_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(100).map_err(map)?,
            ]),
            DerivationPath::from(vec![
                ChildNumber::from_normal_idx(1).map_err(map)?,
                ChildNumber::from_normal_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(101).map_err(map)?,
            ]),
        )),
        MasterKeyScheme::Mwebd => Ok((
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(1000).map_err(map)?,
                ChildNumber::from_hardened_idx(2).map_err(map)?,
                ChildNumber::from_hardened_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(0).map_err(map)?,
            ]),
            DerivationPath::from(vec![
                ChildNumber::from_hardened_idx(1000).map_err(map)?,
                ChildNumber::from_hardened_idx(2).map_err(map)?,
                ChildNumber::from_hardened_idx(account).map_err(map)?,
                ChildNumber::from_hardened_idx(1).map_err(map)?,
            ]),
        )),
    }
}

/// Derive MWEB master keys for `account` from a depth-0 master xprv.
pub fn master_keys_for_account(
    master: &Xpriv,
    scheme: MasterKeyScheme,
    account: u32,
    secp: &Secp256k1<All>,
) -> Result<MasterKeys, WalletError> {
    let (scan_path, spend_path) = mweb_scan_spend_paths(scheme, account)?;
    let fingerprint = master.fingerprint(secp);
    let mut scan_xprv = master
        .derive_priv(secp, &scan_path)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    let mut scan = scan_xprv.private_key;
    crate::seed::wipe_xpriv(&mut scan_xprv);
    let mut spend_xprv = match master.derive_priv(secp, &spend_path) {
        Ok(x) => x,
        Err(e) => {
            scan.non_secure_erase();
            return Err(WalletError::Mweb(e.to_string()));
        }
    };
    let spend = spend_xprv.private_key;
    crate::seed::wipe_xpriv(&mut spend_xprv);
    Ok(MasterKeys {
        scan,
        spend,
        scheme,
        master_fingerprint: fingerprint,
        scan_path,
        spend_path,
    })
}

impl MwebRuntime {
    pub fn open(
        data_dir: &Path,
        secret: &crate::seed::MasterSecret,
        network: WalletNetwork,
        scheme: MasterKeyScheme,
        account: u32,
        sealing_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    ) -> Result<Self, WalletError> {
        let secp = Secp256k1::new();
        let bdk_net = network.to_bitcoin_network();
        let master = secret.master_xprv_guarded(bdk_net)?;
        let keys = master_keys_for_account(&master, scheme, account, &secp)?;
        drop(master);
        let book = AddressBook::from_keys(&keys, MWEB_GAP_LIMIT, &secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;

        let key_ref = sealing_key.as_deref();
        let saved_counter = if key_ref.is_some() {
            load_seal_counter(data_dir)
        } else {
            0
        };
        let (store, agg, coins_counter) = load_store(data_dir, key_ref, saved_counter)?;
        let (sync_state, sync_counter) = load_sync_state(data_dir, key_ref, saved_counter)?;
        let (receive_index, index_counter) = load_receive_index(data_dir, key_ref, saved_counter)?;
        let (history, history_counter) = load_history(data_dir, key_ref, saved_counter)?;

        let v2_counters: Vec<u64> = [coins_counter, sync_counter, index_counter, history_counter]
            .into_iter()
            .flatten()
            .collect();
        if let (Some(&min_c), Some(&max_c)) = (v2_counters.iter().min(), v2_counters.iter().max()) {
            // A kill mid-persist leaves at most a 1-step split ({C, C+1}) across the
            // four blobs. A wider gap means an individual file was rolled back.
            if max_c.saturating_sub(min_c) > 1 {
                return Err(WalletError::Mweb(format!(
                    "sealed MWEB files have inconsistent persist counters ({min_c} vs {max_c})"
                )));
            }
        }
        let loaded_seal_counter = v2_counters.into_iter().fold(saved_counter, u64::max);

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
            last_cross_checked_tip: None,
            agg,
            loaded_seal_counter,
            sealing_key,
            secp,
        })
    }

    pub fn persist(&mut self, data_dir: &Path) -> Result<(), WalletError> {
        if let Some(ref key) = self.sealing_key {
            self.agg.merge(self.store.take_staged());
            // One counter for all four blobs, so a later read can tell whether
            // they came from the same persist. Taking max(disk, loaded) ensures
            // a restart after a crash right before save_seal_counter never
            // reuses the interrupted persist's counter.
            let counter = load_seal_counter(data_dir)
                .max(self.loaded_seal_counter)
                .saturating_add(1);

            // Crash-safe write order: index -> coins -> history -> sync_state -> counter.
            // SyncState is last among the blobs so a kill mid-persist never records
            // a synced tip height ahead of the coins and history discovered at that tip.
            let index_str = zeroize::Zeroizing::new(self.receive_index.to_string());
            write_sealed(
                &meta::mweb_index_enc_path(data_dir),
                seal_bytes(key, index_str.as_bytes(), SealContext::Index, counter)?,
            )?;
            crate::crashpoint::maybe_crash("persist_after_index_enc");

            let coins =
                bdk_mweb::seal_changeset_with_context(key, &self.agg, SealContext::Coins, counter)
                    .map_err(|e| WalletError::Mweb(e.to_string()))?;
            write_sealed(&meta::mweb_coins_enc_path(data_dir), coins)?;
            crate::crashpoint::maybe_crash("persist_after_coins_enc");

            let history_json = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.history).map_err(|e| WalletError::Mweb(e.to_string()))?,
            );
            write_sealed(
                &meta::mweb_history_enc_path(data_dir),
                seal_bytes(key, &history_json, SealContext::History, counter)?,
            )?;
            crate::crashpoint::maybe_crash("persist_after_history_enc");

            let sync_json = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.sync_state)
                    .map_err(|e| WalletError::Mweb(e.to_string()))?,
            );
            write_sealed(
                &meta::mweb_sync_enc_path(data_dir),
                seal_bytes(key, &sync_json, SealContext::SyncState, counter)?,
            )?;
            crate::crashpoint::maybe_crash("persist_after_sync_enc");

            // Written last: a crash between the blobs and the counter leaves the
            // counter behind by 1, which reads as an interrupted persist rather
            // than a rollback.
            save_seal_counter(data_dir, counter)?;
            self.loaded_seal_counter = counter;
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
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn sync_at_tip(
        &mut self,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        prev_tip_hash: Option<bdk_wallet::bitcoin::BlockHash>,
        peers: &[String],
        network: WalletNetwork,
        progress: Option<Arc<SyncProgress>>,
        hold_spent: &BTreeSet<[u8; 32]>,
    ) -> Result<(), WalletError> {
        self.sync_at_tip_cancellable(
            tip_height,
            tip_hash,
            prev_tip_hash,
            peers,
            network,
            progress,
            hold_spent,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sync_at_tip_cancellable(
        &mut self,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        prev_tip_hash: Option<bdk_wallet::bitcoin::BlockHash>,
        peers: &[String],
        network: WalletNetwork,
        progress: Option<Arc<SyncProgress>>,
        hold_spent: &BTreeSet<[u8; 32]>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        pending_lock: Option<&std::sync::atomic::AtomicBool>,
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
                hold_spent,
                cancel,
                pending_lock,
            ) {
                Ok(pre_probed) => {
                    let mut candidates = configured;
                    if candidates.len() < 2 {
                        candidates.extend(crate::discovery::discover_mweb_peers(network));
                    }
                    self.cross_check_leafset(
                        tip_hash,
                        candidates,
                        network,
                        pre_probed,
                        cancel,
                        pending_lock,
                    );
                    return Ok(());
                }
                Err(outcome) => {
                    if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                        return Ok(());
                    }
                    let failure = classify_pass_failure(&outcome.err);
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
        if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
            return Ok(());
        }
        // Their own node is absent or down, so fall back to public MWEB peers
        // from the DNS seeds rather than leaving MWEB dark.
        let discover_started = std::time::Instant::now();
        let mut discovered = crate::discovery::discover_mweb_peers(network);
        let discover_ms = discover_started.elapsed().as_millis() as u64;
        if let Some(good) = self.last_good_peer {
            if crate::discovery::should_prefer_peer(&good) {
                discovered.retain(|addr| *addr != good);
                discovered.insert(0, good);
            } else {
                self.last_good_peer = None;
            }
        }
        crate::diag::log(format!(
            "sync: mweb peers discovered={} ms={discover_ms}",
            discovered.len()
        ));
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
            progress.clone(),
            hold_spent,
            cancel,
            pending_lock,
        ) {
            Ok(pre_probed) => {
                self.last_status.push_str(" via public peer");
                self.cross_check_leafset(
                    tip_hash,
                    discovered,
                    network,
                    pre_probed,
                    cancel,
                    pending_lock,
                );
                Ok(())
            }
            Err(first) => {
                if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                    return Ok(());
                }
                // When Electrum sees a brand-new block 1–2s before P2P gossip,
                // every healthy peer can answer `notfound` or an empty `pong`
                // in ~50ms. Wait briefly and retry the same pool rather than
                // evicting healthy peers or re-crawling DNS seeds.
                if first.all_tip_lag {
                    let backoff = tip_lag_backoff();
                    crate::diag::log(format!(
                        "sync: mweb all {} peer(s) lagging tip={tip_height}; waiting {}ms before retry",
                        first.tried,
                        backoff.as_millis()
                    ));
                    if !backoff.is_zero() {
                        std::thread::sleep(backoff);
                    }
                    if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                        return Ok(());
                    }
                    if let Ok(pre_probed) = self.sync_pass(
                        discovered.clone(),
                        tip_height,
                        tip_hash,
                        prev_tip_hash,
                        network,
                        progress,
                        hold_spent,
                        cancel,
                        pending_lock,
                    ) {
                        self.last_status.push_str(" via public peer");
                        self.cross_check_leafset(
                            tip_hash,
                            discovered,
                            network,
                            pre_probed,
                            cancel,
                            pending_lock,
                        );
                        return Ok(());
                    }
                } else if discover_ms == 0 {
                    // The pass failed on a cached peer list; flush the cache and
                    // crawl once so a stale pool recovers within the same cycle.
                    crate::discovery::clear_cache();
                    let refresh_started = std::time::Instant::now();
                    let mut refreshed = crate::discovery::discover_mweb_peers(network);
                    let refresh_ms = refresh_started.elapsed().as_millis() as u64;
                    refreshed.retain(|addr| !first.hard_failed.contains(addr));
                    crate::diag::log(format!(
                        "sync: mweb peers refreshed={} ms={refresh_ms}",
                        refreshed.len()
                    ));
                    if !refreshed.is_empty() {
                        if let Ok(pre_probed) = self.sync_pass(
                            refreshed.clone(),
                            tip_height,
                            tip_hash,
                            prev_tip_hash,
                            network,
                            progress,
                            hold_spent,
                            cancel,
                            pending_lock,
                        ) {
                            self.last_status.push_str(" via public peer");
                            self.cross_check_leafset(
                                tip_hash,
                                refreshed,
                                network,
                                pre_probed,
                                cancel,
                                pending_lock,
                            );
                            return Ok(());
                        }
                    }
                }
                self.stale = true;
                self.last_status = classify_pass_failure(&first.err).status;
                Ok(())
            }
        }
    }

    /// Ask an independent peer for the MWEB header at `tip_hash` and verify our
    /// freshly synced leafset against its `leafset_root`.
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
        pre_probed: Option<PreProbedCrossCheck>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        pending_lock: Option<&std::sync::atomic::AtomicBool>,
    ) {
        self.cross_check_warning = None;
        if self.sync_state.leafset.is_empty() {
            return;
        }
        if let Some((checked_hash, prev_confirmed)) = self.last_cross_checked_tip {
            if checked_hash == tip_hash && prev_confirmed >= 2 {
                self.last_status
                    .push_str(&format!(" · leafset confirmed by {prev_confirmed} peers"));
                return;
            }
        }
        let cross_started = std::time::Instant::now();
        let sync_peer = self.last_good_peer;
        let mut distinct: Vec<std::net::SocketAddr> = Vec::new();
        for addr in addrs {
            if Some(addr) != sync_peer && !distinct.contains(&addr) {
                distinct.push(addr);
            }
        }
        let leafset = MwebLeafset {
            block_hash: tip_hash,
            leafset: self.sync_state.leafset.clone(),
        };
        let bdk_net = network.to_bitcoin_network();
        let policy = peer_policy_for_pool(distinct.len().max(2));
        // The sync peer already verified the leafset against its anchored header.
        let mut confirmed = u32::from(sync_peer.is_some());
        let mut hard_failed = Vec::new();
        let mut lagging = Vec::new();
        let mut already_probed = Vec::new();

        if let Some(pre) = pre_probed {
            for item in pre.probed {
                already_probed.push(item.addr);
                if Some(item.addr) == sync_peer || confirmed >= 2 {
                    continue;
                }
                match item.header {
                    Err(ProbePeerFailure::HardFailed) => hard_failed.push(item.addr),
                    Err(ProbePeerFailure::Lagging) => lagging.push(item.addr),
                    Ok(hdr) => match verify_leafset(
                        &leafset,
                        &hdr.mweb_header.leafset_root,
                        hdr.mweb_header.output_mmr_size,
                    ) {
                        Ok(()) => confirmed += 1,
                        Err(_) => {
                            let addr = item.addr;
                            hard_failed.push(addr);
                            crate::discovery::evict_peers(&hard_failed);
                            crate::discovery::demote_peers(&lagging);
                            self.cross_check_warning = Some(format!(
                                "WARNING: MWEB peer {addr} reports a different UTXO set than the peer \
                                 used for this sync — your private balance may be incomplete. Run \
                                 'Resync MWEB' or verify against your own node"
                            ));
                            return;
                        }
                    },
                }
            }
        }

        for addr in distinct {
            if confirmed >= 2 || CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                break;
            }
            if already_probed.contains(&addr) {
                continue;
            }
            let attempt_started = std::time::Instant::now();
            let mut peer = match TcpMwebPeer::connect_with_policy(addr, bdk_net, policy) {
                Ok(peer) => peer,
                Err(e) => {
                    let stage = connect_failure_stage(&e);
                    crate::diag::log(format!(
                        "sync: mweb cross-check peer={addr} stage={stage} err={} ms={}",
                        compact_peer_err(&e, stage),
                        attempt_started.elapsed().as_millis() as u64,
                    ));
                    hard_failed.push(addr);
                    continue;
                }
            };
            let hdr = match peer.get_header(tip_hash) {
                Ok(hdr) => hdr,
                Err(e) => {
                    let stage = peer.last_stage();
                    crate::diag::log(format!(
                        "sync: mweb cross-check peer={addr} stage={stage} err={} ms={}",
                        compact_peer_err(&e, stage),
                        attempt_started.elapsed().as_millis() as u64,
                    ));
                    if is_clean_tip_lag(&e, stage) {
                        lagging.push(addr);
                    } else {
                        hard_failed.push(addr);
                    }
                    continue;
                }
            };
            match verify_leafset(
                &leafset,
                &hdr.mweb_header.leafset_root,
                hdr.mweb_header.output_mmr_size,
            ) {
                Ok(()) => confirmed += 1,
                Err(_) => {
                    hard_failed.push(addr);
                    crate::discovery::evict_peers(&hard_failed);
                    crate::discovery::demote_peers(&lagging);
                    self.cross_check_warning = Some(format!(
                        "WARNING: MWEB peer {addr} reports a different UTXO set than the peer \
                         used for this sync — your private balance may be incomplete. Run \
                         'Resync MWEB' or verify against your own node"
                    ));
                    return;
                }
            }
        }
        crate::discovery::evict_peers(&hard_failed);
        crate::discovery::demote_peers(&lagging);
        if confirmed >= 2 {
            self.last_cross_checked_tip = Some((tip_hash, confirmed));
        }
        crate::diag::log(format!(
            "sync: mweb cross-check confirmed={confirmed} ms={}",
            cross_started.elapsed().as_millis() as u64
        ));
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
    /// Returns the typed [`bdk_mweb::Error`] inside [`SyncPassFailure`]: the
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
        hold_spent: &BTreeSet<[u8; 32]>,
        cancel: Option<&std::sync::atomic::AtomicBool>,
        pending_lock: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Option<PreProbedCrossCheck>, SyncPassFailure> {
        let pass_started = std::time::Instant::now();
        // Heal before this pass so a stuck split/send is included in the
        // full UTXO download rather than waiting for a later sync.
        let invalidated_for_outgoing =
            pending_unverifiable_outgoing(&self.history, self.store.db());
        if invalidated_for_outgoing {
            self.sync_state.invalidate_leafset();
        }
        let prev_height = self.sync_state.tip_height;
        let prior_leafset_bytes = self.sync_state.leafset.len();
        let full_utxo_scan = self.sync_state.leafset.is_empty();
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

        let total_peers = addrs.len();
        let policy = peer_policy_for_pool(total_peers);
        let need_cross_probe = !self
            .last_cross_checked_tip
            .is_some_and(|(h, c)| h == tip_hash && c >= 2);
        let unproductive_budget = unproductive_failover_budget();
        let mut unproductive_elapsed = std::time::Duration::ZERO;
        let mut tried = 0usize;
        let mut tip_lag_count = 0usize;
        let mut served = 0usize;
        let mut undecodable = 0usize;
        let mut hard_failed: Vec<std::net::SocketAddr> = Vec::new();
        let mut lagging: Vec<std::net::SocketAddr> = Vec::new();
        let mut last_err: Option<bdk_mweb::Error> = None;

        for (idx, addr) in addrs.iter().copied().enumerate() {
            if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                last_err = Some(bdk_mweb::Error::Crypto("MWEB sync cancelled".into()));
                break;
            }
            if idx > 0 && unproductive_elapsed >= unproductive_budget {
                crate::diag::log(format!(
                    "sync: mweb pass unproductive budget exhausted after {}ms ({tried}/{total_peers} peers tried)",
                    unproductive_elapsed.as_millis()
                ));
                break;
            }
            let attempt_started = std::time::Instant::now();
            tried += 1;
            let tcp_peer = match TcpMwebPeer::connect_with_policy(addr, bdk_net, policy) {
                Ok(peer) => peer,
                Err(e) => {
                    let elapsed = attempt_started.elapsed();
                    unproductive_elapsed += elapsed;
                    let stage = connect_failure_stage(&e);
                    crate::diag::log(format!(
                        "sync: mweb peer={addr} stage={stage} err={} attempt={tried}/{total_peers} ms={}",
                        compact_peer_err(&e, stage),
                        elapsed.as_millis() as u64,
                    ));
                    if self.last_good_peer == Some(addr) {
                        self.last_good_peer = None;
                    }
                    hard_failed.push(addr);
                    last_err = Some(e);
                    continue;
                }
            };
            served += 1;
            let backup_addrs: Vec<std::net::SocketAddr> = if need_cross_probe {
                addrs
                    .iter()
                    .skip(idx + 1)
                    .copied()
                    .filter(|a| *a != addr && !hard_failed.contains(a) && !lagging.contains(a))
                    .collect()
            } else {
                Vec::new()
            };
            let probe_policy = peer_policy_for_pool(backup_addrs.len().max(2));
            let pass_aborted = std::sync::atomic::AtomicBool::new(false);

            let (sync_res, last_stage, stage_unproductive, pre_probed) =
                std::thread::scope(|scope| {
                    let mut peer = CancellableMwebPeer {
                        inner: tcp_peer,
                        cancel,
                        pending_lock,
                        probe_spec: (!backup_addrs.is_empty()).then_some(CrossProbeSpec {
                            scope,
                            backup_addrs,
                            tip_hash,
                            bdk_net,
                            policy: probe_policy,
                            cancel,
                            pending_lock,
                            pass_aborted: &pass_aborted,
                        }),
                        probe_handle: None,
                        last_progress_at: std::time::Instant::now(),
                        aborted_pipeline_err: None,
                        needs_reconnect_before_sequential: false,
                    };
                    let res = self.store.sync_differential(
                        bdk_wallet::MwebSyncDrivers {
                            syncer: &syncer,
                            headers: &headers,
                            notifier: &mut notifier,
                            state: &mut self.sync_state,
                        },
                        &mut peer,
                        bdk_wallet::MwebScanContext {
                            keys: &self.keys,
                            book: &self.book,
                            secp: &self.secp,
                        },
                    );
                    let stage = peer.last_stage();
                    let unproductive = peer.unproductive_elapsed();
                    if res.is_err() {
                        pass_aborted.store(true, std::sync::atomic::Ordering::Release);
                    }
                    let pre = peer.probe_handle.take().and_then(|h| h.join().ok());
                    (res, stage, unproductive, pre)
                });

            match sync_res {
                Ok(result) => {
                    crate::discovery::evict_peers(&hard_failed);
                    crate::discovery::demote_peers(&lagging);
                    crate::discovery::note_good_peer(addr);
                    self.last_good_peer = Some(addr);
                    self.last_synced_height = Some(tip_height);
                    self.stale = false;
                    self.last_status = format!(
                        "MWEB synced at {tip_height} (+{} downloaded, {} found)",
                        result.downloaded,
                        result.found.len()
                    );
                    let completed_full_scan =
                        full_utxo_scan && self.sync_state.utxo_cursor.is_none();
                    self.apply_post_sync(tip_height, hold_spent, completed_full_scan);
                    crate::diag::log(format!(
                        "sync: mweb pass peer={addr} prev_height={prev_height:?} tip={tip_height} full_scan={full_utxo_scan} \
                         invalidated_outgoing={invalidated_for_outgoing} prior_leafset_bytes={prior_leafset_bytes} \
                         leafset_bytes={} downloaded={} found={} ms={}",
                        self.sync_state.leafset.len(),
                        result.downloaded,
                        result.found.len(),
                        pass_started.elapsed().as_millis() as u64,
                    ));
                    return Ok(pre_probed);
                }
                Err(e) => {
                    if CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
                        last_err = Some(e);
                        break;
                    }
                    let elapsed = attempt_started.elapsed();
                    unproductive_elapsed += stage_unproductive;
                    let stage = last_stage;
                    crate::diag::log(format!(
                        "sync: mweb peer={addr} stage={stage} err={} attempt={tried}/{total_peers} ms={}",
                        compact_peer_err(&e, stage),
                        elapsed.as_millis() as u64,
                    ));
                    if self.last_good_peer == Some(addr) {
                        self.last_good_peer = None;
                    }
                    if is_clean_tip_lag(&e, stage) {
                        tip_lag_count += 1;
                        lagging.push(addr);
                    } else if e.ban_reason() == Some(BanReason::Throttled) {
                        lagging.push(addr);
                    } else if e.ban_reason() == Some(BanReason::Undecodable) {
                        undecodable += 1;
                    } else {
                        hard_failed.push(addr);
                    }
                    if !is_rotatable_peer_error(&e) {
                        last_err = Some(e);
                        break;
                    }
                    last_err = Some(e);
                }
            }
        }

        if !CancellableMwebPeer::is_cancelled(cancel, pending_lock) {
            crate::discovery::evict_peers(&hard_failed);
            crate::discovery::demote_peers(&lagging);
        }
        let err = if served > 0 && undecodable == served {
            let last = last_err.map(|e| format!("{e}")).unwrap_or_default();
            bdk_mweb::Error::undecodable(format!(
                "block data from all {served} peer(s) failed to decode; this points at a local \
                 decoder bug (bdk_mweb / rust-litecoin), not at the peers. Last error: {last}"
            ))
        } else {
            last_err
                .unwrap_or_else(|| bdk_mweb::Error::Crypto("MWEB sync failed on all peers".into()))
        };
        crate::diag::log(format!(
            "sync: mweb pass failed tip={tip_height} tried={tried}/{total_peers} err={err} ms={}",
            pass_started.elapsed().as_millis() as u64,
        ));
        Err(SyncPassFailure {
            err,
            tried,
            all_tip_lag: tried > 0 && tip_lag_count == tried,
            hard_failed,
        })
    }

    pub fn disconnect_from(&mut self, height: u32) {
        self.store.disconnect_from(height);
        self.sync_state.height_map.retain(|&h, _| h < height);
        self.last_cross_checked_tip = None;
        if self.sync_state.tip_height.is_some_and(|h| h >= height) {
            self.sync_state.tip_height = height.checked_sub(1);
            self.sync_state.invalidate_leafset();
        }
        // Reorged-out entries must be re-resolved on the new chain.
        for entry in &mut self.history.entries {
            if entry.confirmed_height.is_some_and(|h| h >= height) {
                entry.confirmed_height = None;
            }
        }
    }

    /// Re-apply spends a self-spend is still holding, then absorb receives.
    ///
    /// P-6 restores a locally spent coin whose leaf is still unspent after 12
    /// blocks. That is right for a spend that was broadcast and then dropped.
    /// A self-spend marks its input spent when the hop is armed, which can be
    /// many blocks before broadcast, so the restore would hand the coin back
    /// while the signed transaction still spends it. `hold_spent` is those
    /// inputs. Re-marking clears the staged restore, so the persist after this
    /// pass keeps the coin spent, and absorb does not record it as a receive.
    fn apply_post_sync(
        &mut self,
        tip_height: u32,
        hold_spent: &BTreeSet<[u8; 32]>,
        completed_full_scan: bool,
    ) {
        for id in hold_spent {
            let _ = self.store.db_mut().mark_spent(id);
        }
        self.absorb_received_coins();
        let leafset = self.sync_state.leafset.clone();
        update_outgoing_confirmations_after_scan(
            &mut self.history,
            self.store.db_mut(),
            &leafset,
            tip_height,
            completed_full_scan,
        );
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
                net_sats: i64::try_from(coin.amount.min(crate::tx_invariants::MAX_MONEY))
                    .unwrap_or(i64::MAX),
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
        let mweb_addr = self.receive_address(transparent.network).ok();
        Ok(CombinedSummary {
            transparent,
            mweb_confirmed_sats: bal.mweb_confirmed.to_sat(),
            mweb_unconfirmed_sats: bal.mweb_untrusted_pending.to_sat(),
            mweb_immature_sats: bal.mweb_immature.to_sat(),
            mweb_maturity_blocks: MWEB_PEGIN_MATURITY,
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
        let Some(coin) = db.get_spent(&id) else {
            continue;
        };
        let Some(leaf) = coin.leaf_index else {
            continue;
        };
        if leafset_has_leaf(leafset, leaf) {
            let _ = db.restore_spent(&id);
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
#[cfg(test)]
pub(crate) fn update_outgoing_confirmations(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
) {
    update_outgoing_confirmations_at(history, db, leafset, tip, now_ts());
}

fn update_outgoing_confirmations_after_scan(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
    completed_full_scan: bool,
) {
    update_outgoing_confirmations_at_inner(
        history,
        db,
        leafset,
        tip,
        now_ts(),
        completed_full_scan,
    );
}

#[cfg(test)]
fn update_outgoing_confirmations_at(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
    now: u64,
) {
    update_outgoing_confirmations_at_inner(history, db, leafset, tip, now, false);
}

fn update_outgoing_confirmations_at_inner(
    history: &mut MwebHistory,
    db: &mut MwebCoinDatabase,
    leafset: &[u8],
    tip: u32,
    now: u64,
    completed_full_scan: bool,
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
                Some(coin) => match coin.leaf_index {
                    Some(leaf) => !leafset_has_leaf(leafset, leaf),
                    // A completed full UTXO download scans every unspent output on
                    // chain and populates `leaf_index`. A spent coin that still has
                    // no `leaf_index` after a full scan is absent from the chain's
                    // unspent set (confirmed spent on chain).
                    None => completed_full_scan && db.get(&id).is_none(),
                },
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

    /// Block data our decoder rejects points at this wallet, not the peer:
    /// another peer would fail the same way, so it must not get our queries.
    #[test]
    fn undecodable_block_data_asks_for_an_update_without_public_fallback() {
        let failure = classify_pass_failure(&bdk_mweb::Error::undecodable(
            "mwebutxos decode: output at leaf 7: unexpected end of file",
        ));
        assert!(!failure.allow_public_fallback);
        assert!(
            !failure.status.contains("unreachable"),
            "{}",
            failure.status
        );
        assert!(failure.status.contains("update"), "{}", failure.status);
    }

    /// Everything that is not a throttle or a decode failure keeps the old behavior: a node that
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

    /// A [`coin`] whose commitment opens to its amount and blind. Reloading a
    /// store drops coins that fail that check, so tests that persist and reopen
    /// need one.
    fn persistable_coin(id: u8, height: Option<u32>, leaf_index: Option<u64>) -> MwebCoin {
        let mut c = coin(id, height, leaf_index);
        c.blind = [0x0b; 32];
        c.commitment = bdk_mweb::crypto::switch_commit(&c.blind, c.amount, &Secp256k1::new())
            .expect("valid blind");
        c
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
    fn completed_full_utxo_scan_confirms_unverifiable_outgoing_spend_without_reinvalidating_leafset(
    ) {
        let mut db = MwebCoinDatabase::default();
        db.insert(coin(2, None, None));
        db.mark_spent(&[2; 32]);
        let mut history = MwebHistory::default();
        history.record(entry(TxKind::Pegout, &[], &[2]));
        assert!(pending_unverifiable_outgoing(&history, &db));

        update_outgoing_confirmations_after_scan(&mut history, &mut db, &leafset(&[9]), TIP, true);
        assert_eq!(history.entries[0].confirmed_height, Some(TIP));
        assert!(
            !pending_unverifiable_outgoing(&history, &db),
            "after a full UTXO scan resolves the spend, subsequent syncs must not re-invalidate the leafset"
        );
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
            0,
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
        assert_eq!(rows[0].status, CoinStatus::Frozen);
        assert!(rows[0].actions.unfreeze);
        assert_eq!(rows[0].actions.blocked, Some(CoinBlock::Frozen));
    }

    fn ready_facts() -> CoinFacts {
        CoinFacts {
            confirmations: 10,
            mature: true,
            maturity_blocks_left: 0,
            locked: false,
            reserved: false,
            from_pegin: false,
            non_solo_blocks: None,
            churn_phase: None,
        }
    }

    #[test]
    fn coin_status_reports_each_status() {
        let cases = [
            (ready_facts(), CoinStatus::Ready),
            (
                CoinFacts {
                    churn_phase: Some(ChurnPhase::WaitingForCover),
                    ..ready_facts()
                },
                CoinStatus::Churning,
            ),
            (
                CoinFacts {
                    reserved: true,
                    ..ready_facts()
                },
                CoinStatus::Sending,
            ),
            (
                CoinFacts {
                    confirmations: 0,
                    mature: false,
                    maturity_blocks_left: 6,
                    ..ready_facts()
                },
                CoinStatus::Pending,
            ),
            (
                CoinFacts {
                    confirmations: 2,
                    mature: false,
                    maturity_blocks_left: 4,
                    from_pegin: true,
                    ..ready_facts()
                },
                CoinStatus::Maturing,
            ),
            (
                CoinFacts {
                    locked: true,
                    ..ready_facts()
                },
                CoinStatus::Frozen,
            ),
            (
                CoinFacts {
                    from_pegin: true,
                    non_solo_blocks: Some(0),
                    ..ready_facts()
                },
                CoinStatus::TiedToPegin,
            ),
            (
                CoinFacts {
                    from_pegin: true,
                    non_solo_blocks: None,
                    ..ready_facts()
                },
                CoinStatus::Ready,
            ),
            (
                CoinFacts {
                    churn_phase: Some(ChurnPhase::Done),
                    ..ready_facts()
                },
                CoinStatus::Ready,
            ),
        ];
        for (facts, want) in cases {
            assert_eq!(coin_status(&facts).0, want);
        }
    }

    #[test]
    fn coin_status_takes_the_first_match() {
        let churning_frozen_tied = CoinFacts {
            churn_phase: Some(ChurnPhase::PausedSolo),
            locked: true,
            from_pegin: true,
            non_solo_blocks: Some(0),
            ..ready_facts()
        };
        let (status, actions) = coin_status(&churning_frozen_tied);
        assert_eq!(status, CoinStatus::Churning);
        assert_eq!(actions.blocked, Some(CoinBlock::Churning));
        assert!(!actions.unfreeze, "the job owns the freeze while it runs");

        let sending_frozen = CoinFacts {
            reserved: true,
            locked: true,
            ..ready_facts()
        };
        let (status, actions) = coin_status(&sending_frozen);
        assert_eq!(status, CoinStatus::Sending);
        assert_eq!(actions.blocked, Some(CoinBlock::Sending));
        assert!(
            !actions.unfreeze,
            "the send owns the coin until it finishes"
        );

        let maturing_frozen = CoinFacts {
            confirmations: 2,
            mature: false,
            maturity_blocks_left: 4,
            locked: true,
            ..ready_facts()
        };
        let (status, actions) = coin_status(&maturing_frozen);
        assert_eq!(status, CoinStatus::Maturing);
        assert_eq!(actions.blocked, Some(CoinBlock::Frozen));

        let frozen_tied = CoinFacts {
            locked: true,
            from_pegin: true,
            non_solo_blocks: Some(0),
            ..ready_facts()
        };
        assert_eq!(coin_status(&frozen_tied).0, CoinStatus::Frozen);
    }

    #[test]
    fn coin_actions_follow_the_blocked_reason() {
        let pending = CoinFacts {
            confirmations: 0,
            mature: false,
            maturity_blocks_left: 1,
            ..ready_facts()
        };
        let maturing = CoinFacts {
            confirmations: 3,
            mature: false,
            maturity_blocks_left: 3,
            ..ready_facts()
        };
        let frozen = CoinFacts {
            locked: true,
            ..ready_facts()
        };
        let churning = CoinFacts {
            churn_phase: Some(ChurnPhase::WaitingConfirm),
            locked: true,
            ..ready_facts()
        };
        let tied = CoinFacts {
            from_pegin: true,
            non_solo_blocks: Some(0),
            ..ready_facts()
        };
        let sending = CoinFacts {
            reserved: true,
            ..ready_facts()
        };
        let cases = [
            (sending, Some(CoinBlock::Sending), false),
            (pending, Some(CoinBlock::Unconfirmed), false),
            (
                maturing,
                Some(CoinBlock::Maturing { blocks_left: 3 }),
                false,
            ),
            (frozen, Some(CoinBlock::Frozen), true),
            (churning, Some(CoinBlock::Churning), false),
        ];
        for (facts, blocked, unfreeze) in cases {
            let a = coin_status(&facts).1;
            assert_eq!(a.blocked, blocked);
            assert!(!a.spend_to_self && !a.split && !a.transfer && !a.select && !a.freeze);
            assert_eq!(a.unfreeze, unfreeze);
        }
        for facts in [ready_facts(), tied] {
            let a = coin_status(&facts).1;
            assert_eq!(a.blocked, None);
            assert!(a.spend_to_self && a.split && a.transfer && a.select && a.freeze);
            assert!(!a.unfreeze);
        }
    }

    fn public_facts(
        confirmations: u32,
        mature: bool,
        maturity_blocks_left: u32,
        locked: bool,
        reserved: bool,
    ) -> PublicCoinFacts {
        PublicCoinFacts {
            confirmations,
            mature,
            maturity_blocks_left,
            locked,
            reserved,
        }
    }

    #[test]
    fn public_coin_status_takes_the_first_match() {
        // (facts, status, blocked, select/freeze, split/transfer, unfreeze)
        let cases = [
            (
                public_facts(3, true, 0, false, false),
                CoinStatus::Ready,
                None,
                true,
                true,
                false,
            ),
            (
                public_facts(0, true, 0, false, false),
                CoinStatus::Pending,
                Some(CoinBlock::Unconfirmed),
                true,
                false,
                false,
            ),
            (
                public_facts(0, false, 6, false, false),
                CoinStatus::Pending,
                Some(CoinBlock::Unconfirmed),
                false,
                false,
                false,
            ),
            (
                public_facts(2, false, 4, false, false),
                CoinStatus::Maturing,
                Some(CoinBlock::Maturing { blocks_left: 4 }),
                false,
                false,
                false,
            ),
            (
                public_facts(2, false, 4, true, false),
                CoinStatus::Maturing,
                Some(CoinBlock::Frozen),
                false,
                false,
                true,
            ),
            (
                public_facts(2, false, 4, false, true),
                CoinStatus::Sending,
                Some(CoinBlock::Sending),
                false,
                false,
                false,
            ),
            (
                public_facts(3, true, 0, true, false),
                CoinStatus::Frozen,
                Some(CoinBlock::Frozen),
                false,
                false,
                true,
            ),
            (
                public_facts(0, true, 0, true, false),
                CoinStatus::Pending,
                Some(CoinBlock::Frozen),
                false,
                false,
                true,
            ),
            (
                public_facts(3, true, 0, false, true),
                CoinStatus::Sending,
                Some(CoinBlock::Sending),
                false,
                false,
                false,
            ),
            (
                public_facts(3, true, 0, true, true),
                CoinStatus::Sending,
                Some(CoinBlock::Sending),
                false,
                false,
                false,
            ),
        ];
        for (facts, status, blocked, free, spend, unfreeze) in cases {
            let (s, a) = public_coin_status(&facts);
            assert_eq!(s, status, "{facts:?}");
            assert_eq!(a.blocked, blocked, "{facts:?}");
            assert_eq!((a.select, a.freeze), (free, free), "{facts:?}");
            assert_eq!((a.split, a.transfer), (spend, spend), "{facts:?}");
            assert_eq!(
                a.unfreeze, unfreeze,
                "the send owns the coin until it finishes: {facts:?}"
            );
            assert!(!a.spend_to_self, "{facts:?}");
        }
    }

    /// Doc order for [`coin_status`], written as a list so it is not a copy of the `if` chain.
    fn spec_private(f: &CoinFacts) -> (CoinStatus, Option<CoinBlock>) {
        let churning = f.churn_phase.is_some_and(ChurnPhase::is_active);
        let status = [
            (CoinStatus::Churning, churning),
            (CoinStatus::Sending, f.reserved),
            (CoinStatus::Pending, !f.mature && f.confirmations == 0),
            (CoinStatus::Maturing, !f.mature),
            (CoinStatus::Frozen, f.locked),
            (
                CoinStatus::TiedToPegin,
                f.from_pegin && f.non_solo_blocks == Some(0),
            ),
            (CoinStatus::Ready, true),
        ]
        .into_iter()
        .find(|(_, applies)| *applies)
        .unwrap()
        .0;
        let blocked = [
            (CoinBlock::Churning, churning),
            (CoinBlock::Sending, f.reserved),
            (CoinBlock::Frozen, f.locked),
            (CoinBlock::Unconfirmed, !f.mature && f.confirmations == 0),
            (
                CoinBlock::Maturing {
                    blocks_left: f.maturity_blocks_left,
                },
                !f.mature,
            ),
        ]
        .into_iter()
        .find(|(_, applies)| *applies)
        .map(|(block, _)| block);
        (status, blocked)
    }

    #[test]
    fn coin_status_holds_for_every_fact_combination() {
        let phases = std::iter::once(None).chain(ChurnPhase::ALL.map(Some));
        let maturities = [
            (0, false, 6), // pending
            (2, false, 4), // maturing peg-in
            (10, true, 0), // mature
        ];
        let mut seen = 0usize;
        for churn_phase in phases {
            for reserved in [false, true] {
                for locked in [false, true] {
                    for (confirmations, mature, maturity_blocks_left) in maturities {
                        for from_pegin in [false, true] {
                            for non_solo_blocks in [None, Some(0), Some(1)] {
                                let facts = CoinFacts {
                                    confirmations,
                                    mature,
                                    maturity_blocks_left,
                                    locked,
                                    reserved,
                                    from_pegin,
                                    non_solo_blocks,
                                    churn_phase,
                                };
                                let (status, actions) = coin_status(&facts);
                                let (want_status, want_blocked) = spec_private(&facts);
                                assert_eq!(status, want_status, "{facts:?}");
                                assert_eq!(actions.blocked, want_blocked, "{facts:?}");
                                let spend = actions.blocked.is_none();
                                assert_eq!(
                                    (
                                        actions.spend_to_self,
                                        actions.split,
                                        actions.transfer,
                                        actions.select,
                                        actions.freeze,
                                    ),
                                    (spend, spend, spend, spend, spend),
                                    "{facts:?}"
                                );
                                assert_eq!(
                                    spend,
                                    matches!(status, CoinStatus::Ready | CoinStatus::TiedToPegin),
                                    "{facts:?}"
                                );
                                let churning = facts.churn_phase.is_some_and(ChurnPhase::is_active);
                                if facts.reserved || churning {
                                    assert!(
                                        !actions.spend_to_self
                                            && !actions.split
                                            && !actions.transfer
                                            && !actions.select
                                            && !actions.freeze
                                            && !actions.unfreeze,
                                        "a hold is not a freeze the user can undo: {facts:?}"
                                    );
                                }
                                if facts.locked && !facts.reserved && !churning {
                                    assert!(actions.unfreeze, "{facts:?}");
                                }
                                if !facts.locked {
                                    assert!(!actions.unfreeze, "{facts:?}");
                                }
                                assert!(
                                    !(actions.freeze && actions.unfreeze),
                                    "freeze and unfreeze are never both on: {facts:?}"
                                );
                                if status == CoinStatus::Churning {
                                    assert_eq!(actions.blocked, Some(CoinBlock::Churning));
                                }
                                if status == CoinStatus::Sending {
                                    assert_eq!(actions.blocked, Some(CoinBlock::Sending));
                                }
                                if let Some(CoinBlock::Maturing { blocks_left }) = actions.blocked {
                                    assert_eq!(blocks_left, facts.maturity_blocks_left);
                                }
                                seen += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(seen, 8 * 2 * 2 * 3 * 2 * 3);
    }

    /// Doc order for [`public_coin_status`].
    fn spec_public(f: &PublicCoinFacts) -> (CoinStatus, Option<CoinBlock>) {
        let status = [
            (CoinStatus::Sending, f.reserved),
            (CoinStatus::Pending, f.confirmations == 0),
            (CoinStatus::Maturing, !f.mature),
            (CoinStatus::Frozen, f.locked),
            (CoinStatus::Ready, true),
        ]
        .into_iter()
        .find(|(_, applies)| *applies)
        .unwrap()
        .0;
        let blocked = [
            (CoinBlock::Sending, f.reserved),
            (CoinBlock::Frozen, f.locked),
            (CoinBlock::Unconfirmed, f.confirmations == 0),
            (
                CoinBlock::Maturing {
                    blocks_left: f.maturity_blocks_left,
                },
                !f.mature,
            ),
        ]
        .into_iter()
        .find(|(_, applies)| *applies)
        .map(|(block, _)| block);
        (status, blocked)
    }

    #[test]
    fn public_coin_status_holds_for_every_fact_combination() {
        let maturities = [
            (0, true, 0),  // ordinary unconfirmed public coin (stays selectable)
            (0, false, 6), // unconfirmed HogEx peg-out / coinbase
            (1, false, 5), // 1-conf HogEx peg-out (5 blocks left)
            (5, false, 1), // 5-conf HogEx peg-out (1 block left)
            (6, true, 0),  // 6-conf mature HogEx peg-out
            (1, true, 0),  // 1-conf ordinary public coin
        ];
        let mut seen = 0usize;
        for (confirmations, mature, maturity_blocks_left) in maturities {
            for locked in [false, true] {
                for reserved in [false, true] {
                    let facts = public_facts(
                        confirmations,
                        mature,
                        maturity_blocks_left,
                        locked,
                        reserved,
                    );
                    let (status, actions) = public_coin_status(&facts);
                    let (want_status, want_blocked) = spec_public(&facts);
                    assert_eq!(status, want_status, "{facts:?}");
                    assert_eq!(actions.blocked, want_blocked, "{facts:?}");
                    assert!(!actions.spend_to_self, "{facts:?}");
                    let free = !facts.reserved && !facts.locked && facts.mature;
                    assert_eq!((actions.select, actions.freeze), (free, free), "{facts:?}");
                    let spend = actions.blocked.is_none();
                    assert_eq!(
                        (actions.split, actions.transfer),
                        (spend, spend),
                        "{facts:?}"
                    );
                    assert_eq!(spend, status == CoinStatus::Ready, "{facts:?}");
                    assert_eq!(
                        actions.unfreeze,
                        facts.locked && !facts.reserved,
                        "{facts:?}"
                    );
                    assert!(
                        !(actions.freeze && actions.unfreeze),
                        "freeze and unfreeze are never both on: {facts:?}"
                    );
                    if facts.reserved {
                        assert!(
                            !actions.spend_to_self
                                && !actions.split
                                && !actions.transfer
                                && !actions.select
                                && !actions.freeze
                                && !actions.unfreeze,
                            "a hold is not a freeze the user can undo: {facts:?}"
                        );
                    }
                    if let Some(CoinBlock::Maturing { blocks_left }) = actions.blocked {
                        assert_eq!(blocks_left, facts.maturity_blocks_left, "{facts:?}");
                    }
                    seen += 1;
                }
            }
        }
        assert_eq!(seen, 6 * 2 * 2);
    }

    #[test]
    fn pegin_blocks_left_only_while_a_pegin_matures() {
        assert_eq!(
            pegin_blocks_left(TxKind::Pegin, 0),
            Some(MWEB_PEGIN_MATURITY)
        );
        assert_eq!(
            pegin_blocks_left(TxKind::Pegin, 2),
            Some(MWEB_PEGIN_MATURITY - 2)
        );
        assert_eq!(pegin_blocks_left(TxKind::Pegin, MWEB_PEGIN_MATURITY), None);
        assert_eq!(pegin_blocks_left(TxKind::Pegout, 0), None);
        assert_eq!(pegin_blocks_left(TxKind::Transparent, 1), None);
    }

    /// Verify all Litecoin Core MWEB consensus equations on an authored transaction:
    /// 1. Pedersen commitment balance: `Σ C_out + (fee + Σ pegout)·H == Σ C_in + pegin·H + Σ excess + kernel_offset·G`
    /// 2. Stealth excess balance: `Σ Ks + Σ Ki == Σ stealth_excess + Σ Ko_in + stealth_offset·G`
    /// 3. 675-byte Bulletproof rangeproof verification on every output (`extra_data = serialize(&output.message)`)
    /// 4. Strict canonical sorting of inputs and outputs by `output_id`, plus wire serialize/deserialize round-trip.
    fn assert_mweb_tx_consensus_and_balance(tx: &Transaction, secp: &Secp256k1<All>) {
        use bdk_mweb::crypto::{bulletproof_verify, commitment_to_pubkey, pedersen_commit};
        use bdk_wallet::bitcoin::consensus::encode::serialize;
        use bdk_wallet::bitcoin::secp256k1::{PublicKey, SecretKey};

        let raw = serialize(tx);
        let roundtripped: Transaction = deserialize(&raw).expect("consensus MWEB tx round-trip");
        assert_eq!(roundtripped.compute_wtxid(), tx.compute_wtxid());

        let mw = tx.mw_tx.as_ref().expect("mw_tx present");
        for win in mw.body.inputs.windows(2) {
            assert!(
                win[0].output_id < win[1].output_id,
                "inputs not strictly sorted"
            );
        }
        for win in mw.body.outputs.windows(2) {
            assert!(
                bdk_mweb::output_id(&win[0]) < bdk_mweb::output_id(&win[1]),
                "outputs not strictly sorted"
            );
        }

        for out in &mw.body.outputs {
            let extra = serialize(&out.message);
            assert!(
                bulletproof_verify(&out.commitment, &out.range_proof, &extra)
                    .expect("bulletproof FFI"),
                "bulletproof failed to verify on output {}",
                hex::encode(bdk_mweb::output_id(out))
            );
        }

        // Fixed blind r for value-only terms: C(v, r) - C(0, r) = v·H.
        let r = [0x11u8; 32];
        let zero_r = commitment_to_pubkey(&pedersen_commit(0, &r, secp).unwrap()).unwrap();
        let value_h = |v: u64| -> Option<PublicKey> {
            (v > 0).then(|| {
                let with_v = commitment_to_pubkey(&pedersen_commit(v, &r, secp).unwrap()).unwrap();
                with_v.combine(&zero_r.negate(secp)).unwrap()
            })
        };

        let mut fee_and_pegout = 0u64;
        let mut pegin_total = 0u64;
        for k in &mw.body.kernels {
            if let Some(f) = k.fee {
                assert!(f >= 0, "negative kernel fee");
                fee_and_pegout = fee_and_pegout.checked_add(f as u64).unwrap();
            }
            for po in &k.pegouts {
                assert!(po.amount > 0, "non-positive pegout");
                fee_and_pegout = fee_and_pegout.checked_add(po.amount as u64).unwrap();
            }
            if let Some(p) = k.pegin {
                assert!(p > 0, "non-positive pegin");
                pegin_total = pegin_total.checked_add(p as u64).unwrap();
            }
        }

        let mut commit_lhs: Vec<PublicKey> = mw
            .body
            .outputs
            .iter()
            .map(|o| commitment_to_pubkey(&o.commitment).unwrap())
            .collect();
        commit_lhs.extend(value_h(fee_and_pegout));

        let mut commit_rhs: Vec<PublicKey> = mw
            .body
            .inputs
            .iter()
            .map(|i| commitment_to_pubkey(&i.commitment).unwrap())
            .collect();
        commit_rhs.extend(value_h(pegin_total));
        commit_rhs.extend(
            mw.body
                .kernels
                .iter()
                .map(|k| commitment_to_pubkey(&k.excess).unwrap()),
        );
        if mw.kernel_offset != [0u8; 32] {
            commit_rhs.push(PublicKey::from_secret_key(
                secp,
                &SecretKey::from_slice(&mw.kernel_offset).unwrap(),
            ));
        }
        let sum_keys = |keys: &[PublicKey]| -> PublicKey {
            let refs: Vec<&PublicKey> = keys.iter().collect();
            PublicKey::combine_keys(&refs).unwrap()
        };
        assert_eq!(
            sum_keys(&commit_lhs),
            sum_keys(&commit_rhs),
            "Pedersen commitments and kernel excess do not balance"
        );

        let mut stealth_lhs: Vec<PublicKey> = mw
            .body
            .outputs
            .iter()
            .map(|o| o.sender_public_key)
            .collect();
        stealth_lhs.extend(mw.body.inputs.iter().filter_map(|i| i.input_public_key));

        let mut stealth_rhs: Vec<PublicKey> = mw
            .body
            .kernels
            .iter()
            .filter_map(|k| k.stealth_excess)
            .collect();
        stealth_rhs.extend(mw.body.inputs.iter().map(|i| i.output_public_key));
        if mw.stealth_offset != [0u8; 32] {
            stealth_rhs.push(PublicKey::from_secret_key(
                secp,
                &SecretKey::from_slice(&mw.stealth_offset).unwrap(),
            ));
        }
        assert_eq!(
            sum_keys(&stealth_lhs),
            sum_keys(&stealth_rhs),
            "Stealth excess and offset do not balance"
        );
    }

    #[test]
    fn mweb_constructed_spends_balance_commitments_stealth_and_rangeproofs() {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::chain::BlockId;
        use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};

        let dir = tempfile::tempdir().unwrap();
        let mnemonic = crate::descriptors::generate_mnemonic().unwrap();
        let secret = crate::seed::MasterSecret::parse(&mnemonic, None).unwrap();
        let network = WalletNetwork::Testnet;
        let meta = crate::meta::WalletMeta::new(network, None);
        let mut db = Connection::open(meta::db_path(dir.path())).unwrap();
        let params = crate::descriptors::create_params(&secret, network, 0).unwrap();
        let mut wallet = PersistedWallet::create(&mut db, params).unwrap();
        insert_checkpoint(
            &mut wallet,
            BlockId {
                height: 100,
                hash: BlockHash::all_zeros(),
            },
        );
        let _utxo = receive_output_in_latest_block(&mut wallet, Amount::from_sat(10_000_000));
        wallet.persist(&mut db).unwrap();
        let signer = crate::descriptors::signer(&secret, network, 0).unwrap();

        let mut runtime = MwebRuntime::open(
            dir.path(),
            &secret,
            network,
            crate::dto::MwebScheme::default().to_master_scheme(),
            0,
            None,
        )
        .unwrap();
        let _ = meta;

        // 1. Peg-in: prepare -> sign transparent -> extract -> verify consensus & rewind.
        let mut prepared_pegin = prepare_pegin(
            &mut wallet,
            &runtime.keys,
            runtime.receive_index,
            2_000_000,
            50_000,
            1_000,
            &[],
            Vec::new(),
            network,
            &runtime.secp,
        )
        .unwrap();
        sign_and_finalize(&wallet, &signer, &mut prepared_pegin.psbt).unwrap();
        let pegin_tx = extract_prepared_mweb_pegin(&prepared_pegin.psbt).unwrap();
        crate::tx_invariants::verify_pegin_tx(
            &prepared_pegin.psbt,
            &pegin_tx,
            &prepared_pegin.kernel_id,
            2_000_000,
            50_000,
            1_000,
            &prepared_pegin.outputs,
            &runtime.secp,
        )
        .unwrap();
        assert_mweb_tx_consensus_and_balance(&pegin_tx, &runtime.secp);

        // Rewind / scan the peg-in tx with our AddressBook and confirm the credited coin matches.
        let mut scan_db = MwebCoinDatabase::default();
        let scanned_pegin = bdk_mweb::scan_litecoin_tx(
            &runtime.keys,
            &runtime.book,
            &pegin_tx,
            &mut scan_db,
            &runtime.secp,
        )
        .unwrap();
        assert_eq!(scanned_pegin.len(), 1);
        assert_eq!(scanned_pegin[0].amount, 1_950_000);
        assert_eq!(
            scanned_pegin[0].output_id,
            prepared_pegin.outputs[0].output_id
        );

        // Insert mature peg-in coin into store for subsequent spends.
        let mut pegin_coin = prepared_pegin.outputs[0].clone();
        pegin_coin.is_pegin = true;
        pegin_coin.block_height = Some(50);
        pegin_coin.leaf_index = Some(1);
        let pegin_id_hex = hex::encode(pegin_coin.output_id);
        runtime.store.db_mut().insert(pegin_coin.clone());

        // 2. Private send with change: 1,950,000 -> 500,000 recipient + 50,000 fee + 1,400,000 change.
        let mweb_dest = runtime.receive_address(network).unwrap();
        let signed_send = sign_mweb_send(
            &wallet,
            &mut runtime,
            dir.path(),
            &MwebSendRequest {
                address: mweb_dest,
                amount_sats: 500_000,
                fee_sats: 50_000,
                drain: false,
                selected_output_ids: Some(vec![pegin_id_hex.clone()]),
            },
            network,
        )
        .unwrap();
        assert_mweb_tx_consensus_and_balance(&signed_send.tx, &runtime.secp);
        assert_eq!(signed_send.change.as_ref().unwrap().amount, 1_400_000);

        // 3. Private split (1-in-3): 1,950,000 -> [600,000, 600,000, 700,000] + 50,000 fee.
        let signed_split = sign_mweb_split(
            &wallet,
            &mut runtime,
            dir.path(),
            &pegin_id_hex,
            &[600_000, 600_000, 700_000],
            50_000,
            network,
        )
        .unwrap();
        assert_mweb_tx_consensus_and_balance(&signed_split.tx, &runtime.secp);
        assert_eq!(signed_split.outputs.len(), 3);

        // 4. Typed peg-out with private change: 1,950,000 -> 400,000 public + 50,000 fee + 1,500,000 change.
        let pub_dest = wallet
            .peek_address(bdk_wallet::KeychainKind::External, 0)
            .address
            .to_string();
        let signed_pegout = sign_pegout(
            &wallet,
            &runtime,
            dir.path(),
            PegoutRequest {
                address: pub_dest.clone(),
                amount_sats: 400_000,
                fee_sats: 50_000,
                drain: false,
                selected_output_ids: Some(vec![pegin_id_hex.clone()]),
                output_amounts: vec![400_000],
                addresses: Vec::new(),
                per_coin: false,
                fee_output_index: None,
            },
            network,
        )
        .unwrap();
        assert_mweb_tx_consensus_and_balance(&signed_pegout.tx, &runtime.secp);
        assert_eq!(signed_pegout.change.as_ref().unwrap().amount, 1_500_000);

        // 5. Per-coin peg-out (drain, no private change): 1,950,000 -> 1,900,000 public + 50,000 fee.
        let signed_per_coin = sign_pegout(
            &wallet,
            &runtime,
            dir.path(),
            PegoutRequest {
                address: String::new(),
                amount_sats: 1_900_000,
                fee_sats: 50_000,
                drain: true,
                selected_output_ids: Some(vec![pegin_id_hex]),
                output_amounts: vec![1_900_000],
                addresses: vec![pub_dest],
                per_coin: true,
                fee_output_index: Some(0),
            },
            network,
        )
        .unwrap();
        assert_mweb_tx_consensus_and_balance(&signed_per_coin.tx, &runtime.secp);
        assert!(signed_per_coin.change.is_none());

        // 6. Multi-hop self-spend chain (2 hops): 1,950,000 -> 1,900,000 -> 1,850,000.
        let hops = sign_self_spend_hops(
            &wallet,
            &mut runtime,
            dir.path(),
            pegin_coin,
            2,
            50_000,
            network,
        )
        .unwrap();
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].created.amount, 1_900_000);
        assert_eq!(hops[1].created.amount, 1_850_000);
        for hop in &hops {
            let tx: Transaction = deserialize(&hex::decode(&hop.raw_hex).unwrap()).unwrap();
            assert_mweb_tx_consensus_and_balance(&tx, &runtime.secp);
        }
    }

    #[test]
    fn plan_pegout_per_coin_seeded_property_holds_invariants() {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        let dust = p2wpkh_dust_sats().unwrap();
        for seed in 0..250u64 {
            let mut rng = StdRng::seed_from_u64(seed);
            let n = rng.gen_range(1..=12usize);
            let fee_sats = rng.gen_range(0..=150_000u64);
            let coins: Vec<u64> = (0..n)
                .map(|_| {
                    if rng.gen_bool(0.2) {
                        rng.gen_range(0..=dust + fee_sats)
                    } else {
                        rng.gen_range(dust..=50_000_000)
                    }
                })
                .collect();

            let res = plan_pegout_per_coin(&coins, fee_sats, dust);
            let script = p2wpkh_script();
            let min_fee = crate::tx_invariants::min_kernel_fee(
                0,
                std::iter::repeat(script.as_script()).take(n),
            );
            let max_coin = coins.iter().copied().max().unwrap();
            let min_coin = coins.iter().copied().min().unwrap();
            let should_succeed = fee_sats >= min_fee
                && max_coin >= fee_sats.saturating_add(dust)
                && min_coin >= dust;

            assert_eq!(
                res.is_ok(),
                should_succeed,
                "seed={seed} coins={coins:?} fee={fee_sats} dust={dust}: {res:?}"
            );
            if let Ok(plan) = res {
                assert_eq!(plan.amounts.len(), n);
                assert!(plan.fee_output_index < n);
                let in_sum: u64 = coins.iter().sum();
                let out_sum: u64 = plan.amounts.iter().sum();
                assert_eq!(out_sum + fee_sats, in_sum, "seed={seed}");
                for (i, &amt) in plan.amounts.iter().enumerate() {
                    assert!(amt >= dust, "seed={seed} output {i} below dust: {amt}");
                    if i == plan.fee_output_index {
                        assert_eq!(amt + fee_sats, coins[i], "seed={seed}");
                    } else {
                        assert_eq!(amt, coins[i], "seed={seed}");
                    }
                }
            }
        }
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
            0,
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

    /// A signed self-spend holds only its own coin. Split and transfer of the
    /// others still resolve. A second self-spend does not.
    #[test]
    fn other_coins_stay_spendable_while_a_self_spend_is_unbroadcast() {
        use crate::churn::{self, StartCheck};
        use crate::dto::ChurnPhase;
        use crate::split::{self, PlanParams};

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
            0,
            None,
        )
        .unwrap();
        let mut coin_a = coin(1, Some(100), Some(1));
        let mut coin_b = coin(2, Some(100), Some(2));
        let mut coin_c = coin(3, Some(100), Some(3));
        for coin in [&mut coin_a, &mut coin_b, &mut coin_c] {
            coin.amount = 2_000_000;
        }
        runtime.store.db_mut().insert(coin_a);
        runtime.store.db_mut().insert(coin_b);
        runtime.store.db_mut().insert(coin_c);

        let id_a = id_hex(1);
        let id_b = id_hex(2);
        let id_c = id_hex(3);
        let mut job = churn::new_job(&id_a, false, 1, 50_000, 2, false).unwrap();
        job.set_phase_for_test(ChurnPhase::WaitingForCover);
        churn::write_job(dir.path(), &job).unwrap();
        mweb_frozen::set_locked(dir.path(), &id_a, true).unwrap();

        let frozen = mweb_frozen::read_ids(dir.path()).unwrap().ids;
        let split_coin =
            select_split_coin(runtime.store.db(), &id_b, TIP, &frozen).expect("split coin B");
        let preview = split::plan_split(&PlanParams {
            input_sats: split_coin.amount,
            equal_count: Some(2),
            amounts: vec![],
            fee_sats: 50_000,
            fee_rate_sat_vb: 0,
            public: false,
            mweb_fee: 50_000,
        })
        .expect("plan split of B");
        assert_eq!(preview.outputs.len(), 2);

        let transfer = resolve_spend_coins(
            runtime.store.db(),
            TIP,
            &frozen,
            Some(&[id_c.clone()]),
            2_000_000,
            "spending",
        )
        .expect("transfer coin C");
        assert_eq!(transfer.len(), 1);
        assert_eq!(transfer[0].output_id, [3; 32]);

        let held = select_split_coin(runtime.store.db(), &id_a, TIP, &frozen).unwrap_err();
        assert!(
            held.to_string().to_lowercase().contains("frozen"),
            "coin A should stay held, got {held}"
        );

        let second = churn::check_start(&StartCheck {
            mature: true,
            frozen: false,
            amount_sats: 2_000_000,
            fee_sats: 50_000,
            job_active: churn::read_job(dir.path())
                .unwrap()
                .is_some_and(|job| job.phase().is_active()),
            target_depth: 1,
        })
        .unwrap_err();
        assert!(second.to_string().contains("already in progress"));

        assert!(churn::held_by_active_job(dir.path(), &id_a).unwrap());
        assert!(!churn::held_by_active_job(dir.path(), &id_b).unwrap());
        assert!(!churn::held_by_active_job(dir.path(), &id_c).unwrap());

        let rows = list_mweb_unspent(&runtime, TIP, dir.path());
        let phase = |id: &str| {
            rows.iter()
                .find(|row| row.output_id == id)
                .and_then(|row| row.churn_phase)
        };
        assert_eq!(phase(&id_a), Some(ChurnPhase::WaitingForCover));
        assert_eq!(phase(&id_b), None);
        assert_eq!(phase(&id_c), None);
        let job = churn::read_job(dir.path()).unwrap().unwrap();
        assert_eq!(job.current_output_id, id_a);
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
            MwebRuntime::open(dir.path(), &secret, WalletNetwork::Testnet, scheme, 0, None)
                .unwrap();
        legacy
            .store
            .db_mut()
            .insert(persistable_coin(1, Some(100), Some(4)));
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
            0,
            Some(zeroize::Zeroizing::new(key)),
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
        let mut reloaded = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            0,
            Some(zeroize::Zeroizing::new(key)),
        )
        .unwrap();
        assert!(reloaded.has_sealing_key_for_test());
        assert_eq!(reloaded.store.db().unspent_count(), 1);
        assert_eq!(reloaded.receive_index, 7);
        assert_eq!(reloaded.history.entries.len(), 1);
        reloaded.wipe();
        assert!(!reloaded.has_sealing_key_for_test());
        let blob = std::fs::read(meta::mweb_history_enc_path(dir.path())).unwrap();
        assert!(!blob.windows(2).any(|w| w == b"tx"));

        // Wrong key must fail loudly, not fall back to empty state.
        let wrong = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            0,
            Some(zeroize::Zeroizing::new([0u8; 32])),
        );
        assert!(wrong.is_err());
    }

    /// P-6 puts a locally spent coin back when its leaf is still unspent.
    /// An unbroadcast self-spend re-marks that coin before absorb, so the
    /// restore is not recorded as a new receive.
    #[test]
    fn unbroadcast_hold_keeps_a_restored_spend_spent() {
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        let mut runtime =
            MwebRuntime::open(dir.path(), &secret, WalletNetwork::Testnet, scheme, 0, None)
                .unwrap();
        let coin = persistable_coin(1, Some(100), Some(4));
        let id = coin.output_id;
        runtime.store.db_mut().insert(coin);
        assert!(runtime.store.db_mut().mark_spent(&id));
        assert!(runtime.store.db_mut().restore_spent(&id));

        runtime.apply_post_sync(100, &BTreeSet::from([id]), false);

        assert!(runtime.store.db().get(&id).is_none());
        assert!(runtime.store.db().get_spent(&id).is_some());
        assert!(
            !runtime
                .history
                .entries
                .iter()
                .any(|entry| entry.kind == TxKind::MwebReceive),
            "a held spend must not be absorbed as a receive"
        );
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
            0,
            Some(zeroize::Zeroizing::new(key)),
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
            0,
            Some(zeroize::Zeroizing::new(key)),
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
            0,
            Some(zeroize::Zeroizing::new(key)),
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
    fn partial_rollback_of_any_sealed_blob_is_rejected_on_open() {
        let (dir, secret, key) = sealed_fixture();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        let paths = [
            meta::mweb_coins_enc_path(dir.path()),
            meta::mweb_sync_enc_path(dir.path()),
            meta::mweb_index_enc_path(dir.path()),
            meta::mweb_history_enc_path(dir.path()),
        ];
        let v1_blobs: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();

        // Advance to counter 2 and counter 3.
        for _ in 0..2 {
            let mut rt = MwebRuntime::open(
                dir.path(),
                &secret,
                WalletNetwork::Testnet,
                scheme,
                0,
                Some(zeroize::Zeroizing::new(key)),
            )
            .unwrap();
            rt.persist(dir.path()).unwrap();
        }
        assert_eq!(load_seal_counter(dir.path()), 3);
        let v3_blobs: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();

        // Rolling back any single blob to counter 1 must fail open, both with
        // mweb_seal_counter.txt intact (3) and if an attacker also rolled back
        // mweb_seal_counter.txt to 1 while leaving the other blobs at 3.
        for (idx, path) in paths.iter().enumerate() {
            save_seal_counter(dir.path(), 3).unwrap();
            std::fs::write(path, &v1_blobs[idx]).unwrap();
            let res = MwebRuntime::open(
                dir.path(),
                &secret,
                WalletNetwork::Testnet,
                scheme,
                0,
                Some(zeroize::Zeroizing::new(key)),
            );
            assert!(
                res.is_err(),
                "rolling back {} below seal counter was accepted",
                path.display()
            );

            // Even if mweb_seal_counter.txt is rolled back to 1 alongside that
            // single blob, a 2-step spread (1 vs 3) across the four blobs must
            // be rejected as a partial rollback rather than a mid-persist crash.
            save_seal_counter(dir.path(), 1).unwrap();
            let res_spread = MwebRuntime::open(
                dir.path(),
                &secret,
                WalletNetwork::Testnet,
                scheme,
                0,
                Some(zeroize::Zeroizing::new(key)),
            );
            assert!(
                res_spread.is_err(),
                "rolling back {} + seal_counter (spread 1 vs 3) was accepted",
                path.display()
            );

            // Restore v3 blob before testing the next one.
            std::fs::write(path, &v3_blobs[idx]).unwrap();
        }
    }

    #[test]
    fn interrupted_persist_before_seal_counter_recovers_and_advances_monotonically() {
        let (dir, secret, key) = sealed_fixture();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        assert_eq!(load_seal_counter(dir.path()), 1);

        // Advance to counter 2, then simulate a kill right before save_seal_counter
        // by restoring mweb_seal_counter.txt to 1 while the blobs carry counter 2.
        let mut rt = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            0,
            Some(zeroize::Zeroizing::new(key)),
        )
        .unwrap();
        rt.receive_index = 11;
        rt.persist(dir.path()).unwrap();
        save_seal_counter(dir.path(), 1).unwrap();

        // Reopen and persist again: must open cleanly and write counter 3 (never
        // reusing counter 2).
        let mut recovered = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            0,
            Some(zeroize::Zeroizing::new(key)),
        )
        .unwrap();
        assert_eq!(recovered.receive_index, 11);
        recovered.persist(dir.path()).unwrap();
        assert_eq!(load_seal_counter(dir.path()), 3);
        for path in [
            meta::mweb_coins_enc_path(dir.path()),
            meta::mweb_sync_enc_path(dir.path()),
            meta::mweb_index_enc_path(dir.path()),
            meta::mweb_history_enc_path(dir.path()),
        ] {
            let blob = std::fs::read(&path).unwrap();
            let counter = u64::from_le_bytes(blob[10..18].try_into().unwrap());
            assert_eq!(counter, 3, "{} did not advance to 3", path.display());
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
        cs.coins
            .insert([1; 32], persistable_coin(1, Some(100), Some(4)));
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
            0,
            Some(zeroize::Zeroizing::new(key)),
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

    #[test]
    fn audit_f6_sealed_mweb_rejects_deleted_enc_downgrade_and_scans_beyond_gap_limit() {
        let (dir, secret, key) = sealed_fixture();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        assert_eq!(load_seal_counter(dir.path()), 1);

        // 1. Deleting sealed v2 blobs and planting unauthenticated plaintext files when
        // seal_counter > 0 must fail open rather than silently wiping coins / accepting
        // an unauthenticated receive_index beyond MWEB_GAP_LIMIT.
        std::fs::remove_file(meta::mweb_coins_enc_path(dir.path())).unwrap();
        std::fs::remove_file(meta::mweb_index_enc_path(dir.path())).unwrap();
        std::fs::write(
            meta::mweb_index_path(dir.path()),
            format!("{}\n", MWEB_GAP_LIMIT + 50),
        )
        .unwrap();

        let downgraded = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            scheme,
            0,
            Some(zeroize::Zeroizing::new(key)),
        );
        assert!(
            downgraded.is_err(),
            "deleting mweb_coins.enc + mweb_receive_index.enc and planting plaintext receive_index succeeded despite seal_counter=1"
        );
    }

    #[test]
    fn audit_f6b_receive_index_at_gap_limit_must_remain_scannable_by_address_book() {
        let dir = tempfile::tempdir().unwrap();
        let secret = crate::seed::MasterSecret::parse(
            &crate::descriptors::generate_mnemonic().unwrap(),
            None,
        )
        .unwrap();
        let scheme = crate::dto::MwebScheme::default().to_master_scheme();
        save_receive_index(dir.path(), MWEB_GAP_LIMIT).unwrap();

        let rt = MwebRuntime::open(dir.path(), &secret, WalletNetwork::Testnet, scheme, 0, None)
            .unwrap();
        assert_eq!(rt.receive_index, MWEB_GAP_LIMIT);

        // Build a peg-in paying our own current `rt.receive_index` (1000) and verify `rt.book` scans it.
        let mut funded = bdk_mweb::fund_mweb_pegin(
            &rt.keys,
            rt.receive_index,
            200_000,
            2_100,
            NetworkKind::Test,
            &rt.secp,
        )
        .unwrap();
        let _ = bdk_mweb::sign_funded_mweb_pegin(&mut funded, &rt.keys, &rt.secp).unwrap();
        let tx = bdk_wallet::bitcoin::Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
            mw_tx: Some(bdk_wallet::bitcoin::blockdata::mimblewimble::Transaction {
                kernel_offset: funded.psbt.mweb_tx_offset.unwrap_or([0u8; 32]),
                stealth_offset: funded.psbt.mweb_stealth_offset.unwrap_or([0u8; 32]),
                body: bdk_wallet::bitcoin::blockdata::mimblewimble::TxBody {
                    inputs: Vec::new(),
                    outputs: vec![funded.staged_outputs[0].output.clone()],
                    kernels: Vec::new(),
                },
            }),
            is_hog_ex: false,
        };
        let mut scan_db = MwebCoinDatabase::default();
        let found =
            bdk_mweb::scan_litecoin_tx(&rt.keys, &rt.book, &tx, &mut scan_db, &rt.secp).unwrap();
        assert_eq!(
            found.len(),
            1,
            "MwebRuntime::open capped AddressBook at MWEB_GAP_LIMIT ({MWEB_GAP_LIMIT}) despite receive_index={}; payments to receive_address() are invisible to sync",
            rt.receive_index
        );
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
        crate::broadcast_peers::path(data_dir),
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

struct OpenedSealed {
    plain: zeroize::Zeroizing<Vec<u8>>,
    counter: Option<u64>,
}

/// Open a sealed file; `Ok(None)` when the file does not exist.
///
/// Reads both envelope versions. A v2 blob must carry `context` and a counter
/// at least `min_counter`; a legacy blob predates the tag and is accepted only
/// when `min_counter == 0` (before the first v2 persist). The next `persist`
/// rewrites it as v2.
fn read_sealed(
    path: &Path,
    key: &[u8; 32],
    context: SealContext,
    min_counter: u64,
) -> Result<Option<OpenedSealed>, WalletError> {
    match fs::read(path) {
        Ok(blob) => open_sealed_blob(&blob, key, context, min_counter)
            .map(|(pt, counter)| OpenedSealed {
                plain: zeroize::Zeroizing::new(pt),
                counter,
            })
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
    min_counter: u64,
) -> Result<(Vec<u8>, Option<u64>), bdk_mweb::Error> {
    if bdk_mweb::is_v2(blob) {
        bdk_mweb::open_with_context_at_least(key, blob, context, min_counter)
            .map(|(pt, counter)| (pt, Some(counter)))
    } else if min_counter > 0 {
        Err(bdk_mweb::Error::Crypto(
            "legacy v1 sealed blob rejected after v2 upgrade".into(),
        ))
    } else {
        bdk_mweb::open(key, blob).map(|pt| (pt, None))
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
    crate::fs_atomic::write_atomic(
        &meta::mweb_seal_counter_path(data_dir),
        format!("{counter}\n").as_bytes(),
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
    min_counter: u64,
) -> Result<(MwebStore, ChangeSet, Option<u64>), WalletError> {
    if let Some(key) = sealing_key {
        let path = meta::mweb_coins_enc_path(data_dir);
        if path.is_file() {
            let blob = fs::read(&path)?;
            let (cs, counter) = if bdk_mweb::is_v2(&blob) {
                bdk_mweb::open_changeset_with_context(key, &blob, SealContext::Coins, min_counter)
                    .map(|(cs, counter)| (cs, Some(counter)))
            } else if min_counter > 0 {
                Err(bdk_mweb::Error::Crypto(
                    "legacy v1 sealed store rejected after v2 upgrade".into(),
                ))
            } else {
                bdk_mweb::open_changeset(key, &blob).map(|cs| (cs, None))
            }
            .map_err(|e| WalletError::Mweb(format!("sealed MWEB store: {e}")))?;
            return Ok((MwebStore::from_changeset(cs.clone()), cs, counter));
        }
    }
    let path = meta::mweb_db_path(data_dir);
    if !path.is_file() {
        return Ok((MwebStore::new(), ChangeSet::default(), None));
    }
    let mut conn = Connection::open(&path).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let tx = conn
        .transaction()
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    ChangeSet::init_sqlite_tables(&tx).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let cs = ChangeSet::from_sqlite(&tx).map_err(|e| WalletError::Mweb(e.to_string()))?;
    tx.commit().map_err(|e| WalletError::Mweb(e.to_string()))?;
    Ok((MwebStore::from_changeset(cs.clone()), cs, None))
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
    min_counter: u64,
) -> Result<(SyncState, Option<u64>), WalletError> {
    if let Some(key) = sealing_key {
        if let Some(opened) = read_sealed(
            &meta::mweb_sync_enc_path(data_dir),
            key,
            SealContext::SyncState,
            min_counter,
        )? {
            let state = serde_json::from_slice(&opened.plain)
                .map_err(|e| WalletError::Mweb(e.to_string()))?;
            return Ok((state, opened.counter));
        }
    }
    let path = meta::mweb_sync_path(data_dir);
    match fs::read_to_string(&path) {
        Ok(s) => {
            let state = serde_json::from_str(&s).map_err(|e| WalletError::Mweb(e.to_string()))?;
            Ok((state, None))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((SyncState::default(), None)),
        Err(e) => Err(WalletError::Io(e)),
    }
}

fn save_sync_state(data_dir: &Path, state: &SyncState) -> Result<(), WalletError> {
    let json = serde_json::to_string_pretty(state).map_err(|e| WalletError::Mweb(e.to_string()))?;
    crate::fs_atomic::write_atomic(&meta::mweb_sync_path(data_dir), json.as_bytes())?;
    Ok(())
}

fn load_receive_index(
    data_dir: &Path,
    sealing_key: Option<&[u8; 32]>,
    min_counter: u64,
) -> Result<(u32, Option<u64>), WalletError> {
    if let Some(key) = sealing_key {
        if let Some(opened) = read_sealed(
            &meta::mweb_index_enc_path(data_dir),
            key,
            SealContext::Index,
            min_counter,
        )? {
            let s = String::from_utf8_lossy(&opened.plain);
            return Ok((s.trim().parse().unwrap_or(0), opened.counter));
        }
    }
    let path = meta::mweb_index_path(data_dir);
    match fs::read_to_string(&path) {
        Ok(s) => Ok((s.trim().parse().unwrap_or(0), None)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((0, None)),
        Err(e) => Err(WalletError::Io(e)),
    }
}

fn save_receive_index(data_dir: &Path, index: u32) -> Result<(), WalletError> {
    crate::fs_atomic::write_atomic(
        &meta::mweb_index_path(data_dir),
        format!("{index}\n").as_bytes(),
    )?;
    Ok(())
}

fn load_history(
    data_dir: &Path,
    sealing_key: Option<&[u8; 32]>,
    min_counter: u64,
) -> Result<(MwebHistory, Option<u64>), WalletError> {
    if let Some(key) = sealing_key {
        if let Some(opened) = read_sealed(
            &meta::mweb_history_enc_path(data_dir),
            key,
            SealContext::History,
            min_counter,
        )? {
            let history = serde_json::from_slice(&opened.plain)
                .map_err(|e| WalletError::Mweb(e.to_string()))?;
            return Ok((history, opened.counter));
        }
    }
    Ok((MwebHistory::load(&meta::mweb_history_path(data_dir))?, None))
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

/// Prepare a hybrid peg-in PSBT with [`crate::tx_invariants::LitecoinDustCoinSelection`]
/// and `unspendable` holds, without touching BDK's `lock_outpoint`.
#[allow(clippy::too_many_arguments)]
pub fn prepare_pegin(
    wallet: &mut PersistedWallet<Connection>,
    keys: &MasterKeys,
    receive_index: u32,
    pegin_amount_sats: u64,
    mweb_fee_sats: u64,
    transparent_fee_sats: u64,
    selected_outpoints: &[bdk_wallet::bitcoin::OutPoint],
    unspendable_outpoints: Vec<bdk_wallet::bitcoin::OutPoint>,
    network: WalletNetwork,
    secp: &Secp256k1<All>,
) -> Result<bdk_wallet::PreparedMwebPegin, WalletError> {
    crate::tx_invariants::check_money(pegin_amount_sats, "peg-in amount")?;
    crate::tx_invariants::check_money(mweb_fee_sats, "peg-in MWEB fee")?;
    crate::tx_invariants::check_money(transparent_fee_sats, "peg-in transparent fee")?;
    if pegin_amount_sats <= mweb_fee_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-in amount {pegin_amount_sats} litoshis must exceed the MWEB fee ({mweb_fee_sats} litoshis) so a private coin remains"
        )));
    }
    if pegin_amount_sats < crate::tx_invariants::PEGIN_V9_DUST_SATS {
        return Err(WalletError::BuildTx(format!(
            "peg-in amount {pegin_amount_sats} litoshis is below the {} litoshis dust limit",
            crate::tx_invariants::PEGIN_V9_DUST_SATS
        )));
    }
    let kind = match network {
        WalletNetwork::Mainnet => NetworkKind::Main,
        WalletNetwork::Testnet => NetworkKind::Test,
    };
    let mut funded = bdk_mweb::fund_mweb_pegin(
        keys,
        receive_index,
        pegin_amount_sats,
        mweb_fee_sats,
        kind,
        secp,
    )
    .map_err(|e| WalletError::Mweb(e.to_string()))?;
    let kernel_id = bdk_mweb::sign_funded_mweb_pegin(&mut funded, keys, secp)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;

    let mut builder = wallet
        .build_tx()
        .coin_selection(crate::tx_invariants::LitecoinDustCoinSelection);
    if !selected_outpoints.is_empty() {
        builder
            .add_utxos(selected_outpoints)
            .map_err(|e| WalletError::BuildTx(e.to_string()))?;
        builder.manually_selected_only();
    }
    builder.unspendable(unspendable_outpoints);
    builder.add_mweb_pegin(kernel_id, Amount::from_sat(pegin_amount_sats));
    builder.fee_absolute(Amount::from_sat(transparent_fee_sats));
    let mut psbt = builder
        .finish()
        .map_err(|e| WalletError::BuildTx(e.to_string()))?;

    psbt.mweb_tx_offset = funded.psbt.mweb_tx_offset;
    psbt.mweb_stealth_offset = funded.psbt.mweb_stealth_offset;
    psbt.mweb_kernels = funded.psbt.mweb_kernels;
    psbt.mweb_inputs = funded.psbt.mweb_inputs;
    psbt.mweb_outputs = funded.psbt.mweb_outputs;

    Ok(bdk_wallet::PreparedMwebPegin {
        psbt,
        kernel_id,
        pegin_amount: Amount::from_sat(pegin_amount_sats),
        outputs: funded.outputs,
    })
}

pub fn pegin(
    wallet: &mut PersistedWallet<Connection>,
    signer: &ZeroizingSigner,
    runtime: &mut MwebRuntime,
    route: &BroadcastRoute,
    req: PeginRequest,
) -> Result<PeginResult, WalletError> {
    let selected =
        crate::tx_invariants::parse_and_dedup_outpoints(req.selected_outpoints.as_deref())?
            .unwrap_or_default();
    let held: Vec<bdk_wallet::bitcoin::OutPoint> =
        mweb_frozen::public_reserved_outpoints(&route.data_dir)?
            .into_iter()
            .collect();

    let mut prepared = prepare_pegin(
        wallet,
        &runtime.keys,
        runtime.receive_index,
        req.amount_sats,
        req.mweb_fee_sats,
        req.transparent_fee_sats,
        &selected,
        held,
        route.network,
        &runtime.secp,
    )?;
    // MWEB components were signed inside prepare_pegin; the transparent inputs are
    // signed here with the caller-owned keys.
    sign_and_finalize(wallet, signer, &mut prepared.psbt)
        .map_err(|e| WalletError::Sign(format!("peg-in: {e}")))?;
    let tx = extract_prepared_mweb_pegin(&prepared.psbt)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    crate::tx_invariants::verify_pegin_tx(
        &prepared.psbt,
        &tx,
        &prepared.kernel_id,
        req.amount_sats,
        req.mweb_fee_sats,
        req.transparent_fee_sats,
        &prepared.outputs,
        &runtime.secp,
    )?;
    // A peg-in tx carries MWEB extension data that Electrum servers reject
    // ("TX decode failed"), so it must take the RPC/P2P path like other MWEB txs.
    broadcast_mweb_tx(&tx, route)?;
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
    let fee_sats = crate::tx_invariants::checked_add_money(
        req.transparent_fee_sats,
        req.mweb_fee_sats,
        "peg-in fee",
    )?;
    let total_out = crate::tx_invariants::checked_add_money(
        req.amount_sats,
        fee_sats,
        "peg-in transparent spend",
    )?;
    let net_sats = crate::tx_invariants::neg_net_sats(total_out)?;
    // Net matches the transparent spend: peg-in amount + both fees. Deduped
    // against the BDK history row by txid once the graph has the tx.
    if !runtime.history.entries.iter().any(|e| e.id == txid) {
        runtime.history.record(MwebHistoryEntry {
            id: txid.clone(),
            kind: TxKind::Pegin,
            net_sats,
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
/// RPC is the fallback when no peer accepts it, unless the user opted in to
/// [`BroadcastRoute::via_own_node`], which puts RPC first.
pub(crate) fn broadcast_mweb_tx(
    tx: &bdk_wallet::bitcoin::Transaction,
    route: &BroadcastRoute,
) -> Result<(), WalletError> {
    let rpc_first = route.rpc_first();
    let mut own_node_err = None;
    if let Some(url) = rpc_first {
        match rpc::send_raw_transaction(url, &serialize_hex(tx)) {
            Ok(_) => {
                crate::diag::log("MWEB broadcast: sent through your own node (Settings opt-in)");
                return Ok(());
            }
            Err(e) => {
                crate::diag::log(format!(
                    "MWEB broadcast: your own node refused it ({e}); trying peers"
                ));
                own_node_err = Some(e.to_string());
            }
        }
    }

    let configured = resolve_reachable_peers(&route.peers)?;
    let remembered: Vec<std::net::SocketAddr> = crate::broadcast_peers::load(&route.data_dir)
        .into_iter()
        .filter(|addr| !configured.contains(addr))
        .collect();
    let reachable = probe_reachable(remembered.clone());
    let first_pass = first_pass_peers(&configured, &reachable);

    let bdk_net = route.network.to_bitcoin_network();
    let policy = PeerPolicy::fast_failover();
    let started = std::time::Instant::now();
    let mut run = run_p2p(
        &first_pass,
        || crate::discovery::discover_mweb_peers(route.network),
        |addr| match TcpMwebPeer::connect_with_policy(addr, bdk_net, policy) {
            Ok(mut peer) => peer
                .broadcast_tx(tx)
                .map_err(|e| crate::error::humanize_broadcast_error(&e.to_string())),
            Err(e) => Err(e.to_string()),
        },
        || started.elapsed(),
    );
    run.failed
        .extend(remembered.iter().filter(|addr| !reachable.contains(addr)));
    crate::discovery::evict_peers(&run.failed);
    if let Some(confirmed) = run.confirmed {
        crate::discovery::note_good_peer(confirmed);
    } else if !run.sent.is_empty() {
        crate::discovery::demote_peers(&run.sent);
    }
    if let Err(e) = crate::broadcast_peers::record(
        &route.data_dir,
        &crate::broadcast_peers::Outcome {
            confirmed: run.confirmed,
            failed: &run.failed,
            configured: &configured,
        },
    ) {
        crate::diag::log(format!("MWEB broadcast: could not save good peers ({e})"));
    }

    if run.confirmed.is_some() {
        return Ok(());
    }
    if let Some(addr) = run.sent.first() {
        crate::diag::log(format!(
            "MWEB broadcast: no peer confirmed acceptance; keeping optimistic send via {addr}"
        ));
        return Ok(());
    }
    let p2p_err = run.error();
    if let Some(rpc_err) = own_node_err {
        return Err(WalletError::Mweb(format!(
            "could not broadcast through your own node ({rpc_err}) or over P2P ({p2p_err})"
        )));
    }
    let Some(url) = route.rpc_url.as_deref() else {
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

/// Where a transaction that carries MWEB data may be broadcast.
#[derive(Clone)]
pub struct BroadcastRoute {
    pub data_dir: std::path::PathBuf,
    pub rpc_url: Option<String>,
    pub peers: Vec<String>,
    pub network: WalletNetwork,
    /// The user opted in to sending through their own litecoind before any
    /// peer, which makes their node the visible origin of the transaction.
    pub via_own_node: bool,
}

impl std::fmt::Debug for BroadcastRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BroadcastRoute")
            .field("data_dir", &self.data_dir)
            .field("rpc_url", &crate::redact::redact_opt_url(&self.rpc_url))
            .field("peers", &self.peers)
            .field("network", &self.network)
            .field("via_own_node", &self.via_own_node)
            .finish()
    }
}

impl BroadcastRoute {
    fn rpc_first(&self) -> Option<&str> {
        if !self.via_own_node {
            return None;
        }
        self.rpc_url.as_deref().filter(|url| !url.trim().is_empty())
    }
}

/// Stop the peer search after this many unconfirmed `Sent` answers.
const BROADCAST_MAX_SENT: usize = 2;
/// Once some peer has answered `Sent`, stop starting new peers after this long.
/// Without any `Sent` the search keeps going, since there is nothing to fall
/// back on yet.
const BROADCAST_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a P2P broadcast learned from the peers it tried.
#[derive(Debug, Default)]
struct PeerRun {
    confirmed: Option<std::net::SocketAddr>,
    sent: Vec<std::net::SocketAddr>,
    failed: Vec<std::net::SocketAddr>,
    tried: Vec<std::net::SocketAddr>,
    last_err: Option<String>,
}

impl PeerRun {
    fn done(&self, elapsed: std::time::Duration) -> bool {
        self.confirmed.is_some()
            || self.sent.len() >= BROADCAST_MAX_SENT
            || (!self.sent.is_empty() && elapsed >= BROADCAST_MAX_WAIT)
    }

    fn error(&self) -> String {
        match &self.last_err {
            Some(e) => format!("P2P broadcast failed: {e}"),
            None => "no MWEB P2P peers reachable".into(),
        }
    }
}

/// The user's peers first, then public peers that confirmed a recent broadcast.
fn first_pass_peers(
    configured: &[std::net::SocketAddr],
    remembered: &[std::net::SocketAddr],
) -> Vec<std::net::SocketAddr> {
    let mut out = configured.to_vec();
    for addr in remembered {
        if !out.contains(addr) {
            out.push(*addr);
        }
    }
    out
}

/// Offer the tx to `first_pass`, then to discovered peers if no peer in the
/// first pass took it. One budget covers both passes.
///
/// [`BroadcastAck::Sent`] is optimistic (the peer may not have relayed), so a
/// `Sent` keeps the search going for a Confirmed ack until [`PeerRun::done`].
fn run_p2p(
    first_pass: &[std::net::SocketAddr],
    discover: impl FnOnce() -> Vec<std::net::SocketAddr>,
    mut offer: impl FnMut(std::net::SocketAddr) -> Result<BroadcastAck, String>,
    elapsed: impl Fn() -> std::time::Duration,
) -> PeerRun {
    let mut run = PeerRun::default();
    offer_to_peers(&mut run, first_pass, &mut offer, &elapsed);
    if run.confirmed.is_none() && run.sent.is_empty() {
        // Still prefer a stranger's node over our own RPC: relaying through a
        // peer we did not author the tx on is the whole point of the P2P path.
        let discovered = discover();
        offer_to_peers(&mut run, &discovered, &mut offer, &elapsed);
    }
    run
}

fn offer_to_peers(
    run: &mut PeerRun,
    addrs: &[std::net::SocketAddr],
    offer: &mut impl FnMut(std::net::SocketAddr) -> Result<BroadcastAck, String>,
    elapsed: &impl Fn() -> std::time::Duration,
) {
    for &addr in addrs {
        if run.done(elapsed()) {
            return;
        }
        if run.tried.contains(&addr) {
            continue;
        }
        run.tried.push(addr);
        match offer(addr) {
            Ok(BroadcastAck::Confirmed) => {
                crate::diag::log(format!("MWEB broadcast: {addr} accepted the transaction"));
                run.confirmed = Some(addr);
            }
            Ok(BroadcastAck::Sent) => {
                run.sent.push(addr);
                let left = BROADCAST_MAX_WAIT.saturating_sub(elapsed()).as_secs();
                crate::diag::log(format!(
                    "MWEB broadcast: sent to {addr}; acceptance not confirmed before deadline \
                     ({}/{BROADCAST_MAX_SENT} unconfirmed, {left}s left to find a confirming peer)",
                    run.sent.len()
                ));
            }
            Err(e) => {
                run.failed.push(addr);
                run.last_err = Some(format!("{addr}: {e}"));
            }
        }
    }
}

/// Signed private send, not yet broadcast and not yet applied to the coin set.
///
/// The caller broadcasts outside the wallet lock, then [`apply_signed_mweb_send`].
pub struct SignedMwebSend {
    pub tx: Transaction,
    pub wtxid: String,
    pub fee_sats: u64,
    pub amount_sats: u64,
    spent_ids: Vec<[u8; 32]>,
    change: Option<bdk_mweb::MwebCoin>,
}

impl SignedMwebSend {
    /// Output ids this send spends. Freeze them until broadcast finishes.
    pub fn input_ids(&self) -> Vec<String> {
        self.spent_ids.iter().map(hex::encode).collect()
    }

    pub fn result(&self) -> MwebBroadcastResult {
        MwebBroadcastResult {
            wtxid: self.wtxid.clone(),
            fee_sats: self.fee_sats,
            addresses: Vec::new(),
        }
    }
}

/// Build and sign a private send. Does not broadcast or mark coins spent.
pub fn sign_mweb_send(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    req: &MwebSendRequest,
    network: WalletNetwork,
) -> Result<SignedMwebSend, WalletError> {
    let dest = crate::tx_invariants::validate_mweb_recipient(&req.address, network)?;
    if req.amount_sats == 0 {
        return Err(WalletError::BuildTx(
            "private send amount must be greater than zero".into(),
        ));
    }
    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(data_dir)?;
    let selected = normalize_selected_ids(req.selected_output_ids.as_deref());
    let needed = crate::tx_invariants::checked_add_money(
        req.amount_sats,
        req.fee_sats,
        "private send total",
    )?;
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
    crate::tx_invariants::verify_mweb_spend_tx(
        &tx,
        &funded.spent_coins,
        &[req.amount_sats],
        &[],
        req.fee_sats,
        change.as_slice(),
        &runtime.secp,
    )?;
    Ok(SignedMwebSend {
        wtxid: tx.compute_wtxid().to_string(),
        tx,
        fee_sats: req.fee_sats,
        amount_sats: req.amount_sats,
        spent_ids,
        change,
    })
}

/// Mark the spent coins, remember change, and record history. Does not broadcast.
pub fn apply_signed_mweb_send(
    runtime: &mut MwebRuntime,
    signed: &SignedMwebSend,
) -> MwebBroadcastResult {
    for id in &signed.spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::new();
    if let Some(mut change) = signed.change.clone() {
        change.block_height = None;
        output_ids.push(hex::encode(change.output_id));
        runtime.store.db_mut().insert(change);
    }
    let net_sats =
        crate::tx_invariants::neg_net_sats(signed.amount_sats.saturating_add(signed.fee_sats))
            .unwrap_or(i64::MIN);
    runtime.history.record(MwebHistoryEntry {
        id: signed.wtxid.clone(),
        kind: TxKind::MwebSend,
        net_sats,
        fee_sats: Some(signed.fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: signed.input_ids(),
        confirmed_height: None,
    });
    signed.result()
}

/// List unspent MWEB coins (including immature / unconfirmed) for the Coins screen.
pub fn list_mweb_unspent(
    runtime: &MwebRuntime,
    tip_height: u32,
    data_dir: &Path,
) -> Vec<MwebUtxoRecord> {
    let mweb_frozen::MwebFrozenFile {
        ids: frozen,
        reserved,
        ..
    } = mweb_frozen::read_ids(data_dir).unwrap_or_default();
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
            let (status, actions) = coin_status(&CoinFacts {
                confirmations,
                mature,
                maturity_blocks_left,
                locked,
                reserved: reserved.contains_key(&output_id),
                from_pegin: fields.from_pegin,
                non_solo_blocks: fields.non_solo_blocks,
                churn_phase: fields.churn_phase,
            });
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
                churn_fee_sats: fields.churn_fee_sats,
                churn_cover_hold: fields.churn_cover_hold,
                churn_cover_min: fields.churn_cover_min,
                churn_cover_seen: fields.churn_cover_seen,
                churn_cover_checked_at: fields.churn_cover_checked_at,
                churn_cover_total: fields.churn_cover_total,
                churn_cover_kernels: fields.churn_cover_kernels,
                churn_cover_outputs: fields.churn_cover_outputs,
                churn_cover_error: fields.churn_cover_error,
                churn_spreading: fields.churn_spreading,
                churn_actions: fields.churn_actions,
                status,
                actions,
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

/// What [`coin_status`] reads about one coin.
#[derive(Debug)]
pub(crate) struct CoinFacts {
    pub confirmations: u32,
    pub mature: bool,
    pub maturity_blocks_left: u32,
    pub locked: bool,
    /// A spend in flight holds the coin (`mweb_frozen` `reserved`).
    pub reserved: bool,
    pub from_pegin: bool,
    pub non_solo_blocks: Option<u32>,
    pub churn_phase: Option<ChurnPhase>,
}

/// The only place a private coin's status and buttons are decided.
///
/// Status is the first match of: churning, sending, pending, maturing, frozen, tied to peg-in,
/// ready. The blocked reason is the first match of: churning, sending, frozen, unconfirmed,
/// maturing.
pub(crate) fn coin_status(f: &CoinFacts) -> (CoinStatus, CoinActions) {
    let churning = f.churn_phase.is_some_and(ChurnPhase::is_active);
    let status = if churning {
        CoinStatus::Churning
    } else if f.reserved {
        CoinStatus::Sending
    } else if !f.mature && f.confirmations == 0 {
        CoinStatus::Pending
    } else if !f.mature {
        CoinStatus::Maturing
    } else if f.locked {
        CoinStatus::Frozen
    } else if f.from_pegin && f.non_solo_blocks == Some(0) {
        CoinStatus::TiedToPegin
    } else {
        CoinStatus::Ready
    };
    let blocked = if churning {
        Some(CoinBlock::Churning)
    } else if f.reserved {
        Some(CoinBlock::Sending)
    } else if f.locked {
        Some(CoinBlock::Frozen)
    } else if !f.mature && f.confirmations == 0 {
        Some(CoinBlock::Unconfirmed)
    } else if !f.mature {
        Some(CoinBlock::Maturing {
            blocks_left: f.maturity_blocks_left,
        })
    } else {
        None
    };
    let spendable = blocked.is_none();
    let actions = CoinActions {
        spend_to_self: spendable,
        split: spendable,
        transfer: spendable,
        select: spendable,
        freeze: spendable,
        unfreeze: !churning && !f.reserved && f.locked,
        blocked,
    };
    (status, actions)
}

/// What [`public_coin_status`] reads about one public coin.
#[derive(Debug)]
pub(crate) struct PublicCoinFacts {
    pub confirmations: u32,
    pub mature: bool,
    pub maturity_blocks_left: u32,
    /// Frozen by the user (BDK wallet lock).
    pub locked: bool,
    /// A split or transfer in flight holds the coin (`mweb_frozen` `public_reserved`).
    pub reserved: bool,
}

/// The only place a public coin's status and buttons are decided.
///
/// Status is the first match of: sending, pending, maturing, frozen, ready. The blocked reason
/// is the first match of: sending, frozen, unconfirmed, maturing. An ordinary unconfirmed coin
/// may still be picked for a send; split and transfer wait for a confirmation, and a HogEx
/// peg-out or coinbase coin waits for maturity.
pub(crate) fn public_coin_status(f: &PublicCoinFacts) -> (CoinStatus, CoinActions) {
    let status = if f.reserved {
        CoinStatus::Sending
    } else if f.confirmations == 0 {
        CoinStatus::Pending
    } else if !f.mature {
        CoinStatus::Maturing
    } else if f.locked {
        CoinStatus::Frozen
    } else {
        CoinStatus::Ready
    };
    let blocked = if f.reserved {
        Some(CoinBlock::Sending)
    } else if f.locked {
        Some(CoinBlock::Frozen)
    } else if f.confirmations == 0 {
        Some(CoinBlock::Unconfirmed)
    } else if !f.mature {
        Some(CoinBlock::Maturing {
            blocks_left: f.maturity_blocks_left,
        })
    } else {
        None
    };
    let free = !f.reserved && !f.locked && f.mature;
    let spendable = blocked.is_none();
    let actions = CoinActions {
        spend_to_self: false,
        split: spendable,
        transfer: spendable,
        select: free,
        freeze: free,
        unfreeze: !f.reserved && f.locked,
        blocked,
    };
    (status, actions)
}

/// The sentence a freeze command shows when [`CoinActions`] blocks that request.
///
/// Churning and sending reuse the sentences the older checks already return.
pub(crate) fn coin_block_message(block: CoinBlock) -> String {
    match block {
        CoinBlock::Churning => "A self-spend has this coin.".into(),
        CoinBlock::Sending => mweb_frozen::RESERVED_MESSAGE.into(),
        CoinBlock::Frozen => "This coin is frozen.".into(),
        CoinBlock::Unconfirmed => "This coin is not confirmed yet.".into(),
        CoinBlock::Maturing { blocks_left } => {
            format!("This coin is still maturing ({blocks_left} blocks left).")
        }
    }
}

/// Blocks left before a peg-in's private coin is spendable, or `None` once it is.
pub(crate) fn pegin_blocks_left(kind: TxKind, confirmations: u32) -> Option<u32> {
    let left = MWEB_PEGIN_MATURITY.saturating_sub(confirmations);
    (kind == TxKind::Pegin && left > 0).then_some(left)
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
    churn_fee_sats: Option<u64>,
    churn_cover_hold: Option<crate::dto::CoverHold>,
    churn_cover_min: Option<u32>,
    churn_cover_seen: Option<u64>,
    churn_cover_checked_at: Option<u64>,
    churn_cover_total: Option<u64>,
    churn_cover_kernels: Option<u64>,
    churn_cover_outputs: Option<u64>,
    churn_cover_error: Option<String>,
    churn_spreading: Option<bool>,
    churn_actions: Option<crate::dto::ChurnActions>,
}

/// The part of a job that belongs on the coin it currently holds.
#[derive(Default)]
struct LiveJobFields {
    phase: Option<crate::dto::ChurnPhase>,
    error: Option<String>,
    target: Option<u32>,
    counted: Option<u32>,
    fee: Option<u64>,
    cover_hold: Option<crate::dto::CoverHold>,
    cover_min: Option<u32>,
    cover_seen: Option<u64>,
    cover_checked_at: Option<u64>,
    cover_total: Option<u64>,
    cover_kernels: Option<u64>,
    cover_outputs: Option<u64>,
    cover_error: Option<String>,
    spreading: Option<bool>,
    actions: Option<crate::dto::ChurnActions>,
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
    let live = match job {
        Some(job) if job.current_output_id == output_id && job.phase().is_active() => {
            LiveJobFields {
                phase: Some(job.phase()),
                error: job.last_error.clone(),
                target: Some(job.target_depth),
                counted: Some(job.effective_depth),
                fee: Some(job.fee_sats),
                cover_hold: job.cover_hold,
                cover_min: Some(job.cover_min),
                cover_seen: job.last_cover_count,
                cover_checked_at: job.last_cover_check_unix,
                cover_total: job.last_cover_total,
                cover_kernels: job.last_cover_kernels,
                cover_outputs: job.last_cover_outputs,
                cover_error: job.last_cover_error.clone(),
                spreading: Some(job.spreading),
                actions: Some(crate::churn::allowed_actions(job)),
            }
        }
        Some(job)
            if job.current_output_id == output_id
                && job.phase() == crate::dto::ChurnPhase::Done =>
        {
            LiveJobFields {
                target: Some(job.target_depth),
                counted: Some(job.effective_depth),
                ..LiveJobFields::default()
            }
        }
        _ => LiveJobFields::default(),
    };
    ChurnFields {
        from_pegin,
        non_solo_blocks,
        last_other_kernels: record.and_then(|r| r.last_other_kernels),
        last_other_outputs: record.and_then(|r| r.last_other_outputs),
        hops: record.map(|r| r.hops.clone()).unwrap_or_default(),
        churn_phase: live.phase,
        churn_error: live.error,
        churn_target: live.target,
        churn_counted: live.counted,
        churn_fee_sats: live.fee,
        churn_cover_hold: live.cover_hold,
        churn_cover_min: live.cover_min,
        churn_cover_seen: live.cover_seen,
        churn_cover_checked_at: live.cover_checked_at,
        churn_cover_total: live.cover_total,
        churn_cover_kernels: live.cover_kernels,
        churn_cover_outputs: live.cover_outputs,
        churn_cover_error: live.cover_error,
        churn_spreading: live.spreading,
        churn_actions: live.actions,
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
        let _ = db.restore_spent(&id);
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
        if configured.contains(&first) || crate::discovery::should_prefer_peer(&first) {
            configured.retain(|addr| *addr != first);
            configured.insert(0, first);
        }
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
    let policy = peer_policy_for_pool(addrs.len().max(2));
    for addr in addrs {
        if out.iter().all(|slot| slot.is_some()) {
            break;
        }
        let Ok(mut peer) = TcpMwebPeer::connect_with_policy(*addr, bdk_net, policy) else {
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
        let policy = peer_policy_for_pool(self.addrs.len().max(2));
        while self.peer_at < self.addrs.len() {
            if self.peer.is_none() {
                match TcpMwebPeer::connect_with_policy(self.addrs[self.peer_at], bdk_net, policy) {
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
    let policy = peer_policy_for_pool(addrs.len().max(2));
    for addr in addrs {
        let Ok(mut peer) = TcpMwebPeer::connect_with_policy(*addr, bdk_net, policy) else {
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
            "selected private coin is frozen or a send is still using it — unfreeze it or wait before {action}"
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

/// Signed private split, not yet broadcast and not yet applied to the coin set.
///
/// The receive index is already persisted. The caller broadcasts outside the
/// wallet lock, then [`apply_signed_mweb_split`].
pub struct SignedMwebSplit {
    pub tx: Transaction,
    pub wtxid: String,
    pub fee_sats: u64,
    pub output_count: u32,
    /// Output id of the coin this split spends. Frozen while the broadcast runs.
    pub input_id: String,
    spent_ids: Vec<[u8; 32]>,
    outputs: Vec<bdk_mweb::MwebCoin>,
}

impl SignedMwebSplit {
    pub fn result(&self) -> SplitResult {
        SplitResult {
            txid: self.wtxid.clone(),
            fee_sats: self.fee_sats,
            output_count: self.output_count,
        }
    }
}

/// 1-in-N-out MWEB self-split. Persists `receive_index` after building & signing, before broadcast.
pub fn sign_mweb_split(
    wallet: &PersistedWallet<Connection>,
    runtime: &mut MwebRuntime,
    data_dir: &Path,
    output_id_hex: &str,
    recipient_amounts: &[u64],
    fee_sats: u64,
    network: WalletNetwork,
) -> Result<SignedMwebSplit, WalletError> {
    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(data_dir)?;
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
    let mut outputs = Vec::with_capacity(funded.staged_outputs.len());
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
        outputs.push(owned);
    }
    crate::tx_invariants::verify_mweb_spend_tx(
        &tx,
        &funded.spent_coins,
        recipient_amounts,
        &[],
        fee_sats,
        &outputs,
        &runtime.secp,
    )?;

    // Advance and persist receive_index only after building & signing succeed,
    // still before returning to the caller for broadcast.
    runtime.receive_index = start.saturating_add(recipient_amounts.len() as u32);
    if let Err(e) = runtime.persist(data_dir) {
        runtime.receive_index = start;
        return Err(e);
    }

    let wtxid = tx.compute_wtxid().to_string();
    Ok(SignedMwebSplit {
        tx,
        wtxid,
        fee_sats,
        output_count: recipient_amounts.len() as u32,
        input_id: hex::encode(spent_ids[0]),
        spent_ids,
        outputs,
    })
}

/// Mark the spent coin and remember the new outputs. Does not broadcast.
pub fn apply_signed_mweb_split(runtime: &mut MwebRuntime, signed: &SignedMwebSplit) {
    for id in &signed.spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::with_capacity(signed.outputs.len());
    for coin in &signed.outputs {
        output_ids.push(hex::encode(coin.output_id));
        runtime.store.db_mut().insert(coin.clone());
    }
    runtime.history.record(MwebHistoryEntry {
        id: signed.wtxid.clone(),
        kind: TxKind::MwebSplit,
        net_sats: crate::tx_invariants::neg_net_sats(signed.fee_sats).unwrap_or(i64::MIN),
        fee_sats: Some(signed.fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: signed.spent_ids.iter().map(hex::encode).collect(),
        confirmed_height: None,
    });
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

impl std::fmt::Debug for PreparedHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedHop")
            .field("raw_hex", &"<redacted>")
            .field("txid", &self.txid)
            .field("wtxid", &self.wtxid)
            .field("spent_output_id", &self.spent_output_id)
            .field("created_output_id", &self.created_output_id)
            .field("receive_index", &self.receive_index)
            .field("fee_sats", &self.fee_sats)
            .field("created", &self.created)
            .finish()
    }
}

/// Sign `hops` dependent self-spends. The receive index advances and is persisted
/// once all hops build and sign, before the function returns.
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
        crate::tx_invariants::verify_mweb_spend_tx(
            &tx,
            &funded.spent_coins,
            &[amount],
            &[],
            fee_sats,
            std::slice::from_ref(&owned),
            &runtime.secp,
        )?;
        let created_output_id = hex::encode(owned.output_id);
        prepared.push(PreparedHop {
            raw_hex: serialize_hex(&tx),
            txid: mempool_id(&tx),
            wtxid: tx.compute_wtxid().to_string(),
            spent_output_id,
            created_output_id,
            receive_index: index,
            fee_sats,
            created: owned.clone(),
        });
        coin = owned;
    }

    runtime.receive_index = start.saturating_add(hops);
    if let Err(e) = runtime.persist(data_dir) {
        runtime.receive_index = start;
        return Err(e);
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
    let net_sats = crate::tx_invariants::neg_net_sats(fee_sats)?;
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
            net_sats,
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
pub fn broadcast_prepared_raw(raw_hex: &str, route: &BroadcastRoute) -> Result<(), WalletError> {
    let bytes = hex::decode(raw_hex).map_err(|e| WalletError::Mweb(e.to_string()))?;
    let tx: Transaction = deserialize(&bytes).map_err(|e| WalletError::Mweb(e.to_string()))?;
    broadcast_mweb_tx(&tx, route)
}

/// One successful read of the node mempool for the cover gate.
///
/// `foreign_txs` is the number the gate compares against the user's count.
/// `kernels` and `outputs` are summed over those foreign transactions only, so
/// the card can speak the same language as the post-hop block score.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverRead {
    /// Every transaction id the node listed.
    pub total_txs: u64,
    /// Transactions with an MWEB payload or HogEx flag, ours included.
    pub mweb_txs: u64,
    /// MWEB transactions that are not this wallet's.
    pub foreign_txs: u64,
    /// MWEB kernels across the foreign transactions.
    pub kernels: u64,
    /// MWEB outputs across the foreign transactions.
    pub outputs: u64,
    /// Ids the node listed but could not hand back, or bytes that did not decode.
    pub unreadable_txs: u64,
    pub checked_at_unix: u64,
}

/// What one mempool entry contributes to a [`CoverRead`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverTx {
    /// `getrawtransaction` failed or the bytes did not decode.
    Unreadable,
    /// A plain Litecoin transaction with no MWEB part.
    Plain,
    /// Carries an MWEB payload or is a HogEx. A HogEx has no kernels or outputs.
    Mweb {
        txid: String,
        wtxid: String,
        kernels: u64,
        outputs: u64,
    },
}

/// Classify one decoded transaction for the cover tally.
///
/// A pure MWEB transaction (no transparent inputs or outputs) is identified
/// by its first kernel id. `compute_txid` ignores `mw_tx`, so every such
/// transaction shares one empty-skeleton txid and cannot be told apart by it.
pub fn cover_tx_from(tx: &Transaction) -> CoverTx {
    if tx.mw_tx.is_none() && !tx.is_hog_ex {
        return CoverTx::Plain;
    }
    let (kernels, outputs) = tx
        .mw_tx
        .as_ref()
        .map(|mw| (mw.body.kernels.len() as u64, mw.body.outputs.len() as u64))
        .unwrap_or((0, 0));
    CoverTx::Mweb {
        txid: mempool_id(tx),
        wtxid: tx.compute_wtxid().to_string(),
        kernels,
        outputs,
    }
}

/// Id a node and this wallet agree on for a transaction in the mempool.
///
/// Pure MWEB uses the first kernel's BLAKE3 hash (Core `ComputeHash`, the
/// same id P2P broadcast inventories). Anything with a transparent input or
/// output uses `compute_txid`.
pub(crate) fn mempool_id(tx: &Transaction) -> String {
    pure_mweb_kernel_id(tx).unwrap_or_else(|| tx.compute_txid().to_string())
}

/// First kernel id of a transaction with an empty transparent skeleton.
pub(crate) fn pure_mweb_kernel_id(tx: &Transaction) -> Option<String> {
    if !tx.input.is_empty() || !tx.output.is_empty() {
        return None;
    }
    let kernel = tx.mw_tx.as_ref()?.body.kernels.first()?;
    Some(hex::encode(bdk_mweb::kernel_id(kernel)))
}

/// `compute_txid` of every pure MWEB transaction this wallet authors.
pub(crate) fn empty_mweb_skeleton_txid() -> String {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        use bdk_wallet::bitcoin::absolute::LockTime;
        use bdk_wallet::bitcoin::transaction::Version;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
            mw_tx: None,
            is_hog_ex: false,
        };
        tx.compute_txid().to_string()
    })
    .clone()
}

/// Kernel id of a pure MWEB transaction encoded as consensus hex.
pub(crate) fn kernel_id_from_raw(raw_hex: &str) -> Option<String> {
    if raw_hex.is_empty() {
        return None;
    }
    let bytes = hex::decode(raw_hex).ok()?;
    let tx: Transaction = deserialize(&bytes).ok()?;
    pure_mweb_kernel_id(&tx)
}

/// Sum a mempool listing. Pure so a test can feed it a fixed set.
///
/// Ids in `own` (txid or wtxid) are not foreign, including this wallet's other spends.
pub fn tally_cover(
    txs: impl IntoIterator<Item = CoverTx>,
    own: &BTreeSet<String>,
    now_unix: u64,
) -> CoverRead {
    let mut read = CoverRead {
        checked_at_unix: now_unix,
        ..CoverRead::default()
    };
    for tx in txs {
        read.total_txs = read.total_txs.saturating_add(1);
        match tx {
            CoverTx::Unreadable => {
                read.unreadable_txs = read.unreadable_txs.saturating_add(1);
            }
            CoverTx::Plain => {}
            CoverTx::Mweb {
                txid,
                wtxid,
                kernels,
                outputs,
            } => {
                read.mweb_txs = read.mweb_txs.saturating_add(1);
                if crate::churn::is_foreign_id(&txid, &wtxid, own) {
                    read.foreign_txs = read.foreign_txs.saturating_add(1);
                    read.kernels = read.kernels.saturating_add(kernels);
                    read.outputs = read.outputs.saturating_add(outputs);
                }
            }
        }
    }
    read
}

/// Other people's MWEB transactions in the node mempool.
///
/// A transaction counts when it carries an MWEB payload or is a HogEx integration.
/// Ids in `own` (txid or wtxid) are skipped, including this wallet's other spends.
pub fn count_foreign_mweb_mempool(
    rpc_url: &str,
    own: &BTreeSet<String>,
) -> Result<CoverRead, WalletError> {
    let ids = crate::rpc::get_raw_mempool(rpc_url)?;
    let txs = ids.iter().map(|txid| {
        let Ok(hex_tx) = crate::rpc::get_raw_transaction_hex(rpc_url, txid) else {
            return CoverTx::Unreadable;
        };
        let Ok(bytes) = hex::decode(&hex_tx) else {
            return CoverTx::Unreadable;
        };
        let Ok(tx) = deserialize::<Transaction>(&bytes) else {
            return CoverTx::Unreadable;
        };
        cover_tx_from(&tx)
    });
    Ok(tally_cover(txs, own, crate::churn::unix_now()))
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

/// Signed peg-out, not yet broadcast and not yet applied to the coin set.
///
/// The caller broadcasts outside the wallet lock, then [`apply_signed_pegout`].
pub struct SignedPegout {
    pub tx: Transaction,
    pub wtxid: String,
    fee_sats: u64,
    amount_sats: u64,
    spent_ids: Vec<[u8; 32]>,
    change: Option<bdk_mweb::MwebCoin>,
    addresses: Vec<String>,
}

impl SignedPegout {
    /// Output ids this peg-out spends. Freeze them until broadcast finishes.
    pub fn input_ids(&self) -> Vec<String> {
        self.spent_ids.iter().map(hex::encode).collect()
    }
}

/// Build and sign a peg-out. Does not broadcast or mark coins spent.
pub fn sign_pegout(
    wallet: &PersistedWallet<Connection>,
    runtime: &MwebRuntime,
    data_dir: &Path,
    req: PegoutRequest,
    network: WalletNetwork,
) -> Result<SignedPegout, WalletError> {
    let pegouts: Vec<(ScriptBuf, u64)> = if req.per_coin {
        if req.addresses.len() != req.output_amounts.len() || req.output_amounts.is_empty() {
            return Err(WalletError::BuildTx(
                "per-coin peg-out needs one fresh public address per private coin".into(),
            ));
        }
        let mut out = Vec::with_capacity(req.output_amounts.len());
        for (addr, amount) in req.addresses.iter().zip(req.output_amounts.iter()) {
            let (_dest, spk, min_non_dust) =
                crate::tx_invariants::validate_public_recipient(addr, network)?;
            crate::tx_invariants::check_money(*amount, "peg-out output amount")?;
            if *amount < min_non_dust {
                return Err(WalletError::BuildTx(format!(
                    "peg-out amount {} litoshis is below dust limit ({min_non_dust})",
                    amount
                )));
            }
            out.push((spk, *amount));
        }
        out
    } else {
        let (_dest, spk, min_non_dust) =
            crate::tx_invariants::validate_public_recipient(&req.address, network)?;
        crate::tx_invariants::check_money(req.amount_sats, "peg-out amount")?;
        if req.amount_sats < min_non_dust {
            return Err(WalletError::BuildTx(format!(
                "peg-out amount {} litoshis is below dust limit ({min_non_dust})",
                req.amount_sats
            )));
        }
        vec![(spk, req.amount_sats)]
    };

    let pegout_sum =
        crate::tx_invariants::checked_sum_sats(pegouts.iter().map(|(_, a)| *a), "peg-out outputs")?;
    if pegout_sum != req.amount_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-out output sum ({pegout_sum}) does not match amount_sats ({})",
            req.amount_sats
        )));
    }
    let tip = wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(data_dir)?;
    let selected = normalize_selected_ids(req.selected_output_ids.as_deref());
    let needed =
        crate::tx_invariants::checked_add_money(req.amount_sats, req.fee_sats, "peg-out total")?;
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
        pegouts.clone(),
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
    crate::tx_invariants::verify_mweb_spend_tx(
        &tx,
        &funded.spent_coins,
        &[],
        &pegouts,
        req.fee_sats,
        change.as_slice(),
        &runtime.secp,
    )?;
    let addresses = if req.per_coin {
        req.addresses
    } else if !req.address.is_empty() {
        vec![req.address]
    } else {
        Vec::new()
    };
    Ok(SignedPegout {
        wtxid: tx.compute_wtxid().to_string(),
        tx,
        fee_sats: req.fee_sats,
        amount_sats: req.amount_sats,
        spent_ids,
        change,
        addresses,
    })
}

/// Mark the spent coins, remember change, and record history. Does not broadcast.
pub fn apply_signed_pegout(
    runtime: &mut MwebRuntime,
    signed: &SignedPegout,
) -> MwebBroadcastResult {
    for id in &signed.spent_ids {
        let _ = runtime.store.db_mut().mark_spent(id);
    }
    let mut output_ids = Vec::new();
    if let Some(mut change) = signed.change.clone() {
        change.block_height = None;
        output_ids.push(hex::encode(change.output_id));
        runtime.store.db_mut().insert(change);
    }
    let net_sats =
        crate::tx_invariants::neg_net_sats(signed.amount_sats.saturating_add(signed.fee_sats))
            .unwrap_or(i64::MIN);
    runtime.history.record(MwebHistoryEntry {
        id: signed.wtxid.clone(),
        kind: TxKind::Pegout,
        net_sats,
        fee_sats: Some(signed.fee_sats),
        timestamp: now_ts(),
        output_ids,
        input_ids: signed.input_ids(),
        confirmed_height: None,
    });
    MwebBroadcastResult {
        wtxid: signed.wtxid.clone(),
        fee_sats: signed.fee_sats,
        addresses: signed.addresses.clone(),
    }
}

#[cfg(test)]
mod pegin_balance_tests {
    use super::*;
    use bdk_mweb::keys::{MasterKeyScheme, MasterKeys};
    use bdk_wallet::bitcoin::hex::FromHex;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::descriptor::IntoWalletDescriptor;
    use bdk_wallet::extract_prepared_mweb_pegin;
    use bdk_wallet::test_utils::{get_funded_wallet_wpkh, get_test_wpkh_and_change_desc};

    const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// Caller-owned signer for the `get_funded_wallet_wpkh` test descriptors.
    fn test_signer(wallet: &bdk_wallet::Wallet) -> ZeroizingSigner {
        let (desc, change_desc) = get_test_wpkh_and_change_desc();
        let (_, mut keymap) = desc
            .into_wallet_descriptor(wallet.secp_ctx(), wallet.network().into())
            .expect("descriptor");
        let (_, change_keymap) = change_desc
            .into_wallet_descriptor(wallet.secp_ctx(), wallet.network().into())
            .expect("change descriptor");
        keymap.extend(change_keymap);
        ZeroizingSigner::new(keymap)
    }

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
        let mweb_fee = Amount::from_sat(5_000);
        let transparent_fee = Amount::from_sat(500);
        let mut prepared = wallet
            .prepare_mweb_pegin(&keys, 2, pegin_amount, mweb_fee, transparent_fee, &secp)
            .expect("prepare_mweb_pegin");
        crate::descriptors::sign_and_finalize(&wallet, &test_signer(&wallet), &mut prepared.psbt)
            .expect("sign");
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
        let mut job = churn::new_job(&id, true, 4, 50_000, 2, false).unwrap();
        job.effective_depth = 2;
        job.set_phase_for_test(ChurnPhase::PausedSolo);
        let fields = churn_fields(&id, true, &BTreeMap::new(), Some(&job));
        assert_eq!(fields.churn_phase, Some(ChurnPhase::PausedSolo));
        assert_eq!(fields.churn_target, Some(4));
        assert_eq!(fields.churn_counted, Some(2));
        assert_eq!(fields.churn_fee_sats, Some(50_000));
        assert!(fields.churn_error.is_none());
    }

    #[test]
    fn finished_job_does_not_stamp_progress() {
        let id = output_id();
        let mut job = churn::new_job(&id, false, 1, 50_000, 2, false).unwrap();
        job.set_phase_for_test(ChurnPhase::Done);
        job.effective_depth = 1;
        let fields = churn_fields(&id, false, &BTreeMap::new(), Some(&job));
        assert!(fields.churn_phase.is_none());
        assert!(fields.churn_error.is_none());
        assert_eq!(fields.churn_target, Some(1));
        assert_eq!(fields.churn_counted, Some(1));
        assert!(fields.churn_fee_sats.is_none());
    }

    #[test]
    fn waiting_job_stamps_the_last_mempool_read() {
        let id = output_id();
        let mut job = churn::new_job(&id, false, 1, 50_000, 2, false).unwrap();
        job.set_phase_for_test(ChurnPhase::WaitingForCover);
        churn::note_cover_read(
            &mut job,
            &super::CoverRead {
                total_txs: 309,
                mweb_txs: 1,
                foreign_txs: 0,
                kernels: 0,
                outputs: 0,
                unreadable_txs: 2,
                checked_at_unix: 1_700_000_000,
            },
        );
        let fields = churn_fields(&id, false, &BTreeMap::new(), Some(&job));
        assert_eq!(fields.churn_cover_seen, Some(0));
        assert_eq!(fields.churn_cover_checked_at, Some(1_700_000_000));
        assert_eq!(fields.churn_cover_total, Some(309));
        assert_eq!(fields.churn_cover_kernels, Some(0));
        assert_eq!(fields.churn_cover_outputs, Some(0));
        assert!(fields.churn_cover_error.is_none());

        churn::note_cover_error(&mut job, 1_700_000_060, "Connection Failed");
        let fields = churn_fields(&id, false, &BTreeMap::new(), Some(&job));
        assert_eq!(fields.churn_cover_checked_at, Some(1_700_000_060));
        assert_eq!(
            fields.churn_cover_error.as_deref(),
            Some("Connection Failed")
        );
        // The last good counts stay so the card does not go blank.
        assert_eq!(fields.churn_cover_total, Some(309));

        job.set_phase_for_test(ChurnPhase::Done);
        let fields = churn_fields(&id, false, &BTreeMap::new(), Some(&job));
        assert!(fields.churn_cover_checked_at.is_none());
        assert!(fields.churn_cover_error.is_none());
    }
}

#[cfg(test)]
mod cover_tally_tests {
    use super::{tally_cover, CoverRead, CoverTx};
    use bdk_wallet::bitcoin::Transaction;
    use std::collections::BTreeSet;

    fn mweb(txid: &str, wtxid: &str, kernels: u64, outputs: u64) -> CoverTx {
        CoverTx::Mweb {
            txid: txid.into(),
            wtxid: wtxid.into(),
            kernels,
            outputs,
        }
    }

    #[test]
    fn empty_mempool_is_a_timestamped_zero() {
        let read = tally_cover(Vec::new(), &BTreeSet::new(), 42);
        assert_eq!(
            read,
            CoverRead {
                checked_at_unix: 42,
                ..CoverRead::default()
            }
        );
    }

    #[test]
    fn plain_transactions_count_toward_total_only() {
        let read = tally_cover(
            vec![CoverTx::Plain, CoverTx::Plain, CoverTx::Plain],
            &BTreeSet::new(),
            1,
        );
        assert_eq!(read.total_txs, 3);
        assert_eq!(read.mweb_txs, 0);
        assert_eq!(read.foreign_txs, 0);
    }

    #[test]
    fn foreign_kernels_and_outputs_are_summed_and_own_are_not() {
        let mut own = BTreeSet::new();
        own.insert("ours-wtxid".to_string());
        let read = tally_cover(
            vec![
                CoverTx::Plain,
                mweb("a", "aw", 1, 2),
                mweb("b", "bw", 2, 3),
                // Our own earlier hop is in the mempool. It is MWEB but not cover.
                mweb("ours", "ours-wtxid", 1, 1),
                // A HogEx has no MWEB body.
                mweb("hogex", "hogex-w", 0, 0),
                CoverTx::Unreadable,
            ],
            &own,
            7,
        );
        assert_eq!(read.total_txs, 6);
        assert_eq!(read.mweb_txs, 4);
        assert_eq!(read.foreign_txs, 3);
        assert_eq!(read.kernels, 3);
        assert_eq!(read.outputs, 5);
        assert_eq!(read.unreadable_txs, 1);
        assert_eq!(read.checked_at_unix, 7);
    }

    /// Two pure MWEB transactions share `compute_txid`. Cover still tells them
    /// apart by kernel id, so an own-set that contains one kernel id and the
    /// shared skeleton counts the other transaction as foreign.
    #[test]
    fn pure_mweb_cover_uses_kernel_id_not_the_shared_skeleton() {
        let ours = pure_mweb(1);
        let theirs = pure_mweb(2);
        let skeleton = super::empty_mweb_skeleton_txid();
        assert_eq!(ours.compute_txid(), theirs.compute_txid());
        assert_eq!(ours.compute_txid().to_string(), skeleton);

        let ours_cover = super::cover_tx_from(&ours);
        let theirs_cover = super::cover_tx_from(&theirs);
        let (ours_id, theirs_id) = match (&ours_cover, &theirs_cover) {
            (
                CoverTx::Mweb { txid: ours_id, .. },
                CoverTx::Mweb {
                    txid: theirs_id, ..
                },
            ) => (ours_id.clone(), theirs_id.clone()),
            _ => panic!("both transactions carry an MWEB kernel"),
        };
        assert_ne!(ours_id, theirs_id);
        assert_ne!(ours_id, skeleton);
        assert_ne!(theirs_id, skeleton);

        let mut own = BTreeSet::new();
        own.insert(ours_id);
        own.insert(skeleton);
        let read = tally_cover([ours_cover, theirs_cover], &own, 1);
        assert_eq!(read.mweb_txs, 2);
        assert_eq!(read.foreign_txs, 1);
    }

    /// Fee feature set, so the kernel round-trips through consensus encoding.
    fn pure_mweb(excess: u8) -> Transaction {
        use bdk_wallet::bitcoin::absolute::LockTime;
        use bdk_wallet::bitcoin::blockdata::mimblewimble::{Kernel, Transaction as MwTx, TxBody};
        use bdk_wallet::bitcoin::transaction::Version;
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
            mw_tx: Some(MwTx {
                kernel_offset: [1; 32],
                stealth_offset: [2; 32],
                body: TxBody {
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    kernels: vec![Kernel {
                        features: 0x01,
                        fee: Some(50_000),
                        pegin: None,
                        pegouts: Vec::new(),
                        lock_height: None,
                        stealth_excess: None,
                        extra_data: Vec::new(),
                        excess: [excess; 33],
                        signature: [7; 64],
                    }],
                },
            }),
            is_hog_ex: false,
        }
    }
}

#[cfg(test)]
mod broadcast_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::net::SocketAddr;
    use std::time::Duration;

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 9333))
    }

    /// Runs `run_p2p` against scripted peer answers. Each offer advances the
    /// fake clock by `per_offer`. Returns the run and the order peers were offered.
    fn run(
        first_pass: &[SocketAddr],
        discovered: &[SocketAddr],
        answers: &[(SocketAddr, Result<BroadcastAck, &str>)],
        per_offer: Duration,
    ) -> (PeerRun, Vec<SocketAddr>) {
        let offered = RefCell::new(Vec::new());
        let now = Cell::new(Duration::ZERO);
        let run = run_p2p(
            first_pass,
            || discovered.to_vec(),
            |a| {
                offered.borrow_mut().push(a);
                now.set(now.get() + per_offer);
                answers
                    .iter()
                    .find(|(peer, _)| *peer == a)
                    .map(|(_, answer)| (*answer).map_err(str::to_string))
                    .unwrap_or_else(|| Err("no answer scripted".into()))
            },
            || now.get(),
        );
        (run, offered.into_inner())
    }

    const SENT: Result<BroadcastAck, &str> = Ok(BroadcastAck::Sent);
    const CONFIRMED: Result<BroadcastAck, &str> = Ok(BroadcastAck::Confirmed);
    const FAILED: Result<BroadcastAck, &str> = Err("refused");

    #[test]
    fn first_confirmed_stops_the_search() {
        let (run, offered) = run(
            &[addr(1), addr(2), addr(3)],
            &[addr(9)],
            &[
                (addr(1), FAILED),
                (addr(2), CONFIRMED),
                (addr(3), CONFIRMED),
            ],
            Duration::from_secs(1),
        );
        assert_eq!(run.confirmed, Some(addr(2)));
        assert_eq!(offered, vec![addr(1), addr(2)]);
        assert_eq!(run.failed, vec![addr(1)]);
    }

    #[test]
    fn two_sent_answers_stop_the_search() {
        let (run, offered) = run(
            &[addr(1), addr(2), addr(3)],
            &[addr(9)],
            &[(addr(1), SENT), (addr(2), SENT), (addr(3), CONFIRMED)],
            Duration::from_secs(1),
        );
        assert_eq!(offered, vec![addr(1), addr(2)]);
        assert_eq!(run.confirmed, None);
        assert_eq!(run.sent, vec![addr(1), addr(2)]);
    }

    #[test]
    fn time_limit_stops_new_peers_once_a_sent_is_held() {
        let (run, offered) = run(
            &[addr(1), addr(2), addr(3)],
            &[],
            &[(addr(1), SENT), (addr(2), SENT), (addr(3), SENT)],
            BROADCAST_MAX_WAIT + Duration::from_secs(1),
        );
        assert_eq!(offered, vec![addr(1)]);
        assert_eq!(run.sent, vec![addr(1)]);
    }

    #[test]
    fn time_limit_does_not_stop_a_search_with_nothing_to_fall_back_on() {
        let (run, offered) = run(
            &[addr(1), addr(2)],
            &[addr(3)],
            &[(addr(1), FAILED), (addr(2), FAILED), (addr(3), CONFIRMED)],
            BROADCAST_MAX_WAIT + Duration::from_secs(1),
        );
        assert_eq!(offered, vec![addr(1), addr(2), addr(3)]);
        assert_eq!(run.confirmed, Some(addr(3)));
    }

    #[test]
    fn every_peer_failing_is_an_error_so_rpc_fallback_runs() {
        let (run, _) = run(
            &[addr(1)],
            &[addr(2)],
            &[(addr(1), FAILED), (addr(2), FAILED)],
            Duration::from_secs(1),
        );
        assert!(run.confirmed.is_none() && run.sent.is_empty());
        assert_eq!(run.failed, vec![addr(1), addr(2)]);
        assert!(
            run.error().contains("10.0.0.2:9333: refused"),
            "{}",
            run.error()
        );
    }

    #[test]
    fn no_peers_at_all_reports_unreachable() {
        let (run, offered) = run(&[], &[], &[], Duration::from_secs(1));
        assert!(offered.is_empty());
        assert_eq!(run.error(), "no MWEB P2P peers reachable");
    }

    #[test]
    fn a_sent_in_the_first_pass_skips_discovery() {
        let discovered_called = Cell::new(false);
        let run = run_p2p(
            &[addr(1)],
            || {
                discovered_called.set(true);
                vec![addr(9)]
            },
            |_| Ok(BroadcastAck::Sent),
            || Duration::ZERO,
        );
        assert_eq!(run.sent, vec![addr(1)]);
        assert!(!discovered_called.get());
    }

    #[test]
    fn order_is_configured_then_remembered_then_discovered_without_repeats() {
        let configured = [addr(1), addr(2)];
        let remembered = [addr(2), addr(5)];
        let first_pass = first_pass_peers(&configured, &remembered);
        assert_eq!(first_pass, vec![addr(1), addr(2), addr(5)]);
        let (_, offered) = run(
            &first_pass,
            &[addr(5), addr(1), addr(8)],
            &[],
            Duration::from_secs(1),
        );
        assert_eq!(offered, vec![addr(1), addr(2), addr(5), addr(8)]);
    }

    fn route(rpc_url: Option<&str>, via_own_node: bool) -> BroadcastRoute {
        BroadcastRoute {
            data_dir: std::path::PathBuf::new(),
            rpc_url: rpc_url.map(str::to_string),
            peers: Vec::new(),
            network: WalletNetwork::Testnet,
            via_own_node,
        }
    }

    #[test]
    fn rpc_goes_first_only_when_opted_in_with_a_url() {
        assert_eq!(
            route(Some("http://127.0.0.1:9332"), true).rpc_first(),
            Some("http://127.0.0.1:9332")
        );
        assert_eq!(
            route(Some("http://127.0.0.1:9332"), false).rpc_first(),
            None
        );
        assert_eq!(route(None, true).rpc_first(), None);
        assert_eq!(route(Some("  "), true).rpc_first(), None);
    }
}

#[cfg(test)]
mod sync_failover_tests {
    use super::*;
    use bdk_mweb::p2p::{
        header_hash, MwebHeaderMsg, MwebLeafset, MSG_MWEB_HEADER, MSG_MWEB_LEAFSET,
    };
    use bdk_wallet::bitcoin::block::{Header, MwebBlockHeader, Version as BlockVersion};
    use bdk_wallet::bitcoin::consensus::encode::{deserialize_partial, serialize};
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::merkle_tree::PartialMerkleTree;
    use bdk_wallet::bitcoin::p2p::message::{CommandString, NetworkMessage, RawNetworkMessage};
    use bdk_wallet::bitcoin::p2p::message_blockdata::Inventory;
    use bdk_wallet::bitcoin::p2p::message_network::VersionMessage;
    use bdk_wallet::bitcoin::p2p::{Address, ServiceFlags};
    use bdk_wallet::bitcoin::{
        absolute::LockTime, Amount, BlockHash, CompactTarget, MerkleBlock, ScriptBuf, Transaction,
        TxMerkleNode, TxOut,
    };
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};

    const NODE_MWEB_LIGHT_CLIENT: u64 = 1 << 23;

    #[derive(Clone, Copy)]
    enum PeerScript {
        /// Serves valid anchored `mwebheader` and empty `mwebleafset` for `tip_hash`,
        /// and `notfound` for any other block hash.
        Good,
        /// Immediately replies `notfound` to `getdata`.
        NotFound,
        /// Drops `getdata` and only replies `pong` to `ping` (clean tip-lag / empty pong).
        EmptyPong,
        /// Completes handshake, then stalls silently past `stage_timeout`.
        SilentStall,
        /// Serves `mwebheader` + `mwebleafset` after productive work, then stalls
        /// `getmwebutxos` past `pipeline_round_timeout` and writes late `mwebutxos`
        /// frames onto the same socket.
        SlowLeafsetThenDirtyStallUtxos,
    }

    fn anchored_block_with_leafset(
        height: u32,
        nonce: u32,
        leafset_bytes: Vec<u8>,
        output_mmr_size: u64,
    ) -> (BlockHash, Vec<u8>, Vec<u8>) {
        let mweb_header = MwebBlockHeader {
            height,
            output_root: [0u8; 32],
            kernel_root: [0u8; 32],
            leafset_root: bdk_mweb::hash::blake3_hash(&leafset_bytes),
            kernel_offset: [0u8; 32],
            stealth_offset: [0u8; 32],
            output_mmr_size,
            kernel_mmr_size: 0,
        };
        let mut spk = vec![0x58u8, 0x20];
        spk.extend_from_slice(&header_hash(&mweb_header));
        let filler = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
            mw_tx: None,
            is_hog_ex: false,
        };
        let hogex = Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(2),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            mw_tx: None,
            is_hog_ex: true,
        };
        let txids = vec![filler.compute_txid(), hogex.compute_txid()];
        let txn = PartialMerkleTree::from_txids(&txids, &[false, true]);
        let merkle_root = bdk_wallet::bitcoin::merkle_tree::calculate_root(txids.into_iter())
            .map(|h| TxMerkleNode::from_byte_array(h.to_byte_array()))
            .expect("merkle root");
        let header = Header {
            version: BlockVersion::ONE,
            prev_blockhash: BlockHash::from_byte_array([0x22; 32]),
            merkle_root,
            time: 1,
            bits: CompactTarget::from_consensus(1),
            nonce,
        };
        let block_hash = header.block_hash();
        let hdr_msg = MwebHeaderMsg {
            merkle: MerkleBlock { header, txn },
            hogex,
            mweb_header,
        };
        let leafset_msg = MwebLeafset {
            block_hash,
            leafset: leafset_bytes,
        };
        (block_hash, serialize(&hdr_msg), serialize(&leafset_msg))
    }

    fn anchored_empty_block(height: u32, nonce: u32) -> (BlockHash, Vec<u8>, Vec<u8>) {
        anchored_block_with_leafset(height, nonce, Vec::new(), 0)
    }

    fn read_msg(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<RawNetworkMessage> {
        let mut scratch = [0u8; 4096];
        loop {
            if !buf.is_empty() {
                if let Ok((msg, consumed)) = deserialize_partial::<RawNetworkMessage>(buf) {
                    buf.drain(..consumed);
                    return Some(msg);
                }
            }
            match stream.read(&mut scratch) {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
    }

    fn send_msg(stream: &mut TcpStream, payload: NetworkMessage) -> bool {
        let magic = WalletNetwork::Testnet.to_bitcoin_network().magic();
        let raw = RawNetworkMessage::new(magic, payload);
        let bytes = serialize(&raw);
        stream.write_all(&bytes).is_ok() && stream.flush().is_ok()
    }

    fn send_raw_cmd(stream: &mut TcpStream, command: &str, payload: &[u8]) -> bool {
        use bdk_wallet::bitcoin::consensus::Encodable;
        use bdk_wallet::bitcoin::hashes::sha256d;
        let magic = WalletNetwork::Testnet.to_bitcoin_network().magic();
        let cmd = CommandString::try_from(command).expect("valid command");
        let mut msg = Vec::with_capacity(24 + payload.len());
        magic.consensus_encode(&mut msg).unwrap();
        cmd.consensus_encode(&mut msg).unwrap();
        (payload.len() as u32).consensus_encode(&mut msg).unwrap();
        let checksum = sha256d::Hash::hash(payload);
        msg.extend_from_slice(&checksum[..4]);
        msg.extend_from_slice(payload);
        stream.write_all(&msg).is_ok() && stream.flush().is_ok()
    }

    fn spawn_scripted_peer(
        scripts: Vec<PeerScript>,
        tip_hash: BlockHash,
        hdr_payload: Vec<u8>,
        leafset_payload: Vec<u8>,
    ) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock peer");
        let addr = listener.local_addr().expect("local_addr");
        let connects = Arc::new(AtomicUsize::new(0));
        let tip_header_reqs = Arc::new(AtomicUsize::new(0));
        let connects_cl = Arc::clone(&connects);
        let tip_reqs_cl = Arc::clone(&tip_header_reqs);

        std::thread::spawn(move || {
            for (idx, mut stream) in listener.incoming().flatten().enumerate() {
                connects_cl.fetch_add(1, Ordering::SeqCst);
                let script = scripts
                    .get(idx)
                    .copied()
                    .or_else(|| scripts.last().copied())
                    .unwrap_or(PeerScript::Good);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let mut buf = Vec::new();

                // Expect Version, send Version + Verack.
                let Some(first) = read_msg(&mut stream, &mut buf) else {
                    continue;
                };
                if !matches!(first.payload(), NetworkMessage::Version(_)) {
                    continue;
                }
                let dummy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let ver = VersionMessage::new(
                    ServiceFlags::from(NODE_MWEB_LIGHT_CLIENT),
                    0,
                    Address::new(&dummy_addr, ServiceFlags::NONE),
                    Address::new(&dummy_addr, ServiceFlags::NONE),
                    1,
                    "/mock-mweb:0.1/".into(),
                    100,
                );
                if !send_msg(&mut stream, NetworkMessage::Version(ver))
                    || !send_msg(&mut stream, NetworkMessage::Verack)
                {
                    continue;
                }

                // Serve messages according to `script`.
                while let Some(msg) = read_msg(&mut stream, &mut buf) {
                    match msg.into_payload() {
                        NetworkMessage::GetData(invs) => match script {
                            PeerScript::SilentStall => {
                                std::thread::sleep(Duration::from_millis(350));
                                break;
                            }
                            PeerScript::NotFound => {
                                let _ = send_msg(&mut stream, NetworkMessage::NotFound(invs));
                            }
                            PeerScript::EmptyPong => {}
                            PeerScript::Good | PeerScript::SlowLeafsetThenDirtyStallUtxos => {
                                for inv in invs {
                                    if let Inventory::Unknown { inv_type, hash } = inv {
                                        let requested = BlockHash::from_byte_array(hash);
                                        if inv_type == MSG_MWEB_HEADER && requested == tip_hash {
                                            tip_reqs_cl.fetch_add(1, Ordering::SeqCst);
                                            let _ = send_raw_cmd(
                                                &mut stream,
                                                "mwebheader",
                                                &hdr_payload,
                                            );
                                        } else if inv_type == MSG_MWEB_LEAFSET
                                            && requested == tip_hash
                                        {
                                            if matches!(
                                                script,
                                                PeerScript::SlowLeafsetThenDirtyStallUtxos
                                            ) {
                                                std::thread::sleep(Duration::from_millis(160));
                                            }
                                            let _ = send_raw_cmd(
                                                &mut stream,
                                                "mwebleafset",
                                                &leafset_payload,
                                            );
                                        } else {
                                            let _ = send_msg(
                                                &mut stream,
                                                NetworkMessage::NotFound(vec![inv]),
                                            );
                                        }
                                    }
                                }
                            }
                        },
                        NetworkMessage::Unknown { command, .. }
                            if command.as_ref() == "getmwebutxos" =>
                        {
                            if matches!(script, PeerScript::SlowLeafsetThenDirtyStallUtxos) {
                                // Stall past `stage_timeout` (250ms), then push two late
                                // `mwebutxos` frames onto the socket that would trigger
                                // `peer sent more than 1 mwebutxos` if sequential `get_utxos`
                                // reused the dirty stream.
                                std::thread::sleep(Duration::from_millis(300));
                                let dummy = bdk_mweb::p2p::MwebUtxos {
                                    block_hash: tip_hash,
                                    start_index: 0,
                                    output_format: bdk_mweb::p2p::OUTPUT_FORMAT_FULL,
                                    utxos: Vec::new(),
                                    parent_hashes: Vec::new(),
                                };
                                let payload = serialize(&dummy);
                                let _ = send_raw_cmd(&mut stream, "mwebutxos", &payload);
                                let _ = send_raw_cmd(&mut stream, "mwebutxos", &payload);
                                std::thread::sleep(Duration::from_millis(100));
                                break;
                            } else {
                                let empty_utxos = bdk_mweb::p2p::MwebUtxos {
                                    block_hash: tip_hash,
                                    start_index: 0,
                                    output_format: bdk_mweb::p2p::OUTPUT_FORMAT_FULL,
                                    utxos: Vec::new(),
                                    parent_hashes: Vec::new(),
                                };
                                let _ = send_raw_cmd(
                                    &mut stream,
                                    "mwebutxos",
                                    &serialize(&empty_utxos),
                                );
                            }
                        }
                        NetworkMessage::Ping(nonce) => {
                            if matches!(script, PeerScript::SilentStall) {
                                std::thread::sleep(Duration::from_millis(350));
                                break;
                            }
                            if !send_msg(&mut stream, NetworkMessage::Pong(nonce)) {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
        (addr, connects, tip_header_reqs)
    }

    fn test_runtime(dir: &Path) -> MwebRuntime {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let secret = crate::seed::MasterSecret::parse(mnemonic, None).unwrap();
        MwebRuntime::open(
            dir,
            &secret,
            WalletNetwork::Testnet,
            MasterKeyScheme::LitecoinCore,
            0,
            None,
        )
        .expect("open test MwebRuntime")
    }

    fn fast_test_policy() -> PeerPolicy {
        PeerPolicy {
            connect_timeout: Duration::from_millis(200),
            handshake_timeout: Duration::from_millis(200),
            stage_timeout: Duration::from_millis(120),
            pipeline_round_timeout: Duration::from_millis(200),
            write_timeout: Duration::from_millis(200),
            max_reconnects: 0,
            max_throttled_rounds: 1,
            ping_flush_header: true,
        }
    }

    #[test]
    fn silent_peer_times_out_evicts_and_rotates_to_healthy_peer_with_stage_log() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_empty_block(100, 1);

        let (bad_peer, bad_connects, _) = spawn_scripted_peer(
            vec![PeerScript::SilentStall],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (good_peer, _, _) = spawn_scripted_peer(
            vec![PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (backup_peer, _, _) =
            spawn_scripted_peer(vec![PeerScript::Good], tip_hash, hdr_bytes, leaf_bytes);

        crate::discovery::set_peers_for_test(Some(vec![bad_peer, good_peer, backup_peer]));
        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));
        let (cursor, _) = crate::diag::since(u64::MAX);

        let started = Instant::now();
        rt.sync_at_tip(
            100,
            tip_hash,
            None,
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");
        let elapsed = started.elapsed();

        TEST_PEER_POLICY.with(|c| c.set(None));
        let remaining = crate::discovery::peers_for_test().unwrap_or_default();
        crate::discovery::set_peers_for_test(None);

        assert!(
            !rt.stale,
            "sync should succeed on good_peer: {}",
            rt.last_status
        );
        assert_eq!(rt.last_good_peer, Some(good_peer));
        assert_eq!(
            bad_connects.load(Ordering::SeqCst),
            1,
            "silent peer must not be reconnected 4x in multi-peer failover"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "failover took too long: {elapsed:?}"
        );
        assert_eq!(
            remaining,
            vec![good_peer, backup_peer],
            "hard-failing silent peer must be evicted from discovery cache"
        );

        let (_, logs) = crate::diag::since(cursor);
        assert!(
            logs.iter().any(|l| {
                l.contains(&format!("sync: mweb peer={bad_peer} stage=get_header"))
                    && l.contains("err=timeout")
                    && l.contains("attempt=1/3")
            }),
            "expected per-peer stage timeout log, got: {logs:?}"
        );
    }

    #[test]
    fn notfound_tip_lag_short_circuits_demotes_without_evicting_and_rotates() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_empty_block(101, 2);

        let (lag_peer, _, _) = spawn_scripted_peer(
            vec![PeerScript::NotFound],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (good_peer, _, _) = spawn_scripted_peer(
            vec![PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (backup_peer, _, _) =
            spawn_scripted_peer(vec![PeerScript::Good], tip_hash, hdr_bytes, leaf_bytes);

        crate::discovery::set_peers_for_test(Some(vec![lag_peer, good_peer, backup_peer]));
        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));
        let (cursor, _) = crate::diag::since(u64::MAX);

        rt.sync_at_tip(
            101,
            tip_hash,
            None,
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");

        TEST_PEER_POLICY.with(|c| c.set(None));
        let pool_after = crate::discovery::peers_for_test().unwrap_or_default();
        crate::discovery::set_peers_for_test(None);

        assert!(
            !rt.stale,
            "sync should succeed on good_peer: {}",
            rt.last_status
        );
        assert_eq!(rt.last_good_peer, Some(good_peer));
        assert_eq!(
            pool_after,
            vec![good_peer, backup_peer, lag_peer],
            "clean tip-lag peer (notfound) must be demoted to back, not evicted"
        );

        let (_, logs) = crate::diag::since(cursor);
        assert!(
            logs.iter().any(|l| {
                l.contains(&format!("sync: mweb peer={lag_peer} stage=get_header"))
                    && l.contains("err=notfound")
                    && l.contains("attempt=1/3")
            }),
            "expected notfound stage log, got: {logs:?}"
        );
    }

    #[test]
    fn all_peers_tip_lag_backs_off_and_retries_without_evicting_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_empty_block(102, 3);

        // Both peers lag on pass 1 (empty pong) and serve the block on pass 2.
        let (peer_a, a_connects, _) = spawn_scripted_peer(
            vec![PeerScript::EmptyPong, PeerScript::Good, PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (peer_b, _, _) = spawn_scripted_peer(
            vec![PeerScript::EmptyPong, PeerScript::Good, PeerScript::Good],
            tip_hash,
            hdr_bytes,
            leaf_bytes,
        );

        crate::discovery::set_peers_for_test(Some(vec![peer_a, peer_b]));
        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));
        TEST_TIP_LAG_BACKOFF.with(|c| c.set(Some(Duration::from_millis(20))));
        let (cursor, _) = crate::diag::since(u64::MAX);

        rt.sync_at_tip(
            102,
            tip_hash,
            None,
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");

        TEST_PEER_POLICY.with(|c| c.set(None));
        TEST_TIP_LAG_BACKOFF.with(|c| c.set(None));
        let pool_after = crate::discovery::peers_for_test().unwrap_or_default();
        crate::discovery::set_peers_for_test(None);

        assert!(
            !rt.stale,
            "retry after tip-lag backoff should succeed: {}",
            rt.last_status
        );
        assert!(a_connects.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            pool_after.len(),
            2,
            "all-peer clean tip-lag must not evict healthy peers from the pool"
        );

        let (_, logs) = crate::diag::since(cursor);
        assert!(
            logs.iter()
                .any(|l| l.contains("sync: mweb all 2 peer(s) lagging tip=102; waiting")),
            "expected tip-lag backoff log, got: {logs:?}"
        );
    }

    #[test]
    fn tip_header_is_fetched_only_once_per_peer_across_fine_headers_and_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        // Seed `tip_height = Some(103)` and `prev_tip_hash = Some(prev_hash)` so
        // `FixedHeaderProvider` includes height 103 (missing on peer -> `notfound`)
        // and height 105 (`tip_hash`), exercising `sample_fine_headers` (`FineWindow`)
        // before `run_once` verifies `tip_hash`.
        let prev_hash = BlockHash::from_byte_array([0x33; 32]);
        rt.sync_state.tip_height = Some(103);
        rt.sync_state.tip_hash = Some(prev_hash);
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_empty_block(105, 4);

        let (peer_a, _, a_tip_hdr_reqs) = spawn_scripted_peer(
            vec![PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (peer_b, _, _) =
            spawn_scripted_peer(vec![PeerScript::Good], tip_hash, hdr_bytes, leaf_bytes);

        crate::discovery::set_peers_for_test(Some(vec![peer_a, peer_b]));
        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));

        rt.sync_at_tip(
            105,
            tip_hash,
            Some(prev_hash),
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");

        // Also verify direct `TcpMwebPeer::get_header` memoization on repeated calls.
        let mut direct_peer = TcpMwebPeer::connect_with_policy(
            peer_a,
            WalletNetwork::Testnet.to_bitcoin_network(),
            fast_test_policy(),
        )
        .expect("connect direct_peer");
        let _ = MwebUtxoSource::get_header(&mut direct_peer, tip_hash).expect("first get_header");
        let _ = MwebUtxoSource::get_header(&mut direct_peer, tip_hash).expect("second get_header");
        assert_eq!(direct_peer.header_fetches(), 1);

        TEST_PEER_POLICY.with(|c| c.set(None));
        crate::discovery::set_peers_for_test(None);

        assert!(
            !rt.stale,
            "missing intermediate historical header must not fail sync: {}",
            rt.last_status
        );
        assert_eq!(
            a_tip_hdr_reqs.load(Ordering::SeqCst),
            2,
            "1 wire request during sync_pass + 1 wire request across 2 memoized direct calls"
        );
    }

    #[test]
    fn unconfirmed_broadcast_demotes_sent_peers_so_next_sync_rotates_away() {
        let p1 = SocketAddr::from(([10, 0, 0, 1], 9333));
        let p2 = SocketAddr::from(([10, 0, 0, 2], 9333));
        let p3 = SocketAddr::from(([10, 0, 0, 3], 9333));
        crate::discovery::set_peers_for_test(Some(vec![p1, p2, p3]));

        // Before demotion, `last_good_peer = Some(p1)` is preferred at index 0.
        assert_eq!(
            peers_for_headers(&[], WalletNetwork::Testnet, Some(p1)),
            vec![p1, p2, p3]
        );

        // Unconfirmed broadcast (`BroadcastAck::Sent`, `confirmed: None`) on `p1`
        // demotes `p1` to the back of the discovery pool.
        crate::discovery::demote_peers(&[p1]);
        assert!(!crate::discovery::should_prefer_peer(&p1));
        assert_eq!(
            peers_for_headers(&[], WalletNetwork::Testnet, Some(p1)),
            vec![p2, p3, p1],
            "demoted peer must not be re-promoted to index 0 by peers_for_headers"
        );

        crate::discovery::set_peers_for_test(None);
    }

    #[test]
    fn parallel_cross_check_probe_confirms_leafset_once_and_demotes_lagging_backup_without_evicting(
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        // Non-empty leafset (`vec![0x00]`, 1 spent leaf) so `cross_check_leafset`
        // verifies the leafset root against backup peers while downloading 0 UTXOs.
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_block_with_leafset(106, 5, vec![0x00], 1);

        let (peer_a, a_connects, _) = spawn_scripted_peer(
            vec![PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (peer_b_lag, b_connects, _) = spawn_scripted_peer(
            vec![PeerScript::NotFound],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (peer_c_good, c_connects, c_tip_reqs) =
            spawn_scripted_peer(vec![PeerScript::Good], tip_hash, hdr_bytes, leaf_bytes);

        crate::discovery::set_peers_for_test(Some(vec![peer_a, peer_b_lag, peer_c_good]));
        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));

        rt.sync_at_tip(
            106,
            tip_hash,
            None,
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");

        let pool_after = crate::discovery::peers_for_test().unwrap_or_default();
        assert!(!rt.stale, "sync should succeed: {}", rt.last_status);
        assert_eq!(rt.last_cross_checked_tip, Some((tip_hash, 2)));
        assert_eq!(b_connects.load(Ordering::SeqCst), 1);
        assert_eq!(c_tip_reqs.load(Ordering::SeqCst), 1);
        assert_eq!(
            pool_after,
            vec![peer_a, peer_c_good, peer_b_lag],
            "lagging backup peer probed in parallel must be demoted, never evicted"
        );

        // Also verify `sync_at_tip_cancellable` aborts immediately without touching
        // peers when `cancel` is already set.
        let (tip_hash_2, _, _) = anchored_empty_block(107, 6);
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let a_before = a_connects.load(Ordering::SeqCst);
        let b_before = b_connects.load(Ordering::SeqCst);
        let c_before = c_connects.load(Ordering::SeqCst);
        rt.sync_at_tip_cancellable(
            107,
            tip_hash_2,
            Some(tip_hash),
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
            Some(&cancel),
            None,
        )
        .expect("cancelled sync_at_tip_cancellable returns Ok");
        assert_eq!(a_connects.load(Ordering::SeqCst), a_before);
        assert_eq!(b_connects.load(Ordering::SeqCst), b_before);
        assert_eq!(c_connects.load(Ordering::SeqCst), c_before);
        assert_eq!(rt.sync_state.tip_height, Some(106));

        TEST_PEER_POLICY.with(|c| c.set(None));
        crate::discovery::set_peers_for_test(None);
    }

    #[test]
    fn pipelined_utxo_timeout_does_not_reuse_dirty_socket_or_charge_productive_time_to_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rt = test_runtime(tmp.path());
        // Leaf 0 is unspent (`0x80`, output_mmr_size = 1) so full scan enters
        // `get_utxos_pipelined`.
        let (tip_hash, hdr_bytes, leaf_bytes) = anchored_block_with_leafset(108, 7, vec![0x80], 1);

        let (stalling_peer, _, _) = spawn_scripted_peer(
            vec![PeerScript::SlowLeafsetThenDirtyStallUtxos],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (good_peer, good_connects, _) = spawn_scripted_peer(
            vec![PeerScript::Good],
            tip_hash,
            hdr_bytes.clone(),
            leaf_bytes.clone(),
        );
        let (backup_peer, _, _) =
            spawn_scripted_peer(vec![PeerScript::Good], tip_hash, hdr_bytes, leaf_bytes);

        crate::discovery::set_peers_for_test(Some(vec![stalling_peer, good_peer, backup_peer]));
        // `stage_timeout` = 250ms allows the 160ms leafset to succeed (`~160ms` productive work),
        // then `get_utxos_pipelined` times out at `pipeline_round_timeout` = 200ms (`~360ms` total
        // attempt wall time, but only `~200ms` unproductive time).
        let mut policy = fast_test_policy();
        policy.stage_timeout = Duration::from_millis(250);
        policy.pipeline_round_timeout = Duration::from_millis(200);
        TEST_PEER_POLICY.with(|c| c.set(Some(policy)));
        // Budget is 340ms: total attempt time (~420ms) exceeds 340ms, but unproductive stage time
        // (~250ms) is under 340ms, so `sync_pass` must still rotate to `good_peer`.
        TEST_UNPRODUCTIVE_BUDGET.with(|c| c.set(Some(Duration::from_millis(340))));
        let (cursor, _) = crate::diag::since(u64::MAX);

        rt.sync_at_tip(
            108,
            tip_hash,
            None,
            &[],
            WalletNetwork::Testnet,
            None,
            &BTreeSet::new(),
        )
        .expect("sync_at_tip");

        TEST_PEER_POLICY.with(|c| c.set(None));
        TEST_UNPRODUCTIVE_BUDGET.with(|c| c.set(None));
        crate::discovery::set_peers_for_test(None);

        assert!(
            !rt.stale,
            "sync must rotate to good_peer without exhausting unproductive budget on productive leafset time: {}",
            rt.last_status
        );
        assert_eq!(rt.last_good_peer, Some(good_peer));
        assert!(good_connects.load(Ordering::SeqCst) >= 1);

        let (_, logs) = crate::diag::since(cursor);
        assert!(
            logs.iter().any(|l| {
                l.contains(&format!("sync: mweb peer={stalling_peer} stage=get_utxos"))
                    && l.contains("err=timeout")
            }),
            "pipelined UTXO timeout must report err=timeout rather than dirty-socket protocol violation, got: {logs:?}"
        );
        assert!(
            !logs
                .iter()
                .any(|l| l.contains("more than 1 mwebutxos") || l.contains("unproductive budget exhausted")),
            "must not hit dirty-socket protocol violation or false unproductive budget exhaustion, got: {logs:?}"
        );
    }

    #[test]
    fn audit_f8_find_output_leaf_rejects_unproven_out_of_bounds_leaf_index() {
        let tmp = tempfile::tempdir().unwrap();
        let rt = test_runtime(tmp.path());
        let mut pegin =
            bdk_mweb::fund_mweb_pegin(&rt.keys, 0, 100_000, 2_100, NetworkKind::Test, &rt.secp)
                .expect("fund pegin output");
        let _ = bdk_mweb::sign_funded_mweb_pegin(&mut pegin, &rt.keys, &rt.secp).unwrap();
        let pegin_tx = extract_prepared_mweb_pegin(&pegin.psbt).unwrap();
        let sample_output = pegin_tx.mw_tx.unwrap().body.outputs[0].clone();
        let want_hex = hex::encode(bdk_mweb::scan::output_id(&sample_output));

        let tip_hash = BlockHash::from_byte_array([0x77; 32]);
        let forged_leaf_index: u64 = 999_999; // Far outside [start_index=1, end_output_mmr=5)
        let raw_mwebutxos = serialize(&bdk_mweb::p2p::MwebUtxos {
            block_hash: tip_hash,
            start_index: 1,
            output_format: bdk_mweb::p2p::OUTPUT_FORMAT_FULL,
            utxos: vec![bdk_mweb::p2p::MwebUtxoEntry {
                leaf_index: forged_leaf_index,
                output: sample_output,
            }],
            parent_hashes: Vec::new(),
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer_addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let mut buf = Vec::new();
                let Some(first) = read_msg(&mut stream, &mut buf) else {
                    return;
                };
                if !matches!(first.payload(), NetworkMessage::Version(_)) {
                    return;
                }
                let dummy_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
                let ver = VersionMessage::new(
                    ServiceFlags::from(NODE_MWEB_LIGHT_CLIENT),
                    0,
                    Address::new(&dummy_addr, ServiceFlags::NONE),
                    Address::new(&dummy_addr, ServiceFlags::NONE),
                    1,
                    "/mock-mweb:0.1/".into(),
                    100,
                );
                let _ = send_msg(&mut stream, NetworkMessage::Version(ver));
                let _ = send_msg(&mut stream, NetworkMessage::Verack);
                while let Some(msg) = read_msg(&mut stream, &mut buf) {
                    match msg.into_payload() {
                        NetworkMessage::Unknown { command, .. }
                            if command.as_ref() == "getmwebutxos" =>
                        {
                            let _ = send_raw_cmd(&mut stream, "mwebutxos", &raw_mwebutxos);
                        }
                        NetworkMessage::Ping(nonce)
                            if !send_msg(&mut stream, NetworkMessage::Pong(nonce)) =>
                        {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        });

        TEST_PEER_POLICY.with(|c| c.set(Some(fast_test_policy())));
        let got = find_output_leaf(
            &[peer_addr],
            WalletNetwork::Testnet,
            tip_hash,
            1,
            5,
            &want_hex,
        );
        TEST_PEER_POLICY.with(|c| c.set(None));

        assert_ne!(
            got,
            ChainLeaf::Found(forged_leaf_index),
            "find_output_leaf accepted unproven out-of-bounds leaf_index={forged_leaf_index} for window [1, 5)"
        );
    }
}

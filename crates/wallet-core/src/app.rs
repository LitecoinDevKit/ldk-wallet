use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_electrum::electrum_client::ElectrumApi;
use bdk_mweb::mweb_sync::SyncProgress;

use bdk_wallet::bitcoin::{
    Amount, BlockHash, OutPoint, Psbt, Script, ScriptBuf, Transaction, Txid,
};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet};
use zeroize::{Zeroize, Zeroizing};

use crate::accounts;
use crate::churn;
use crate::contacts;
use crate::descriptors::{
    self, create_params, load_params, sign_and_finalize, signer, ZeroizingSigner,
};
use crate::diag;
use crate::dto::{
    AddressReuseHint, ChurnPhase, ChurnPreview, ChurnRequest, ChurnStatus, CombinedSummary,
    ContactRecord, CoverHold, CreateAccountRequest, CreateWalletRequest, CreateWalletResponse,
    DeleteContactRequest, DeleteWalletRequest, DiagnosticsBundle, ElectrumProbe, FeeEstimate,
    MigrateEncryptRequest, MwebBroadcastResult, MwebScheme, MwebSendPreview, MwebSendRequest,
    MwebUtxoRecord, PeginPreview, PeginRequest, PeginResult, PegoutPreview, PegoutRequest,
    RenameWalletRequest, RestoreWalletRequest, RevealMnemonicRequest, RevealMnemonicResponse,
    SendPreview, SendRequest, SendResult, SetMwebUtxoLockedRequest, SetTxLabelRequest,
    SetUtxoLabelRequest, SetUtxoLockedRequest, SplitChain, SplitPreview, SplitRequest, SplitResult,
    SwitchWalletRequest, SyncPhase, SyncResult, TransferCoinPreview, TransferCoinRequest,
    TransferCoinResult, TxKind, TxRecord, UnlockRequest, UpdateSettingsRequest,
    UpsertContactRequest, UtxoRecord, WalletListItem, WalletSettings, WalletSummary,
    CHURN_AMOUNT_NOTE,
};
use crate::electrum::{self, MIN_FEE_RATE_SAT_VB};
use crate::error::WalletError;
use crate::labels;
use crate::meta::{self, WalletMeta};
use crate::metadata::{self, MetadataImportResult};
use crate::mweb::{self, MwebRuntime};
use crate::mweb_frozen;
use crate::network::WalletNetwork;
use crate::secrets::{EncryptedFileSecretStore, SecretStore, UnlockableSecretStore};
use crate::seed::MasterSecret;
use crate::split::{self, PlanParams};
use crate::split_ids;
use crate::spv;
use crate::utxo_labels;
use crate::{MNEMONIC_ENC_FILE, MNEMONIC_FILE};

struct WalletState {
    wallet: PersistedWallet<Connection>,
    /// Caller-owned transparent signing keys (see [`descriptors::signer`]); the wallet itself
    /// holds no secrets. Lives and dies with this state, i.e. cleared on `lock()`.
    signer: ZeroizingSigner,
    db: Connection,
    /// BIP84 / MWEB / LitVM account index for [`Self::data_dir`].
    account_index: u32,
    network: WalletNetwork,
    electrum_url: String,
    /// Verify TLS certificates on ssl:// Electrum servers.
    electrum_validate_domain: bool,
    /// Fall back to built-in public servers when the configured one is down.
    electrum_use_public_fallback: bool,
    /// Lock the wallet after this many idle minutes (0 = never); enforced by the UI.
    auto_lock_minutes: u32,
    /// Server that most recently worked this session (tried first to avoid
    /// re-paying a connect timeout on a dead configured server).
    active_electrum_url: Option<String>,
    litecoin_rpc_url: Option<String>,
    broadcast_via_own_node: bool,
    mweb_peers: Vec<String>,
    mweb_scheme: MwebScheme,
    explorer_base_url: String,
    show_fiat: bool,
    use_explorer_fee_hints: bool,
    insights_enabled: bool,
    data_dir: PathBuf,
    needs_full_scan: bool,
    needs_mweb_scan: bool,
    mweb: Option<MwebRuntime>,
    last_tip_height: u32,
    /// Unix seconds of the Electrum header at `tip_time_height`, if read this session.
    tip_time: Option<u64>,
    tip_time_height: u32,
}

/// Snapshot the persistable subset of `state` (single source of truth for
/// every `write_meta` call).
fn meta_from_state(state: &WalletState) -> WalletMeta {
    WalletMeta {
        account_index: state.account_index,
        network: state.network,
        electrum_url: state.electrum_url.clone(),
        electrum_validate_domain: state.electrum_validate_domain,
        electrum_use_public_fallback: state.electrum_use_public_fallback,
        auto_lock_minutes: state.auto_lock_minutes,
        needs_full_scan: state.needs_full_scan,
        needs_mweb_scan: state.needs_mweb_scan,
        litecoin_rpc_url: state.litecoin_rpc_url.clone(),
        broadcast_via_own_node: state.broadcast_via_own_node,
        mweb_peers: state.mweb_peers.clone(),
        mweb_scheme: state.mweb_scheme,
        explorer_base_url: state.explorer_base_url.clone(),
        show_fiat: state.show_fiat,
        use_explorer_fee_hints: state.use_explorer_fee_hints,
        insights_enabled: state.insights_enabled,
    }
}

fn broadcast_route(state: &WalletState) -> mweb::BroadcastRoute {
    mweb::BroadcastRoute {
        data_dir: state.data_dir.clone(),
        rpc_url: state.litecoin_rpc_url.clone(),
        peers: state.mweb_peers.clone(),
        network: state.network,
        via_own_node: state.broadcast_via_own_node,
    }
}

/// Candidate Electrum URLs in try order: session URL (if any), configured,
/// then (unless the user opted out) the built-in public defaults.
fn electrum_candidate_list(
    session_url: Option<&str>,
    configured_url: &str,
    use_public_fallback: bool,
    network: WalletNetwork,
) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    if let Some(session) = session_url.filter(|url| !url.is_empty()) {
        urls.push(session.to_string());
    }
    if !urls.iter().any(|url| url == configured_url) {
        urls.push(configured_url.to_string());
    }
    if use_public_fallback {
        for default in network.default_electrum_urls() {
            let default = default.to_string();
            if !urls.contains(&default) {
                urls.push(default);
            }
        }
    }
    urls
}

/// Candidate Electrum URLs for a loaded wallet: last-good this session, configured,
/// then (unless the user opted out) the built-in public defaults.
fn electrum_candidates(state: &WalletState) -> Vec<String> {
    electrum_candidate_list(
        state.active_electrum_url.as_deref(),
        &state.electrum_url,
        state.electrum_use_public_fallback,
        state.network,
    )
}

/// Connect with fallback, remembering what worked on `state`.
fn connect_electrum(
    state: &mut WalletState,
) -> Result<crate::electrum::ElectrumClient, WalletError> {
    connect_electrum_prefer(state, None)
}

/// [`connect_electrum`] with an extra URL tried first (the server that worked
/// before this wallet was locked).
fn connect_electrum_prefer(
    state: &mut WalletState,
    prefer: Option<&str>,
) -> Result<crate::electrum::ElectrumClient, WalletError> {
    let mut candidates = electrum_candidates(state);
    if let Some(prefer) = prefer.filter(|url| !url.is_empty()) {
        candidates.retain(|url| url != prefer);
        candidates.insert(0, prefer.to_string());
    }
    let (client, used) = electrum::connect_first(&candidates, state.electrum_validate_domain)?;
    if used != state.electrum_url {
        diag::log(format!(
            "electrum: configured server unavailable; using fallback {used}"
        ));
    }
    state.active_electrum_url = Some(used);
    Ok(client)
}

fn connect_from_meta(
    meta: &WalletMeta,
    prefer: Option<&str>,
) -> Result<(crate::electrum::ElectrumClient, String), WalletError> {
    let mut candidates = electrum_candidate_list(
        None,
        &meta.electrum_url,
        meta.electrum_use_public_fallback,
        meta.network,
    );
    if let Some(prefer) = prefer.filter(|url| !url.is_empty()) {
        candidates.retain(|url| url != prefer);
        candidates.insert(0, prefer.to_string());
    }
    let (client, used) = electrum::connect_first(&candidates, meta.electrum_validate_domain)?;
    if used != meta.electrum_url {
        diag::log(format!(
            "electrum: configured server unavailable; using fallback {used}"
        ));
    }
    Ok((client, used))
}

/// True when a `TxKind::Pegin` history row records a locally broadcast
/// transparent peg-in transaction (`id` is the transparent `txid`), rather than
/// a coin synthesized by `absorb_received_coins` (`id` is the MWEB `output_id`).
fn is_local_pegin_entry(entry: &crate::mweb_history::MwebHistoryEntry) -> bool {
    entry.kind == TxKind::Pegin
        && entry.net_sats < 0
        && !entry.output_ids.iter().any(|oid| oid == &entry.id)
}

/// A local peg-in the wallet no longer has, and whose private outputs are gone.
///
/// Evicting the transparent spend puts the inputs back in the balance. The
/// history row would otherwise stay at 0 confirmations and render as
/// "maturing · pending". An entry with no output ids, or whose coins are
/// still in the store, is a repair candidate and stays.
fn is_dropped_local_pegin(
    entry: &crate::mweb_history::MwebHistoryEntry,
    tx_in_wallet: bool,
    outputs_still_owed: bool,
) -> bool {
    is_local_pegin_entry(entry)
        && entry.confirmed_height.is_none()
        && !tx_in_wallet
        && !outputs_still_owed
}

/// How long a peg-in can stay unseen before a sync may call it unrelayed.
///
/// A peer that does not echo the tx can still be relaying it. Litecoin blocks
/// are a couple of minutes apart, so one quiet sync is not a rejection.
const PEGIN_ABSENT_GRACE_SECS: u64 = 180;

/// A local peg-in a sync has already failed to find, which is still not in a block.
///
/// History shows "Not relayed" and Clear. A peg-in that is only missing a
/// broadcast echo stays pending until it is mined or this grace expires.
fn pegin_can_clear(
    entry: &crate::mweb_history::MwebHistoryEntry,
    tx_confirmed: bool,
    output_on_chain: bool,
) -> bool {
    is_local_pegin_entry(entry)
        && entry.absent
        && entry.confirmed_height.is_none()
        && !tx_confirmed
        && !output_on_chain
}

/// A peg-out whose recorded fee is the pre-fix kernel price.
///
/// One public output is the smallest peg-out this wallet sends, so any fee
/// under that floor cannot relay. A per-coin peg-out has no MWEB change and
/// paid exactly the old kernel fee for one output per input; that price is
/// also short once each public output is billed.
fn pegout_fee_is_short(entry: &crate::mweb_history::MwebHistoryEntry) -> bool {
    if entry.kind != TxKind::Pegout {
        return false;
    }
    let Some(fee) = entry.fee_sats else {
        return false;
    };
    let script = mweb::p2wpkh_script();
    let change = entry.output_ids.len();
    let one = crate::tx_invariants::min_kernel_fee(change, [script.as_script()]);
    if fee < one {
        return true;
    }
    if change == 0 {
        let n = entry.input_ids.len().max(1);
        let old = bdk_mweb::policy::min_mweb_fee(bdk_mweb::policy::mweb_weight(
            0,
            std::iter::repeat(script.as_script()).take(n),
        ));
        let required =
            crate::tx_invariants::min_kernel_fee(0, std::iter::repeat(script.as_script()).take(n));
        if fee == old && fee < required {
            return true;
        }
    }
    false
}

/// History shows Not relayed and Clear for a peg-in a sync could not find, or
/// a peg-out whose fee the network will not relay.
fn spend_can_clear(
    entry: &crate::mweb_history::MwebHistoryEntry,
    tx_confirmed: bool,
    on_chain: bool,
) -> bool {
    if tx_confirmed || on_chain || entry.confirmed_height.is_some() {
        return false;
    }
    pegin_can_clear(entry, false, false) || pegout_fee_is_short(entry)
}

fn coin_id_has_leaf(oid_hex: &str, db: &bdk_mweb::MwebCoinDatabase) -> bool {
    hex::decode(oid_hex)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .and_then(|id| db.get(&id).or_else(|| db.get_spent(&id)))
        .is_some_and(|coin| coin.leaf_index.is_some())
}

fn pegin_output_has_leaf(
    entry: &crate::mweb_history::MwebHistoryEntry,
    db: &bdk_mweb::MwebCoinDatabase,
) -> bool {
    entry
        .output_ids
        .iter()
        .any(|oid_hex| coin_id_has_leaf(oid_hex, db))
}

/// True when repair should still look up the transparent peg-in. Empty output
/// lists are the legacy rows that credited nothing we can see. Coins still in
/// the store, or spent with a leaf, were credited and the spend may be missing.
fn pegin_outputs_still_owed(
    entry: &crate::mweb_history::MwebHistoryEntry,
    db: &bdk_mweb::MwebCoinDatabase,
) -> bool {
    entry.output_ids.is_empty()
        || entry.output_ids.iter().any(|oid_hex| {
            hex::decode(oid_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .is_some_and(|id| {
                    db.get(&id).is_some()
                        || db.get_spent(&id).is_some_and(|c| c.leaf_index.is_some())
                })
        })
}

/// Peg-in txids in MWEB history. Their transparent spends are ours even when
/// no Electrum server reports them, so SPV eviction never drops them.
fn pegin_txids(history: &crate::mweb_history::MwebHistory) -> HashSet<Txid> {
    history
        .entries
        .iter()
        .filter(|e| is_local_pegin_entry(e))
        .filter_map(|e| parse_txid(&e.id))
        .collect()
}

/// True when `wallet`'s chain still contains the previous tip header and the tip
/// did not move backwards. A lower tip or a replaced header is a reorg.
fn chain_extended_in_place(
    wallet: &PersistedWallet<Connection>,
    prev_height: u32,
    prev_hash: bdk_wallet::bitcoin::BlockHash,
) -> bool {
    if wallet.latest_checkpoint().height() < prev_height {
        return false;
    }
    wallet
        .local_chain()
        .get(prev_height)
        .map(|cp| cp.hash() == prev_hash)
        .unwrap_or(false)
}

/// Explorer settings Insights needs. Kept off the wallet mutex so a litview
/// refresh does not wait out Electrum or MWEB sync.
struct InsightsEndpoint {
    enabled: bool,
    base_url: String,
}

/// Non-active accounts kept loaded. A switch back skips sqlite and the MWEB
/// address book. Signing keys live here until lock, wipe, or eviction.
const PARK_CAP: usize = 3;

enum WarmSkip {
    /// This index is already loaded.
    This,
    /// Park is full; further opens would be evicted.
    Stop,
    Open,
}

/// Least-recently-used at the front.
struct AccountPark {
    slots: VecDeque<(u32, WalletState)>,
}

impl AccountPark {
    fn new() -> Self {
        Self {
            slots: VecDeque::new(),
        }
    }

    fn clear(&mut self) {
        self.slots.clear();
    }

    fn len(&self) -> usize {
        self.slots.len()
    }

    fn contains(&self, index: u32) -> bool {
        self.slots.iter().any(|(i, _)| *i == index)
    }

    fn take(&mut self, index: u32) -> Option<WalletState> {
        let pos = self.slots.iter().position(|(i, _)| *i == index)?;
        self.slots.remove(pos).map(|(_, state)| state)
    }

    fn drop_index(&mut self, index: u32) {
        self.slots.retain(|(i, _)| *i != index);
    }

    fn get_mut(&mut self, index: u32) -> Option<&mut WalletState> {
        self.slots
            .iter_mut()
            .find(|(i, _)| *i == index)
            .map(|(_, state)| state)
    }

    fn get_mut_by_dir(&mut self, data_dir: &Path) -> Option<&mut WalletState> {
        self.slots
            .iter_mut()
            .find(|(_, state)| state.data_dir == data_dir)
            .map(|(_, state)| state)
    }

    /// Most-recently used at the back. Drops the oldest past [`PARK_CAP`].
    fn insert(&mut self, state: WalletState) {
        let index = state.account_index;
        self.drop_index(index);
        self.slots.push_back((index, state));
        while self.slots.len() > PARK_CAP {
            self.slots.pop_front();
        }
    }
}

/// Install `state` as the active account. A different account that was active
/// stays resident so switching back does not reload it.
fn install_loaded(
    guard: &mut Option<WalletState>,
    park: &mut AccountPark,
    mut state: WalletState,
) -> Result<WalletSummary, WalletError> {
    let summary = build_summary(&mut state)?;
    let from = if guard.is_some() {
        "Loaded"
    } else {
        "UnlockedEmpty"
    };
    let account_index = state.account_index;
    if let Some(prev) = guard.take() {
        if prev.account_index != state.account_index {
            park.insert(prev);
        }
    }
    *guard = Some(state);
    diag::log(format!(
        "lock-state: {from} -> Loaded event=Load account={account_index} reason=account loaded"
    ));
    Ok(summary)
}

/// Swap in a resident account. `None` means it still has to be read from disk.
fn activate_parked(
    guard: &mut Option<WalletState>,
    park: &mut AccountPark,
    index: u32,
) -> Result<Option<WalletSummary>, WalletError> {
    if guard.as_ref().is_some_and(|s| s.account_index == index) {
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        return Ok(Some(build_summary(state)?));
    }
    let Some(mut state) = park.take(index) else {
        return Ok(None);
    };
    let from = if guard.is_some() {
        "Loaded"
    } else {
        "UnlockedEmpty"
    };
    if let Some(prev) = guard.take() {
        park.insert(prev);
    }
    let summary = build_summary(&mut state)?;
    *guard = Some(state);
    diag::log(format!(
        "lock-state: {from} -> Loaded event=Load account={index} reason=parked account activated"
    ));
    Ok(Some(summary))
}

/// How long a completed locked prefetch can stand in for the unlocked Electrum
/// pass that runs right after `load_wallet`.
const PREFETCH_REUSE_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// Cached result of [`electrum::cross_check_tip`] so unchanged tips do not
/// reconnect to the second Electrum server on every sync.
struct CrossCheckCache {
    server_url: String,
    tip_height: u32,
    tip_hash: bdk_wallet::bitcoin::BlockHash,
    warning: Option<String>,
}

/// Result of a recent locked transparent prefetch so the immediate post-unlock
/// [`WalletApp::sync`] does not repeat the same Electrum scan.
struct FreshPrefetch {
    account_dir: PathBuf,
    server_url: String,
    tip_height: u32,
    tip_hash: bdk_wallet::bitcoin::BlockHash,
    tip_time: u64,
    new_txs: u32,
    completed_at: std::time::Instant,
}

/// The only writer of [`WalletApp::sync_phase`] during a pass. Dropped without
/// [`SyncPass::finish`], it puts the phase back to Idle, so no early return can
/// leave pollers reading a step that has stopped.
struct SyncPass<'a> {
    phase: &'a AtomicU8,
    generation: &'a std::sync::atomic::AtomicU64,
    my_gen: u64,
    electrum_progress: &'a spv::ElectrumProgress,
    transparent_ready: &'a AtomicBool,
    finished: bool,
}

impl SyncPass<'_> {
    fn is_current(&self) -> bool {
        self.generation.load(Ordering::Acquire) == self.my_gen
    }

    fn electrum(&self, full_scan: bool) {
        if !self.is_current() {
            return;
        }
        self.electrum_progress.reset();
        if full_scan {
            self.set(SyncPhase::ElectrumFullScan, "electrum full_scan");
        } else {
            self.set(SyncPhase::ElectrumSync, "electrum sync");
        }
    }

    fn mweb(&self) {
        if !self.is_current() {
            return;
        }
        self.electrum_progress.reset();
        self.set(SyncPhase::MwebDownload, "mweb download");
    }

    /// Done stays visible until the next pass starts.
    fn finish(mut self) {
        if self.is_current() {
            self.electrum_progress.reset();
            self.transparent_ready.store(false, Ordering::Release);
            self.set(SyncPhase::Done, "pass finished");
        }
        self.finished = true;
    }

    /// Locked prefetch only warms the transparent chain; return to Idle cleanly
    /// instead of logging an aborted pass on drop.
    fn finish_prefetch(mut self) {
        if self.is_current() {
            self.electrum_progress.reset();
            self.transparent_ready.store(false, Ordering::Release);
            self.set(SyncPhase::Idle, "prefetch finished");
        }
        self.finished = true;
    }

    fn set(&self, phase: SyncPhase, reason: &str) {
        if !self.is_current() {
            return;
        }
        let from = SyncPhase::from_u8(self.phase.swap(phase.as_u8(), Ordering::Relaxed));
        if from != phase {
            diag::log(format!("sync-phase: {from:?} -> {phase:?} reason={reason}"));
        }
    }
}

impl Drop for SyncPass<'_> {
    fn drop(&mut self) {
        if !self.finished && self.is_current() {
            self.electrum_progress.reset();
            self.transparent_ready.store(false, Ordering::Release);
            self.set(SyncPhase::Idle, "pass exited before finish");
        }
    }
}

/// Private balance shown while the MWEB runtime is off the wallet mutex.
///
/// Taken from the last combined summary before the download starts, so a
/// refresh during the download does not flash "MWEB unavailable".
#[derive(Clone)]
struct DetachedMwebView {
    confirmed_sats: u64,
    unconfirmed_sats: u64,
    immature_sats: u64,
    maturity_blocks: u32,
    total_sats: u64,
    receive_address: Option<String>,
    synced_height: Option<u32>,
    stale: bool,
    status: String,
}

impl DetachedMwebView {
    fn from_combined(summary: &CombinedSummary) -> Self {
        Self {
            confirmed_sats: summary.mweb_confirmed_sats,
            unconfirmed_sats: summary.mweb_unconfirmed_sats,
            immature_sats: summary.mweb_immature_sats,
            maturity_blocks: summary.mweb_maturity_blocks,
            total_sats: summary.mweb_total_sats,
            receive_address: summary.mweb_receive_address.clone(),
            synced_height: summary.mweb_synced_height,
            stale: summary.mweb_stale,
            status: summary.mweb_status.clone(),
        }
    }

    fn into_combined(self, transparent: WalletSummary) -> CombinedSummary {
        CombinedSummary {
            transparent,
            mweb_confirmed_sats: self.confirmed_sats,
            mweb_unconfirmed_sats: self.unconfirmed_sats,
            mweb_immature_sats: self.immature_sats,
            mweb_maturity_blocks: self.maturity_blocks,
            mweb_total_sats: self.total_sats,
            mweb_receive_address: self.receive_address,
            mweb_synced_height: self.synced_height,
            mweb_stale: self.stale,
            mweb_status: self.status,
        }
    }
}

/// MWEB runtime plus the tip it is syncing, held off the wallet mutex.
struct ParkedMweb {
    runtime: Option<MwebRuntime>,
    tip_height: u32,
    tip_hash: BlockHash,
    prev_tip_hash: Option<BlockHash>,
    peers: Vec<String>,
    network: WalletNetwork,
    hold_spent: BTreeSet<[u8; 32]>,
    alt_electrum: Option<String>,
    validate_domain: bool,
    local_chain_hashes: HashMap<u32, BlockHash>,
    used_server: String,
    cached_warning: Option<String>,
    run_cross_check: bool,
}

struct DetachedMwebDone {
    parked: ParkedMweb,
    warnings: Vec<String>,
    mweb_ms: u64,
    cross_ms: u64,
    mweb_wall_ms: u64,
}

struct BroadcastFlightGuard<'a> {
    app: &'a WalletApp,
}

impl<'a> BroadcastFlightGuard<'a> {
    fn new(app: &'a WalletApp) -> Self {
        app.in_flight_broadcasts.fetch_add(1, Ordering::AcqRel);
        Self { app }
    }
}

impl Drop for BroadcastFlightGuard<'_> {
    fn drop(&mut self) {
        self.app.in_flight_broadcasts.fetch_sub(1, Ordering::AcqRel);
        self.app.mweb_detached_cv.notify_all();
    }
}

/// Ephemeral commit credentials captured under `lock_state()` before network
/// broadcast, so a transaction that already went out on the wire can still
/// commit its local state change if `lock()` or `park_mweb()` runs mid-broadcast.
/// Zeroized on drop.
struct AccountCommitHandle<'a> {
    secret: MasterSecret,
    sealing_key: Option<Zeroizing<[u8; 32]>>,
    _flight: BroadcastFlightGuard<'a>,
}

/// Application-facing wallet handle. BDK types stay private.
pub struct WalletApp {
    state: Mutex<Option<WalletState>>,
    /// Accounts this session already opened, other than the active one.
    parked: Mutex<AccountPark>,
    /// One cold open at a time, so a switch and a background warm never open
    /// the same sqlite twice. Not held while an already-loaded account swaps in.
    account_load: Mutex<()>,
    secrets: Arc<EncryptedFileSecretStore>,
    /// Shared MWEB download progress; lives outside the state mutex so it can be
    /// polled while a sync (which holds that mutex) is in flight.
    mweb_progress: Arc<SyncProgress>,
    mweb_sync_active: AtomicBool,
    /// Shared Electrum SPV scan/fetch/verify counters for UI polling.
    electrum_progress: spv::ElectrumProgress,
    /// Coarse sync phase for UI polling (see [`SyncPhase`]).
    sync_phase: AtomicU8,
    /// Monotonic counter so an older background prefetch pass cannot overwrite
    /// the phase or progress of a newer unlocked sync pass.
    sync_generation: std::sync::atomic::AtomicU64,
    /// Set once Electrum is persisted and the state mutex is about to be released
    /// for the MWEB download. Cleared when the pass finishes or is dropped.
    transparent_ready: AtomicBool,
    /// True while [`ParkedMweb`] owns the runtime. Private spends refuse.
    mweb_detached: AtomicBool,
    /// Last private balance, served by [`Self::combined_summary`] during detach.
    detached_mweb: Mutex<Option<DetachedMwebView>>,
    /// Monotonic counter incremented on lock/unlock/wipe so a detached MWEB sync
    /// from an earlier unlocked session can never reattach into a new session.
    session_epoch: AtomicU64,
    /// [`Self::session_epoch`] captured when [`Self::park_mweb`] detached the runtime.
    detached_mweb_epoch: AtomicU64,
    /// Account directory whose MWEB runtime is currently detached.
    detached_mweb_dir: Mutex<Option<PathBuf>>,
    /// Notified when [`Self::mweb_detached`] clears or [`Self::lock`] runs.
    mweb_detached_cv: Condvar,
    /// Number of broadcast-then-commit operations in flight between signing and commit.
    in_flight_broadcasts: AtomicUsize,
    /// Set when [`Self::lock`] cannot take the state mutex (e.g. sync in flight).
    /// The holder must drop in-memory wallet state before returning.
    pending_lock: AtomicBool,
    /// Random per process. Coin holds written under another session are stale.
    session: String,
    /// Electrum URL that connected most recently. Survives lock so the next
    /// sync does not retry a dead configured server first. Not a secret.
    last_good_electrum: Mutex<Option<String>>,
    /// Recent locked prefetch that `sync()` can reuse immediately after unlock.
    last_prefetch: Mutex<Option<FreshPrefetch>>,
    /// Last Electrum tip already audited against a second server.
    last_cross_check: Mutex<Option<CrossCheckCache>>,
    /// Copied from wallet state on load and settings save. Insights reads this
    /// instead of the wallet mutex.
    insights_endpoint: Mutex<Option<InsightsEndpoint>>,
    /// When a missing peg-in's slow fallbacks (local RPC, another Electrum
    /// server, a public explorer) last failed. The sync server is still asked
    /// every pass. Not a secret.
    pegin_repair_fallback_at: Mutex<HashMap<String, std::time::Instant>>,
    /// Exclusive non-blocking OS directory lock held on `<data_dir>/.wallet.lock`
    /// while this handle has loaded or parked wallet state.
    dir_lock: Mutex<Option<mweb_frozen::DirLock>>,
}

impl WalletApp {
    /// Create a wallet app with encrypted file-backed mnemonic storage under `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            state: Mutex::new(None),
            parked: Mutex::new(AccountPark::new()),
            account_load: Mutex::new(()),
            secrets: Arc::new(EncryptedFileSecretStore::new(
                data_dir.join(MNEMONIC_ENC_FILE),
                data_dir.join(MNEMONIC_FILE),
            )),
            mweb_progress: Arc::new(SyncProgress::default()),
            mweb_sync_active: AtomicBool::new(false),
            electrum_progress: spv::ElectrumProgress::default(),
            sync_phase: AtomicU8::new(SyncPhase::Idle.as_u8()),
            sync_generation: std::sync::atomic::AtomicU64::new(0),
            transparent_ready: AtomicBool::new(false),
            mweb_detached: AtomicBool::new(false),
            detached_mweb: Mutex::new(None),
            session_epoch: AtomicU64::new(1),
            detached_mweb_epoch: AtomicU64::new(0),
            detached_mweb_dir: Mutex::new(None),
            mweb_detached_cv: Condvar::new(),
            in_flight_broadcasts: AtomicUsize::new(0),
            pending_lock: AtomicBool::new(false),
            session: hex::encode(rand::random::<[u8; 16]>()),
            last_good_electrum: Mutex::new(None),
            last_prefetch: Mutex::new(None),
            last_cross_check: Mutex::new(None),
            insights_endpoint: Mutex::new(None),
            pegin_repair_fallback_at: Mutex::new(HashMap::new()),
            dir_lock: Mutex::new(None),
        }
    }

    fn acquire_dir_lock(&self, data_dir: &Path) -> Result<(), WalletError> {
        let mut slot = self
            .dir_lock
            .lock()
            .map_err(|_| WalletError::Persist("wallet dir lock poisoned".into()))?;
        if slot.as_ref().is_some_and(|l| l.matches_dir(data_dir)) {
            return Ok(());
        }
        let lock = mweb_frozen::try_lock_dir(data_dir)?;
        *slot = Some(lock);
        Ok(())
    }

    fn release_dir_lock(&self) {
        if let Ok(mut slot) = self.dir_lock.lock() {
            *slot = None;
        }
    }

    /// Slow peg-in fallbacks ran and failed recently. The connected Electrum
    /// server is still worth asking; the others are not, until the backoff ends.
    fn pegin_fallback_due(&self, id: &str) -> bool {
        let Ok(map) = self.pegin_repair_fallback_at.lock() else {
            return true;
        };
        match map.get(id) {
            Some(at) => at.elapsed() >= PEGIN_REPAIR_BACKOFF,
            None => true,
        }
    }

    fn note_pegin_fallback(&self, id: &str, failed: bool) {
        let Ok(mut map) = self.pegin_repair_fallback_at.lock() else {
            return;
        };
        if failed {
            map.insert(id.to_string(), std::time::Instant::now());
        } else {
            map.remove(id);
        }
    }

    fn remembered_electrum(&self) -> Option<String> {
        self.last_good_electrum
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    fn remember_electrum(&self, url: String) {
        if let Ok(mut slot) = self.last_good_electrum.lock() {
            *slot = Some(url);
        }
    }

    fn forget_electrum(&self) {
        if let Ok(mut slot) = self.last_good_electrum.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = self.last_prefetch.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = self.last_cross_check.lock() {
            *slot = None;
        }
    }

    fn cached_cross_check(
        &self,
        server_url: &str,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
    ) -> Option<Option<String>> {
        let slot = self.last_cross_check.lock().ok()?;
        let cached = slot.as_ref()?;
        if cached.server_url == server_url
            && cached.tip_height == tip_height
            && cached.tip_hash == tip_hash
        {
            Some(cached.warning.clone())
        } else {
            None
        }
    }

    fn note_cross_check(
        &self,
        server_url: String,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        warning: Option<String>,
    ) {
        if let Ok(mut slot) = self.last_cross_check.lock() {
            *slot = Some(CrossCheckCache {
                server_url,
                tip_height,
                tip_hash,
                warning,
            });
        }
    }

    fn note_fresh_prefetch(&self, prefetch: FreshPrefetch) {
        if let Ok(mut slot) = self.last_prefetch.lock() {
            *slot = Some(prefetch);
        }
    }

    fn take_fresh_prefetch(
        &self,
        account_dir: &Path,
        tip_height: u32,
        tip_hash: bdk_wallet::bitcoin::BlockHash,
        needs_full_scan: bool,
    ) -> Option<FreshPrefetch> {
        let mut slot = self.last_prefetch.lock().ok()?;
        let prefetched = slot.take()?;
        if !needs_full_scan
            && prefetched.account_dir == account_dir
            && prefetched.tip_height == tip_height
            && prefetched.tip_hash == tip_hash
            && prefetched.completed_at.elapsed() < PREFETCH_REUSE_WINDOW
        {
            Some(prefetched)
        } else {
            None
        }
    }

    fn sync_pass(&self) -> SyncPass<'_> {
        let my_gen = self.sync_generation.fetch_add(1, Ordering::AcqRel) + 1;
        SyncPass {
            phase: &self.sync_phase,
            generation: &self.sync_generation,
            my_gen,
            electrum_progress: &self.electrum_progress,
            transparent_ready: &self.transparent_ready,
            finished: false,
        }
    }

    fn capture_commit_handle(&self) -> Result<AccountCommitHandle<'_>, WalletError> {
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let sealing_key = self.secrets.sealing_key();
        Ok(AccountCommitHandle {
            secret,
            sealing_key,
            _flight: BroadcastFlightGuard::new(self),
        })
    }

    fn clear_detached_mweb(&self) {
        self.mweb_detached.store(false, Ordering::Release);
        self.detached_mweb_epoch.store(0, Ordering::Release);
        if let Ok(mut dir) = self.detached_mweb_dir.lock() {
            *dir = None;
        }
        if let Ok(mut slot) = self.detached_mweb.lock() {
            *slot = None;
        }
        self.mweb_detached_cv.notify_all();
    }

    fn detached_mweb_view(&self) -> Option<DetachedMwebView> {
        if self.secrets.is_locked() || self.pending_lock.load(Ordering::Acquire) {
            return None;
        }
        self.detached_mweb.lock().ok().and_then(|slot| slot.clone())
    }

    /// Private coins are not in the wallet mutex. Refuse rather than reporting
    /// that MWEB was never created.
    fn refuse_if_mweb_detached(&self) -> Result<(), WalletError> {
        if self.mweb_detached.load(Ordering::Acquire) {
            Err(WalletError::Mweb(
                "Confidential sync is still running. Public coins can move now; private coins wait until it finishes."
                    .into(),
            ))
        } else {
            Ok(())
        }
    }

    /// Lift the MWEB runtime off the wallet so the download can run without the
    /// state mutex. `None` when this wallet has no MWEB runtime.
    fn park_mweb(&self, guard: &mut StateGuard<'_>) -> Result<Option<MwebRuntime>, WalletError> {
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        if state.mweb.is_none() {
            return Ok(None);
        }
        let account_dir = state.data_dir.clone();
        let transparent = build_summary(state)?;
        let combined = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?
            .combined_summary(&state.wallet, transparent)?;
        let runtime = state
            .mweb
            .take()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let cur_epoch = self.session_epoch.load(Ordering::Acquire);
        self.detached_mweb_epoch.store(cur_epoch, Ordering::Release);
        if let Ok(mut dir) = self.detached_mweb_dir.lock() {
            *dir = Some(account_dir);
        }
        if let Ok(mut slot) = self.detached_mweb.lock() {
            *slot = Some(DetachedMwebView::from_combined(&combined));
        }
        self.mweb_detached.store(true, Ordering::Release);
        Ok(Some(runtime))
    }

    /// Put a parked runtime back on the same account. A lock that landed while
    /// it was out wins: the runtime is dropped (and wiped) instead of being
    /// installed into a wallet the user already locked or into a later session.
    /// If the user switched accounts during the same unlocked session, the
    /// runtime is reattached into [`AccountPark`].
    fn restore_parked_mweb(
        &self,
        account_dir: &Path,
        mut runtime: MwebRuntime,
    ) -> Result<(), WalletError> {
        let mut guard = match self.lock_state() {
            Ok(guard) => guard,
            Err(err) => {
                runtime.wipe();
                self.clear_detached_mweb();
                drop(runtime);
                return Err(err);
            }
        };
        let cur_epoch = self.session_epoch.load(Ordering::Acquire);
        let detached_epoch = self.detached_mweb_epoch.load(Ordering::Acquire);
        let dir_matches = self
            .detached_mweb_dir
            .lock()
            .ok()
            .and_then(|d| d.clone())
            .is_some_and(|d| d == account_dir);
        if detached_epoch == 0 || cur_epoch != detached_epoch || !dir_matches {
            runtime.wipe();
            self.clear_detached_mweb();
            drop(runtime);
            return Err(WalletError::Locked);
        }
        let Some(state) = guard.as_mut() else {
            runtime.wipe();
            self.clear_detached_mweb();
            drop(runtime);
            return Err(WalletError::NotLoaded);
        };
        if state.data_dir == account_dir {
            if state.mweb.is_some() {
                runtime.wipe();
                self.clear_detached_mweb();
                drop(runtime);
                return Err(WalletError::Locked);
            }
            state.mweb = Some(runtime);
            self.clear_detached_mweb();
            return Ok(());
        }
        if let Ok(mut park) = self.lock_park() {
            if let Some(parked_state) = park.get_mut_by_dir(account_dir) {
                if parked_state.mweb.is_none() {
                    parked_state.mweb = Some(runtime);
                    self.clear_detached_mweb();
                    return Ok(());
                }
            }
        }
        runtime.wipe();
        self.clear_detached_mweb();
        drop(runtime);
        Err(WalletError::NotLoaded)
    }

    fn publish_insights(&self, state: &WalletState) {
        if let Ok(mut slot) = self.insights_endpoint.lock() {
            *slot = Some(InsightsEndpoint {
                enabled: state.insights_enabled,
                base_url: state.explorer_base_url.clone(),
            });
        }
    }

    fn clear_insights(&self) {
        if let Ok(mut slot) = self.insights_endpoint.lock() {
            *slot = None;
        }
    }

    /// Progress of the current sync. Does not take the wallet state lock, so it
    /// is safe to poll while [`Self::sync`] or [`Self::resync_mweb`] runs.
    pub fn mweb_sync_progress(&self) -> crate::dto::MwebSyncProgress {
        let (fetched, total) = self.mweb_progress.snapshot();
        crate::dto::MwebSyncProgress {
            phase: SyncPhase::from_u8(self.sync_phase.load(Ordering::Relaxed)),
            active: self.mweb_sync_active.load(Ordering::Relaxed),
            fetched,
            total,
            scripts_scanned: self
                .electrum_progress
                .scripts_scanned
                .load(Ordering::Relaxed),
            scripts_active: self
                .electrum_progress
                .scripts_active
                .load(Ordering::Relaxed),
            transparent_ready: self.transparent_ready.load(Ordering::Acquire),
            txs_fetched: self.electrum_progress.txs_fetched.load(Ordering::Relaxed),
            txs_total: self.electrum_progress.txs_total.load(Ordering::Relaxed),
            anchors_verified: self
                .electrum_progress
                .anchors_verified
                .load(Ordering::Relaxed),
            anchors_total: self.electrum_progress.anchors_total.load(Ordering::Relaxed),
        }
    }

    /// Diagnostic log lines after `since`, for the live log view. Does not touch
    /// wallet state, so it is safe to poll while locked or syncing.
    pub fn diag_log_since(&self, since: u64) -> crate::dto::DiagLogPage {
        let (next, lines) = diag::since(since);
        crate::dto::DiagLogPage { next, lines }
    }

    /// Redacted support bundle for Export diagnostics (no secrets, no Unstoppable API key).
    pub fn diagnostics(&self, app_version: &str) -> DiagnosticsBundle {
        let generated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let sync_phase = SyncPhase::from_u8(self.sync_phase.load(Ordering::Relaxed));
        let recent_log_lines = diag::snapshot();

        let mut bundle = DiagnosticsBundle {
            app_version: app_version.to_string(),
            os: std::env::consts::OS.to_string(),
            generated_unix,
            network: None,
            electrum_url: None,
            electrum_validate_domain: None,
            electrum_use_public_fallback: None,
            active_electrum_url: None,
            mweb_scheme: None,
            mweb_peers: None,
            needs_full_scan: None,
            needs_mweb_scan: None,
            tip_height: None,
            mweb_synced_height: None,
            mweb_status: None,
            sync_phase,
            recent_log_lines,
        };

        let Some(guard) = self.try_lock_state() else {
            bundle
                .recent_log_lines
                .push("note: wallet busy (sync in progress); meta snapshot skipped".into());
            return bundle;
        };
        let Some(state) = guard.as_ref() else {
            return bundle;
        };

        bundle.network = Some(format!("{:?}", state.network).to_lowercase());
        bundle.electrum_url = Some(crate::redact::redact_userinfo(&state.electrum_url));
        bundle.electrum_validate_domain = Some(state.electrum_validate_domain);
        bundle.electrum_use_public_fallback = Some(state.electrum_use_public_fallback);
        bundle.active_electrum_url = crate::redact::redact_opt_url(&state.active_electrum_url);
        bundle.mweb_scheme = Some(match state.mweb_scheme {
            MwebScheme::LitecoinCore => "litecoin-core".into(),
            MwebScheme::Lip0004 => "lip0004".into(),
            MwebScheme::Mwebd => "mwebd".into(),
        });
        bundle.mweb_peers = Some(state.mweb_peers.clone());
        bundle.needs_full_scan = Some(state.needs_full_scan);
        bundle.needs_mweb_scan = Some(state.needs_mweb_scan);
        bundle.tip_height = Some(state.last_tip_height);
        if let Some(ref mweb) = state.mweb {
            bundle.mweb_synced_height = mweb.last_synced_height.or(mweb.sync_state.tip_height);
            if !mweb.last_status.is_empty() {
                bundle.mweb_status = Some(mweb.last_status.clone());
            }
        }
        bundle
    }

    /// Reset shared progress and mark an MWEB pass active/inactive around `f`.
    fn with_mweb_progress<R>(&self, f: impl FnOnce(Arc<SyncProgress>) -> R) -> R {
        self.mweb_progress.fetched.store(0, Ordering::Relaxed);
        self.mweb_progress.total.store(0, Ordering::Relaxed);
        self.mweb_sync_active.store(true, Ordering::Relaxed);
        let out = f(Arc::clone(&self.mweb_progress));
        self.mweb_sync_active.store(false, Ordering::Relaxed);
        out
    }

    /// Test helper using an in-memory secret store (no encryption).
    pub fn with_secrets(secrets: Arc<dyn SecretStore>) -> MemoryBackedApp {
        MemoryBackedApp {
            state: Mutex::new(None),
            parked: Mutex::new(AccountPark::new()),
            account_load: Mutex::new(()),
            secrets,
        }
    }

    pub fn exists(&self, data_dir: &Path) -> bool {
        accounts::wallet_exists(data_dir)
    }

    pub fn is_locked(&self) -> bool {
        self.secrets.is_locked()
    }

    /// 32-byte secp256k1 secret for LitVM (`m/44'/60'/{account}'/0/0`).
    /// Uses the loaded wallet's account index (0 if none loaded). Requires unlock.
    /// Zeroizes on drop. Never log this value.
    pub fn litvm_account_secret(&self) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        self.ensure_unlocked()?;
        let account = self
            .state
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.account_index))
            .unwrap_or(0);
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        secret.litvm_account_secret(account)
    }

    /// Active account directory under `root` (after migration).
    pub fn active_account_dir(&self, root: &Path) -> Result<PathBuf, WalletError> {
        accounts::active_account_dir(root)
    }

    pub fn list_wallets(&self, root: &Path) -> Result<Vec<WalletListItem>, WalletError> {
        accounts::ensure_layout(root)?;
        let reg = accounts::read_registry(root)?;
        Ok(reg
            .accounts
            .iter()
            .map(|a| WalletListItem {
                index: a.index,
                name: a.name.clone(),
                is_active: a.index == reg.active_index,
            })
            .collect())
    }

    pub fn rename_wallet(
        &self,
        root: &Path,
        req: RenameWalletRequest,
    ) -> Result<Vec<WalletListItem>, WalletError> {
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        let entry = reg
            .accounts
            .iter_mut()
            .find(|a| a.index == req.index)
            .ok_or(WalletError::NotFound)?;
        let name = req.name.trim();
        if name.is_empty() {
            return Err(WalletError::Meta("wallet name must not be empty".into()));
        }
        entry.name = name.to_string();
        accounts::write_registry(root, &reg)?;
        self.list_wallets(root)
    }

    pub fn switch_wallet(
        &self,
        root: &Path,
        req: SwitchWalletRequest,
    ) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        if reg.get(req.index).is_none() {
            return Err(WalletError::NotFound);
        }
        reg.active_index = req.index;
        accounts::write_registry(root, &reg)?;
        let _gate = self.lock_account_load()?;
        let mut guard = self.lock_state()?;
        let activated = {
            let mut park = self.lock_park()?;
            if park.get_mut(req.index).is_some_and(|s| s.mweb.is_none()) {
                park.drop_index(req.index);
                None
            } else if guard
                .as_ref()
                .is_some_and(|s| s.account_index == req.index && s.mweb.is_none())
            {
                None
            } else {
                activate_parked(&mut guard, &mut park, req.index)?
            }
        };
        if let Some(summary) = activated {
            if let Some(state) = guard.as_ref() {
                self.publish_insights(state);
            }
            return Ok(summary);
        }
        drop(guard);
        self.load_locked(root)
    }

    pub fn delete_wallet(
        &self,
        root: &Path,
        req: DeleteWalletRequest,
    ) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        if reg.accounts.len() <= 1 {
            return Err(WalletError::Meta(
                "cannot delete the last wallet; wipe the device instead".into(),
            ));
        }
        if reg.get(req.index).is_none() {
            return Err(WalletError::NotFound);
        }
        let switching = reg.active_index == req.index;
        reg.accounts.retain(|a| a.index != req.index);
        if switching {
            reg.active_index = reg.accounts[0].index;
        }
        // Close the sqlite connection before deleting the directory.
        self.discard_resident(req.index)?;
        accounts::remove_account_dir(root, req.index)?;
        accounts::write_registry(root, &reg)?;
        if switching {
            self.load(root)
        } else {
            self.summary()
        }
    }

    pub fn create_wallet_account(
        &self,
        root: &Path,
        req: CreateAccountRequest,
    ) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        let index = reg.next_free_index();
        let name = {
            let trimmed = req.name.trim();
            if trimmed.is_empty() {
                format!("Wallet {index}")
            } else {
                trimmed.to_string()
            }
        };

        let template = {
            let guard = self.lock_state()?;
            let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
            meta_from_state(state)
        };

        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let account_dir = accounts::account_dir(root, index);
        let meta = accounts::meta_for_new_account(&template, index);
        if let Err(e) = open_created_account(&account_dir, &secret, &meta) {
            let _ = accounts::remove_account_dir(root, index);
            return Err(e);
        }

        reg.accounts.push(accounts::AccountEntry { index, name });
        reg.active_index = index;
        accounts::write_registry(root, &reg)?;
        self.load(root)
    }

    /// Dry-run transferring one coin to another account under the same seed.
    pub fn preview_transfer_coin(
        &self,
        root: &Path,
        req: TransferCoinRequest,
    ) -> Result<TransferCoinPreview, WalletError> {
        self.ensure_unlocked()?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let sealing = self.secrets.sealing_key();
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let prepared = {
            let mut park = self.lock_park()?;
            prepare_transfer(
                root,
                state,
                &secret,
                sealing,
                &req,
                DestAddressMode::Preview,
                &mut park,
            )?
        };
        finish_transfer_preview(state, prepared)
    }

    /// Broadcast transferring one coin to another account under the same seed.
    ///
    /// Signs and reserves the coin under the wallet lock, then broadcasts
    /// without it. Peer and Electrum round-trips must not block a split or
    /// another coin's transfer.
    pub fn transfer_coin(
        &self,
        root: &Path,
        req: TransferCoinRequest,
    ) -> Result<TransferCoinResult, WalletError> {
        self.ensure_unlocked()?;
        let (commit_handle, prepared) = {
            let mut guard = self.lock_state()?;
            let commit_handle = self.capture_commit_handle()?;
            let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
            let mut park = self.lock_park()?;
            let prepared = prepare_transfer_broadcast(
                root,
                state,
                &commit_handle.secret,
                commit_handle.sealing_key.clone(),
                &req,
                &mut park,
                &self.session,
            )?;
            (commit_handle, prepared)
        };
        match prepared {
            PreparedTransferBroadcast::Public {
                source_dir,
                electrum_candidates,
                electrum_validate_domain,
                tx,
                fee_sats,
                address,
                to_account_index,
                hold,
            } => {
                let (client, _) =
                    electrum::connect_first(&electrum_candidates, electrum_validate_domain)?;
                client.transaction_broadcast(&tx).map_err(|e| {
                    WalletError::Electrum(crate::error::humanize_broadcast_error(&e.to_string()))
                })?;
                let result = self.commit_public_transfer(
                    &source_dir,
                    &commit_handle,
                    tx,
                    fee_sats,
                    address,
                    to_account_index,
                );
                if result.is_err() {
                    hold.defuse();
                } else {
                    drop(hold);
                }
                result
            }
            PreparedTransferBroadcast::Private {
                source_dir,
                signed,
                route,
                address,
                to_account_index,
                hold,
            } => {
                mweb::broadcast_mweb_tx(&signed.tx, &route)?;
                let result = self.commit_private_transfer(
                    &source_dir,
                    &commit_handle,
                    &signed,
                    address,
                    to_account_index,
                );
                if result.is_err() {
                    hold.defuse();
                } else {
                    drop(hold);
                }
                result
            }
        }
    }

    pub fn needs_migration(&self) -> bool {
        self.secrets.needs_migration()
    }

    pub fn unlock(&self, req: UnlockRequest) -> Result<(), WalletError> {
        match self.secrets.unlock(&req.passphrase) {
            Ok(()) => {
                self.session_epoch.fetch_add(1, Ordering::AcqRel);
                diag::log(
                    "lock-state: Locked -> UnlockedEmpty event=Unlock reason=passphrase verified",
                );
                Ok(())
            }
            Err(err) => {
                diag::log(format!(
                    "lock-state: rejected Unlock from=Locked reason={err}"
                ));
                Err(err)
            }
        }
    }

    /// Re-verify the wallet passphrase and return the stored recovery secret for display.
    ///
    /// Always re-decrypts (does not trust an already-unlocked session). Plaintext
    /// legacy stores (awaiting migration) have no passphrase to check.
    pub fn reveal_mnemonic(
        &self,
        req: RevealMnemonicRequest,
    ) -> Result<RevealMnemonicResponse, WalletError> {
        self.ensure_unlocked()?;
        if self.secrets.needs_migration() {
            // Plaintext store — nothing to verify against.
        } else {
            self.secrets.verify_passphrase(&req.passphrase)?;
        }
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let (phrase, aezeed_passphrase) = secret.backup_material();
        Ok(RevealMnemonicResponse {
            kind: secret.kind().to_string(),
            phrase: phrase.to_string(),
            aezeed_passphrase: aezeed_passphrase.map(|p| p.to_string()),
        })
    }

    /// Lock immediately: wipe the decrypted mnemonic, then drop in-memory wallet
    /// state if the state mutex is free. When another operation holds the mutex,
    /// set [`Self::pending_lock`]; its [`StateGuard`] drops the state on release.
    ///
    /// Does **not** block on an in-flight sync.
    pub fn lock(&self) {
        let was_unlocked = !self.secrets.is_locked();
        let had_pending = self.pending_lock.load(Ordering::Acquire);
        self.session_epoch.fetch_add(1, Ordering::AcqRel);
        self.secrets.lock();
        self.clear_insights();
        if let Ok(mut slot) = self.detached_mweb.lock() {
            *slot = None;
        }
        self.mweb_detached_cv.notify_all();
        self.pending_lock.store(true, Ordering::Release);
        // Parked accounts hold signing keys too. Drop them even when sync still
        // has the active wallet; its StateGuard drops that one on the way out.
        self.clear_park();
        match self.state.try_lock() {
            Ok(mut guard) => {
                let had_loaded = guard.take().is_some();
                self.release_dir_lock();
                self.pending_lock.store(false, Ordering::Release);
                if had_loaded {
                    let from = if had_pending { "LockPending" } else { "Loaded" };
                    diag::log(format!(
                        "lock-state: {from} -> Locked event=Lock reason=lock requested"
                    ));
                } else if was_unlocked {
                    diag::log(
                        "lock-state: UnlockedEmpty -> Locked event=Lock reason=lock requested",
                    );
                }
            }
            Err(TryLockError::WouldBlock) => {
                // A holder has the state and drops it on release; secrets are already cleared.
                diag::log(
                    "lock-state: Loaded -> LockPending event=LockWhileHeld reason=state mutex held",
                );
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut guard = poisoned.into_inner();
                let had_loaded = guard.take().is_some();
                self.release_dir_lock();
                self.pending_lock.store(false, Ordering::Release);
                if had_loaded {
                    diag::log("lock-state: Loaded -> Locked event=Lock reason=lock requested");
                } else if was_unlocked {
                    diag::log(
                        "lock-state: UnlockedEmpty -> Locked event=Lock reason=lock requested",
                    );
                }
            }
        }
    }

    /// Lock was pressed (still pending) or the secrets are already locked.
    fn lock_requested(&self) -> bool {
        self.pending_lock.load(Ordering::Acquire) || self.secrets.is_locked()
    }

    /// Finish a lock after the state holder has dropped the active wallet.
    fn finish_lock(&self) {
        self.session_epoch.fetch_add(1, Ordering::AcqRel);
        self.clear_park();
        self.release_dir_lock();
        self.clear_insights();
        if let Ok(mut slot) = self.detached_mweb.lock() {
            *slot = None;
        }
        self.mweb_detached_cv.notify_all();
        self.secrets.lock();
        self.pending_lock.store(false, Ordering::Release);
    }

    pub fn migrate_encrypt(&self, req: MigrateEncryptRequest) -> Result<(), WalletError> {
        self.secrets.migrate_encrypt(&req.passphrase)
    }

    /// Delete all accounts, registry, and mnemonic secret. Safe if already absent.
    pub fn wipe(&self, data_dir: &Path) -> Result<(), WalletError> {
        let _gate = self.lock_account_load()?;
        if data_dir.exists() {
            self.acquire_dir_lock(data_dir)?;
        }
        self.session_epoch.fetch_add(1, Ordering::AcqRel);
        *self.lock_state_raw()? = None;
        self.clear_park();
        self.clear_insights();
        self.clear_detached_mweb();
        self.forget_electrum();
        self.secrets.delete_mnemonic()?;
        accounts::remove_all_accounts(data_dir)?;
        crate::fs_atomic::sweep_temp_files(data_dir);
        self.release_dir_lock();
        let _ = std::fs::remove_file(data_dir.join(mweb_frozen::WALLET_LOCK_FILE));
        Ok(())
    }

    pub fn create(
        &self,
        data_dir: &Path,
        req: CreateWalletRequest,
        passphrase: &str,
    ) -> Result<CreateWalletResponse, WalletError> {
        let mnemonic = descriptors::generate_mnemonic()?;
        let secret = MasterSecret::parse(&mnemonic, None)?;
        let summary = self.create_or_restore(
            data_dir,
            &secret,
            req.network,
            req.electrum_url,
            passphrase,
            MwebScheme::default(),
        )?;
        Ok(CreateWalletResponse {
            mnemonic: mnemonic.to_string(),
            summary,
        })
    }

    pub fn restore(
        &self,
        data_dir: &Path,
        req: RestoreWalletRequest,
        passphrase: &str,
    ) -> Result<WalletSummary, WalletError> {
        let secret = MasterSecret::parse(&req.mnemonic, req.aezeed_passphrase.as_deref())?;
        self.create_or_restore(
            data_dir,
            &secret,
            req.network,
            req.electrum_url.clone(),
            passphrase,
            req.mweb_scheme,
        )
    }

    pub fn load(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        let _gate = self.lock_account_load()?;
        self.load_locked(data_dir)
    }

    /// Load the registry's active account from disk.
    ///
    /// Caller holds [`Self::account_load`]. The wallet mutex is held across the
    /// sqlite and MWEB open so a split commit, which writes those files after
    /// broadcasting without the lock, cannot interleave. The account this
    /// replaces stays parked when it is a different index.
    fn load_locked(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        if !self.exists(data_dir) {
            return Err(WalletError::NotFound);
        }
        self.acquire_dir_lock(data_dir)?;
        crate::fs_atomic::sweep_temp_files(data_dir);
        accounts::ensure_layout(data_dir)?;
        if let Ok(reg) = accounts::read_registry(data_dir) {
            for entry in &reg.accounts {
                let dir = accounts::account_dir(data_dir, entry.index);
                crate::fs_atomic::sweep_temp_files(&dir);
                let _ = mweb_frozen::clear_stale(&dir, &self.session);
            }
        }
        let account_dir = accounts::active_account_dir(data_dir)?;
        let mut guard = self.lock_state()?;
        let state = self.read_account_state(&account_dir)?;
        crate::discovery::warm_mweb_peers_in_background(state.network);
        guard.check_lock()?;
        let summary = {
            let mut park = self.lock_park()?;
            install_loaded(&mut guard, &mut park, state)?
        };
        if let Some(active) = guard.as_ref() {
            self.publish_insights(active);
        }
        Ok(summary)
    }

    /// Open every other account into the park, one at a time.
    ///
    /// Does not hold the active-wallet mutex while MWEB opens. A switch to an
    /// account this is already opening waits on [`Self::account_load`] and
    /// then uses the parked state instead of a second sqlite connection.
    pub fn warm_other_accounts(&self, root: &Path) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        self.acquire_dir_lock(root)?;
        accounts::ensure_layout(root)?;
        let reg = accounts::read_registry(root)?;
        for entry in &reg.accounts {
            if self.secrets.is_locked() {
                return Ok(());
            }
            let _gate = self.lock_account_load()?;
            if self.secrets.is_locked() {
                return Ok(());
            }
            match self.warm_skip(entry.index)? {
                WarmSkip::Stop => break,
                WarmSkip::This => continue,
                WarmSkip::Open => {}
            }
            let state = self.read_account_state(&accounts::account_dir(root, entry.index))?;
            self.park_if_cold(state)?;
        }
        Ok(())
    }

    fn read_account_state(&self, account_dir: &Path) -> Result<WalletState, WalletError> {
        crate::fs_atomic::sweep_temp_files(account_dir);
        let meta = meta::read_meta(account_dir)?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        mweb_frozen::clear_stale(account_dir, &self.session)?;
        let mut state = open_wallet_state(account_dir, &meta, &secret, self.secrets.sealing_key())?;
        // A hop can expire or land while the wallet is locked, or the process may
        // have died mid-persist / mid-churn. Reconcile before anyone lists coins.
        let _ = reconcile_churn_on_load(&mut state);
        Ok(state)
    }

    pub fn summary(&self) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        build_summary(state)
    }

    pub fn combined_summary(&self) -> Result<CombinedSummary, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let transparent = build_summary(state)?;
        if let Some(ref mut mweb) = state.mweb {
            mweb.combined_summary(&state.wallet, transparent)
        } else if let Some(view) = self.detached_mweb_view() {
            Ok(view.into_combined(transparent))
        } else {
            Ok(CombinedSummary {
                transparent,
                mweb_confirmed_sats: 0,
                mweb_unconfirmed_sats: 0,
                mweb_immature_sats: 0,
                mweb_maturity_blocks: bdk_mweb::MWEB_PEGIN_MATURITY,
                mweb_total_sats: 0,
                mweb_receive_address: None,
                mweb_synced_height: None,
                mweb_stale: true,
                mweb_status: "MWEB unavailable".into(),
            })
        }
    }

    pub fn transactions(&self) -> Result<Vec<TxRecord>, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let tip = state.wallet.local_chain().tip().height();
        let split_ids = split_ids::read_ids(&state.data_dir)
            .map(|f| f.txids)
            .unwrap_or_default();
        let mut records: Vec<TxRecord> = state
            .wallet
            .transactions()
            .map(|tx| {
                let (sent, received) = state.wallet.sent_and_received(&tx.tx);
                let fee_sats = state.wallet.calculate_fee(&tx.tx).ok().map(|f| f.to_sat());
                let sent_sats = sent.to_sat();
                let received_sats = received.to_sat();
                let net_sats = i64::try_from(received_sats)
                    .unwrap_or(i64::MAX)
                    .saturating_sub(i64::try_from(sent_sats).unwrap_or(i64::MAX));
                let (height, confirmations, timestamp) = match &tx.pos {
                    ChainPosition::Confirmed { anchor, .. } => {
                        let h = anchor.block_id.height;
                        let confs = tip.saturating_sub(h).saturating_add(1);
                        (Some(h), confs, Some(anchor.confirmation_time))
                    }
                    ChainPosition::Unconfirmed { first_seen, .. } => (None, 0, *first_seen),
                };
                let txid = tx.txid.to_string();
                let kind = if split_ids.contains(&txid) {
                    TxKind::Split
                } else {
                    TxKind::Transparent
                };
                TxRecord {
                    txid,
                    net_sats,
                    sent_sats,
                    received_sats,
                    fee_sats,
                    height,
                    confirmations,
                    timestamp,
                    kind,
                    maturity_blocks_left: None,
                    can_clear: false,
                }
            })
            .collect();
        if let Some(ref mweb) = state.mweb {
            merge_mweb_history(&mut records, mweb, tip);
        }
        records.sort_by(|a, b| match (a.height, b.height) {
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, None) => b.timestamp.cmp(&a.timestamp),
            (Some(ha), Some(hb)) => hb.cmp(&ha).then_with(|| b.txid.cmp(&a.txid)),
        });
        Ok(records)
    }

    /// Reveal and persist the next external receive address.
    ///
    /// Always advances the derivation index so callers (UI "New address", CLI)
    /// get a fresh address even when earlier revealed addresses are still unused.
    pub fn receive_address(&self) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let address = state
            .wallet
            .reveal_next_address(KeychainKind::External)
            .to_string();
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(address)
    }

    pub fn mweb_receive_address(&self) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let addr = mweb.receive_address(state.network)?;
        mweb.persist(&state.data_dir)?;
        Ok(addr)
    }

    pub fn settings(&self) -> Result<WalletSettings, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(WalletSettings {
            electrum_url: state.electrum_url.clone(),
            electrum_validate_domain: state.electrum_validate_domain,
            electrum_use_public_fallback: state.electrum_use_public_fallback,
            auto_lock_minutes: state.auto_lock_minutes,
            electrum_active_url: state.active_electrum_url.clone(),
            litecoin_rpc_url: state.litecoin_rpc_url.clone(),
            broadcast_via_own_node: state.broadcast_via_own_node,
            mweb_peers: state.mweb_peers.clone(),
            mweb_scheme: state.mweb_scheme,
            explorer_base_url: state.explorer_base_url.clone(),
            show_fiat: state.show_fiat,
            use_explorer_fee_hints: state.use_explorer_fee_hints,
            insights_enabled: state.insights_enabled,
        })
    }

    /// True when `address` is a revealed BIP84 receive/change address that has been used.
    /// MWEB stealth addresses always return `reused: false` (reuse is expected).
    pub fn address_reuse_hint(&self, address: &str) -> Result<AddressReuseHint, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(compute_address_reuse_hint(&state.wallet, address))
    }

    pub fn get_tx_labels(&self) -> Result<std::collections::HashMap<String, String>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(labels::read_labels(&state.data_dir)?.labels)
    }

    pub fn set_tx_label(&self, req: SetTxLabelRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        labels::set_label(&state.data_dir, &req.txid, &req.label)
    }

    /// Non-secret history export (CSV or JSON). Excludes mnemonic and settings secrets.
    pub fn export_history(
        &self,
        format: crate::HistoryExportFormat,
    ) -> Result<String, WalletError> {
        let txs = self.transactions()?;
        let labels = self.get_tx_labels()?;
        crate::history_export::render(format, &txs, &labels)
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(contacts::read_contacts(&state.data_dir)?.contacts)
    }

    pub fn upsert_contact(&self, req: UpsertContactRequest) -> Result<ContactRecord, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        contacts::upsert_contact(
            &state.data_dir,
            state.network,
            req.id.as_deref(),
            &req.name,
            &req.address,
            req.kind,
        )
    }

    pub fn delete_contact(&self, req: DeleteContactRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        contacts::delete_contact(&state.data_dir, &req.id)
    }

    /// List transparent unspent outputs for coin control.
    pub fn list_unspent(&self) -> Result<Vec<UtxoRecord>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(collect_unspent(state))
    }

    /// Freeze or unfreeze a transparent UTXO (persisted in the wallet DB).
    pub fn set_utxo_locked(&self, req: SetUtxoLockedRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        set_public_freeze(state, req)
    }

    /// Freeze or unfreeze a private (MWEB) coin (wipeable sidecar).
    pub fn set_mweb_utxo_locked(&self, req: SetMwebUtxoLockedRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let _ = state
            .mweb
            .as_ref()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        set_private_freeze(state, req)
    }

    /// Set or clear a local UTXO label (non-secret sidecar).
    pub fn set_utxo_label(&self, req: SetUtxoLabelRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        utxo_labels::set_label(&state.data_dir, &req.outpoint, &req.label)
    }

    /// Export contacts + tx/utxo labels as pretty JSON (no secrets).
    pub fn export_metadata_json(&self) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        metadata::export_json(&state.data_dir)
    }

    /// Merge a metadata JSON bundle into local sidecars.
    pub fn import_metadata_json(&self, json: &str) -> Result<MetadataImportResult, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        metadata::import_json(&state.data_dir, json)
    }

    /// Probe an Electrum URL (or the configured one) for tip + latency.
    pub fn test_electrum(&self, url: Option<String>) -> Result<ElectrumProbe, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let url = url
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| state.electrum_url.clone());
        meta::validate_electrum_url(&url)?;
        let (tip_height, latency_ms) =
            electrum::probe_tip(&url, state.electrum_validate_domain, state.network)?;
        Ok(ElectrumProbe {
            url,
            tip_height,
            latency_ms,
        })
    }

    /// Built-in Electrum-LTC candidates for the loaded wallet's network.
    pub fn default_electrum_urls(&self) -> Result<Vec<String>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(state
            .network
            .default_electrum_urls()
            .iter()
            .map(|s| (*s).to_string())
            .collect())
    }

    pub fn update_settings(&self, req: UpdateSettingsRequest) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        meta::validate_electrum_url(&req.electrum_url)?;
        let explorer_base_url = crate::explorer::normalize_base_url(&req.explorer_base_url)?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let electrum_url = req.electrum_url.trim().to_string();
        if electrum_url != state.electrum_url
            || req.electrum_use_public_fallback != state.electrum_use_public_fallback
        {
            let protected = state
                .mweb
                .as_ref()
                .map(|mweb| pegin_txids(&mweb.history))
                .unwrap_or_default();
            spv::evict_unconfirmed_on_server_switch(
                &mut state.wallet,
                &mut state.db,
                &state.data_dir,
                &electrum_url,
                &protected,
            )?;
        }
        state.electrum_url = electrum_url;
        state.electrum_validate_domain = req.electrum_validate_domain;
        state.electrum_use_public_fallback = req.electrum_use_public_fallback;
        state.auto_lock_minutes = req.auto_lock_minutes;
        // New configured server should be tried first on the next connection.
        state.active_electrum_url = None;
        self.forget_electrum();
        state.litecoin_rpc_url = req
            .litecoin_rpc_url
            .map(|s| crate::rpc::normalize_rpc_url(&s))
            .filter(|s| !s.is_empty());
        state.broadcast_via_own_node = req.broadcast_via_own_node;
        state.mweb_peers = req
            .mweb_peers
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        state.explorer_base_url = explorer_base_url;
        state.show_fiat = req.show_fiat;
        state.use_explorer_fee_hints = req.use_explorer_fee_hints;
        state.insights_enabled = req.insights_enabled;
        self.publish_insights(state);
        meta::write_meta(&state.data_dir, &meta_from_state(state))?;
        Ok(())
    }

    /// Build a litview `/explorer/tx/{txid}` URL (no network).
    pub fn explorer_tx_url(&self, txid: &str) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        crate::explorer::tx_url(&state.explorer_base_url, txid)
    }

    /// Build a litview `/explorer/block/{hash}` URL (no network).
    pub fn explorer_block_url(&self, block_hash: &str) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        crate::explorer::block_url(&state.explorer_base_url, block_hash)
    }

    /// Fetch tx details from the explorer; mark wallet IO locally.
    pub fn fetch_tx_detail(&self, txid: &str) -> Result<crate::dto::TxEnrichment, WalletError> {
        self.ensure_unlocked()?;
        let (base, addresses) = {
            let guard = self.lock_state()?;
            let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
            (
                state.explorer_base_url.clone(),
                revealed_address_set(&state.wallet),
            )
        };
        crate::explorer::fetch_tx_detail(&base, txid, &addresses)
    }

    /// Spot LTC/USD from the explorer mempool price endpoint.
    pub fn fetch_spot_price(&self) -> Result<f64, WalletError> {
        self.ensure_unlocked()?;
        let base = {
            let guard = self.lock_state()?;
            let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
            state.explorer_base_url.clone()
        };
        crate::explorer::fetch_spot_price(&base)
    }

    /// Fee ladder suggestions from the explorer.
    pub fn fetch_fee_ladder(&self) -> Result<crate::dto::FeeLadder, WalletError> {
        self.ensure_unlocked()?;
        let base = {
            let guard = self.lock_state()?;
            let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
            if !state.use_explorer_fee_hints {
                return Err(WalletError::Meta(
                    "explorer fee hints are disabled in Settings".into(),
                ));
            }
            state.explorer_base_url.clone()
        };
        crate::explorer::fetch_fee_ladder(&base)
    }

    fn require_insights_enabled(&self) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let guard = self
            .insights_endpoint
            .lock()
            .map_err(|_| WalletError::Persist("insights endpoint lock poisoned".into()))?;
        let endpoint = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        if !endpoint.enabled {
            return Err(WalletError::Insights(
                "Insights are disabled in Settings".into(),
            ));
        }
        Ok(endpoint.base_url.clone())
    }

    /// Litview network pulse for Balance strip / Insights header.
    pub fn fetch_network_pulse(&self) -> Result<crate::dto::NetworkPulse, WalletError> {
        let base = self.require_insights_enabled()?;
        crate::insights::fetch_network_pulse(&base)
    }

    /// Allowlisted litview metric series for Insights charts.
    pub fn fetch_insight_charts(&self) -> Result<Vec<crate::dto::MetricSeries>, WalletError> {
        let base = self.require_insights_enabled()?;
        crate::insights::fetch_insight_charts(&base)
    }

    /// Refresh the active account's transparent chain while the wallet is locked.
    ///
    /// Opens the public BDK database only (no mnemonic, no signer, no MWEB).
    /// Persists when the chain extended in place. A lower tip or a replaced
    /// header is left unpersisted so the unlocked sync can disconnect MWEB.
    ///
    /// Returns `Ok(true)` when an Electrum pass finished and was saved.
    /// Returns `Ok(false)` when there is nothing to do (already unlocked, no
    /// wallet, a session is loaded) or the update was discarded as a reorg.
    /// Network failures are `Err` and leave the database unchanged.
    pub fn prefetch_transparent(&self, data_dir: &Path) -> Result<bool, WalletError> {
        if !self.secrets.is_locked() || !self.exists(data_dir) {
            return Ok(false);
        }
        let (account_dir, mut meta, mut wallet, prev_height, prev_hash, tx_count_before) = {
            let guard = self.lock_state_gate()?;
            if !self.secrets.is_locked() || guard.is_some() {
                return Ok(false);
            }
            accounts::ensure_layout(data_dir)?;
            let account_dir = accounts::active_account_dir(data_dir)?;
            let meta = meta::read_meta(&account_dir)?;
            let mut db = Connection::open(meta::db_path(&account_dir))
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            let params =
                bdk_wallet::Wallet::load().check_network(meta.network.to_bitcoin_network());
            let wallet = PersistedWallet::load(&mut db, params)
                .map_err(|e| WalletError::Persist(e.to_string()))?
                .ok_or(WalletError::NotFound)?;

            let prev = wallet.latest_checkpoint();
            let prev_height = prev.height();
            let prev_hash = prev.hash();
            let tx_count_before = wallet.transactions().count();
            (
                account_dir,
                meta,
                wallet,
                prev_height,
                prev_hash,
                tx_count_before,
            )
        };

        // Warm MWEB peer discovery in the background while the user is on the
        // unlock screen so the subsequent unlocked sync does not wait on DNS crawl.
        crate::discovery::warm_mweb_peers_in_background(meta.network);

        // Prefetch only warms the chain; the sync after it reports Done.
        // The state mutex is released during network I/O so `unlock` + `load`
        // never blocks waiting for a slow Electrum prefetch.
        let pass = self.sync_pass();
        let prefer = self.remembered_electrum();
        let (client, used) = connect_from_meta(&meta, prefer.as_deref())?;
        if !self.secrets.is_locked() {
            pass.finish_prefetch();
            return Ok(false);
        }

        let full_scan = meta.needs_full_scan;
        pass.electrum(full_scan);
        // MWEB history is sealed while locked; the SPV state keeps the peg-ins
        // an unlocked sync recorded.
        let prepared = match spv::prepare_electrum_spv(
            &wallet,
            &client.inner,
            meta.network,
            &account_dir,
            &used,
            &HashSet::new(),
        ) {
            Ok(prepared) => prepared,
            Err(e) => {
                self.forget_electrum();
                return Err(e);
            }
        };
        if !self.secrets.is_locked() {
            pass.finish_prefetch();
            return Ok(false);
        }

        let prep_tip_height = prepared.tip_height();
        let prep_tip_hash = prepared.tip_hash();
        let cached_cross = self.cached_cross_check(&used, prep_tip_height, prep_tip_hash);
        let all_candidates = electrum_candidate_list(
            prefer.as_deref(),
            &meta.electrum_url,
            meta.electrum_use_public_fallback,
            meta.network,
        );
        let alt_electrum = if cached_cross.is_some() {
            None
        } else {
            all_candidates.iter().find(|url| *url != &used).cloned()
        };
        let verified_hashes = if alt_electrum.is_some() {
            prepared.verified_chain_hashes()
        } else {
            HashMap::new()
        };
        let validate_domain = meta.electrum_validate_domain;

        let (outcome_res, cross_res) = std::thread::scope(|scope| {
            let cross_handle = alt_electrum.map(|alt| {
                scope.spawn(move || {
                    let local_hash_at = |height: u32| verified_hashes.get(&height).copied();
                    electrum::cross_check_tip(
                        &alt,
                        validate_domain,
                        prep_tip_height,
                        &local_hash_at,
                    )
                })
            });
            let outcome = spv::finish_electrum_spv_with_shards(
                &mut wallet,
                &client.inner,
                prepared,
                full_scan,
                Some(&self.electrum_progress),
                &all_candidates,
                validate_domain,
            );
            let cross = cross_handle.and_then(|h| h.join().ok());
            (outcome, cross)
        });

        let outcome = match outcome_res {
            Ok(outcome) => outcome,
            Err(e) => {
                self.forget_electrum();
                return Err(e);
            }
        };
        self.remember_electrum(used.clone());
        if !self.secrets.is_locked() {
            pass.finish_prefetch();
            return Ok(false);
        }

        if !chain_extended_in_place(&wallet, prev_height, prev_hash) {
            diag::log("prefetch: electrum update looked like a reorg; not persisting");
            pass.finish_prefetch();
            return Ok(false);
        }

        let guard = self.lock_state_gate()?;
        if !self.secrets.is_locked() || guard.is_some() {
            pass.finish_prefetch();
            return Ok(false);
        }
        if accounts::active_account_dir(data_dir).ok().as_ref() != Some(&account_dir)
            || !meta::db_path(&account_dir).exists()
        {
            pass.finish_prefetch();
            return Ok(false);
        }
        let mut db = Connection::open(meta::db_path(&account_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        wallet
            .persist(&mut db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        outcome.persist_state()?;
        if full_scan {
            meta.needs_full_scan = false;
            meta::write_meta(&account_dir, &meta)?;
        }
        drop(db);
        drop(guard);

        let tx_count_after = wallet.transactions().count();
        let latest = wallet.latest_checkpoint();
        if let Some(Ok(warning)) = cross_res {
            self.note_cross_check(used.clone(), latest.height(), latest.hash(), warning);
        }
        self.note_fresh_prefetch(FreshPrefetch {
            account_dir,
            server_url: used,
            tip_height: latest.height(),
            tip_hash: latest.hash(),
            tip_time: outcome.tip_time,
            new_txs: tx_count_after.saturating_sub(tx_count_before) as u32,
            completed_at: std::time::Instant::now(),
        });
        pass.finish_prefetch();
        Ok(true)
    }

    /// Receive address from the on-disk public descriptor. Does not unlock and
    /// does not keep the wallet in memory.
    #[cfg(test)]
    fn watch_only_receive_address(data_dir: &Path) -> Result<String, WalletError> {
        accounts::ensure_layout(data_dir)?;
        let account_dir = accounts::active_account_dir(data_dir)?;
        let meta = meta::read_meta(&account_dir)?;
        let mut db = Connection::open(meta::db_path(&account_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = bdk_wallet::Wallet::load().check_network(meta.network.to_bitcoin_network());
        let mut wallet = PersistedWallet::load(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?
            .ok_or(WalletError::NotFound)?;
        Ok(current_receive_address(&mut wallet))
    }

    fn log_sync_failure(err: WalletError) -> WalletError {
        diag::log(format!("sync: failed: {err}"));
        err
    }

    /// Cross-check and MWEB download without the wallet mutex, so public sends
    /// can use the transparent wallet Electrum just persisted (or is scanning).
    fn run_detached_stage(
        &self,
        mut parked: ParkedMweb,
        cancel: Option<&AtomicBool>,
    ) -> DetachedMwebDone {
        let stage_started = std::time::Instant::now();
        let mut warnings = Vec::new();
        if let Some(warning) = parked.cached_warning.clone() {
            warnings.push(warning);
        }
        let mut cross_ms = 0u64;
        let mut mweb_ms = 0u64;
        std::thread::scope(|scope| {
            let cross_handle = if parked.run_cross_check {
                parked.alt_electrum.clone().map(|alt| {
                    let hashes = parked.local_chain_hashes.clone();
                    let validate_domain = parked.validate_domain;
                    let tip_height = parked.tip_height;
                    scope.spawn(move || {
                        let started = std::time::Instant::now();
                        let local_hash_at = |height: u32| hashes.get(&height).copied();
                        let outcome = electrum::cross_check_tip(
                            &alt,
                            validate_domain,
                            tip_height,
                            &local_hash_at,
                        );
                        (outcome, started.elapsed().as_millis() as u64)
                    })
                })
            } else {
                None
            };

            if parked.runtime.is_some() {
                diag::log("sync: mweb download starting");
                let mweb_started = std::time::Instant::now();
                let tip_height = parked.tip_height;
                let tip_hash = parked.tip_hash;
                let prev_tip_hash = parked.prev_tip_hash;
                let peers = parked.peers.clone();
                let network = parked.network;
                let hold_spent = parked.hold_spent.clone();
                let pending_lock = &self.pending_lock;
                let epoch_ref = &self.session_epoch;
                let start_epoch = self.detached_mweb_epoch.load(Ordering::Acquire);
                let epoch_check = (start_epoch != 0).then_some((epoch_ref, start_epoch));
                self.with_mweb_progress(|progress| {
                    if let Some(mweb) = parked.runtime.as_mut() {
                        let _ = mweb.sync_at_tip_cancellable(
                            tip_height,
                            tip_hash,
                            prev_tip_hash,
                            &peers,
                            network,
                            Some(progress),
                            &hold_spent,
                            cancel,
                            Some(pending_lock),
                            epoch_check,
                        );
                    }
                });
                if let Some(warning) = parked
                    .runtime
                    .as_ref()
                    .and_then(|mweb| mweb.cross_check_warning.clone())
                {
                    warnings.push(warning);
                }
                mweb_ms = mweb_started.elapsed().as_millis() as u64;
                diag::log(format!("sync: mweb finished in {mweb_ms} ms"));
            }

            if let Some(handle) = cross_handle {
                if let Ok((outcome, elapsed)) = handle.join() {
                    cross_ms = elapsed;
                    if let Ok(warning) = outcome {
                        if let Some(ref found) = warning {
                            warnings.insert(0, found.clone());
                        }
                        self.note_cross_check(
                            parked.used_server.clone(),
                            parked.tip_height,
                            parked.tip_hash,
                            warning,
                        );
                    }
                }
            }
        });
        let mweb_wall_ms = stage_started.elapsed().as_millis() as u64;
        diag::log(format!("sync: cross-check tip ms={cross_ms}"));
        DetachedMwebDone {
            parked,
            warnings,
            mweb_ms,
            cross_ms,
            mweb_wall_ms,
        }
    }

    pub fn sync(&self) -> Result<SyncResult, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let sync_started = std::time::Instant::now();
        let pass = self.sync_pass();
        let state = guard
            .as_mut()
            .ok_or(WalletError::NotLoaded)
            .map_err(Self::log_sync_failure)?;

        let tx_count_before = state.wallet.transactions().count();
        let did_full_scan = state.needs_full_scan;
        let prev_tip = state.last_tip_height;
        let current_cp = state.wallet.latest_checkpoint();

        let (
            used,
            used_server,
            electrum_ms,
            electrum_reused,
            prefetched_new_txs,
            mut lazy_client,
            account_dir,
            done,
            mweb_wait_ms,
        ) = if let Some(prefetched) = self.take_fresh_prefetch(
            &state.data_dir,
            current_cp.height(),
            current_cp.hash(),
            did_full_scan,
        ) {
            pass.electrum(false);
            let used = prefetched.server_url;
            state.active_electrum_url = Some(used.clone());
            self.remember_electrum(used.clone());
            diag::log(format!(
                "sync: electrum reused from prefetch tip={} ms=0",
                prefetched.tip_height
            ));
            let tip_height = state.wallet.latest_checkpoint().height();
            let tip_hash = state.wallet.latest_checkpoint().hash();
            if tip_height < prev_tip {
                if let Some(ref mut mweb) = state.mweb {
                    mweb.disconnect_from(tip_height.saturating_add(1));
                }
            } else if let Some(ref mut mweb) = state.mweb {
                reconcile_mweb_chain_with_wallet(&state.wallet, mweb);
            }
            state.last_tip_height = tip_height;
            if prefetched.tip_height == tip_height {
                state.tip_time = Some(prefetched.tip_time);
                state.tip_time_height = tip_height;
            } else if state.tip_time_height != tip_height {
                state.tip_time = None;
            }
            if did_full_scan {
                state.needs_full_scan = false;
            }
            guard.check_lock().map_err(Self::log_sync_failure)?;
            let (
                used_server,
                cached_cross_hit,
                cached_warning,
                alt_electrum,
                validate_domain,
                local_chain_hashes,
                prev_tip_hash,
                peers,
                network,
                account_dir,
                hold_spent,
            ) = {
                let state = guard
                    .as_mut()
                    .ok_or(WalletError::NotLoaded)
                    .map_err(Self::log_sync_failure)?;
                let used_server = state
                    .active_electrum_url
                    .clone()
                    .unwrap_or_else(|| state.electrum_url.clone());
                let cached_cross = self.cached_cross_check(&used_server, tip_height, tip_hash);
                let cached_warning = cached_cross.clone().flatten();
                let alt_electrum = if cached_cross.is_some() {
                    None
                } else {
                    electrum_candidates(state)
                        .into_iter()
                        .find(|url| *url != used_server)
                };
                let validate_domain = state.electrum_validate_domain;
                let local_chain_hashes: HashMap<u32, BlockHash> = if alt_electrum.is_some() {
                    state
                        .wallet
                        .local_chain()
                        .iter_checkpoints()
                        .map(|cp| (cp.height(), cp.hash()))
                        .collect()
                } else {
                    HashMap::new()
                };
                let prev_tip_hash = state.mweb.as_ref().and_then(|mweb| {
                    mweb.sync_state
                        .tip_height
                        .and_then(|h| state.wallet.local_chain().get(h))
                        .map(|cp| cp.hash())
                });
                let peers = state.mweb_peers.clone();
                let network = state.network;
                let account_dir = state.data_dir.clone();
                let hold_spent = churn::held_unbroadcast_spends(&state.data_dir);
                (
                    used_server,
                    cached_cross.is_some(),
                    cached_warning,
                    alt_electrum,
                    validate_domain,
                    local_chain_hashes,
                    prev_tip_hash,
                    peers,
                    network,
                    account_dir,
                    hold_spent,
                )
            };
            let runtime = if self.in_flight_broadcasts.load(Ordering::Acquire) == 0 {
                self.park_mweb(&mut guard).map_err(Self::log_sync_failure)?
            } else {
                None
            };
            if runtime.is_some() {
                pass.mweb();
            }
            self.transparent_ready.store(true, Ordering::Release);
            drop(guard);
            let wait_started = std::time::Instant::now();
            let done = self.run_detached_stage(
                ParkedMweb {
                    runtime,
                    tip_height,
                    tip_hash,
                    prev_tip_hash,
                    peers,
                    network,
                    hold_spent,
                    alt_electrum,
                    validate_domain,
                    local_chain_hashes,
                    used_server: used_server.clone(),
                    cached_warning,
                    run_cross_check: !cached_cross_hit,
                },
                None,
            );
            let mweb_wait_ms = wait_started.elapsed().as_millis() as u64;
            (
                used,
                used_server,
                0u64,
                true,
                prefetched.new_txs,
                None,
                account_dir,
                done,
                mweb_wait_ms,
            )
        } else {
            let electrum_started = std::time::Instant::now();
            let prefer = self.remembered_electrum();
            let client = connect_electrum_prefer(state, prefer.as_deref())
                .map_err(Self::log_sync_failure)?;
            let used = state
                .active_electrum_url
                .clone()
                .unwrap_or_else(|| state.electrum_url.clone());

            pass.electrum(did_full_scan);
            let protected = state
                .mweb
                .as_ref()
                .map(|mweb| pegin_txids(&mweb.history))
                .unwrap_or_default();
            let prepared = match spv::prepare_electrum_spv(
                &state.wallet,
                &client.inner,
                state.network,
                &state.data_dir,
                &used,
                &protected,
            ) {
                Ok(prepared) => prepared,
                Err(e) => {
                    self.forget_electrum();
                    state.active_electrum_url = None;
                    return Err(Self::log_sync_failure(e));
                }
            };

            let tip_height = prepared.tip_height();
            let tip_hash = prepared.tip_hash();
            let agreement = prepared.agreement();
            let verified_hashes = prepared.verified_chain_hashes();
            let prev_mweb_snap = state.mweb.as_ref().map(|m| {
                (
                    m.stale,
                    m.last_status.clone(),
                    m.cross_check_warning.clone(),
                )
            });

            if let Some(ref mut mweb) = state.mweb {
                if tip_height < prev_tip {
                    mweb.disconnect_from(tip_height.saturating_add(1));
                } else if agreement < prev_tip {
                    mweb.disconnect_from(agreement.saturating_add(1));
                } else if let Some(mweb_tip) = mweb.sync_state.tip_height {
                    if mweb_tip > tip_height {
                        mweb.disconnect_from(tip_height.saturating_add(1));
                    } else if let Some(mweb_hash) = mweb.sync_state.tip_hash {
                        if verified_hashes
                            .get(&mweb_tip)
                            .is_some_and(|&h| h != mweb_hash)
                        {
                            mweb.disconnect_from(mweb_tip);
                        }
                    }
                }
            }

            guard.check_lock().map_err(Self::log_sync_failure)?;

            let (
                used_server,
                cached_cross_hit,
                cached_warning,
                alt_electrum,
                validate_domain,
                local_chain_hashes,
                prev_tip_hash,
                peers,
                network,
                account_dir,
                hold_spent,
                all_candidates,
            ) = {
                let state = guard
                    .as_mut()
                    .ok_or(WalletError::NotLoaded)
                    .map_err(Self::log_sync_failure)?;
                let used_server = state
                    .active_electrum_url
                    .clone()
                    .unwrap_or_else(|| state.electrum_url.clone());
                let cached_cross = self.cached_cross_check(&used_server, tip_height, tip_hash);
                let cached_warning = cached_cross.clone().flatten();
                let all_candidates = electrum_candidates(state);
                let alt_electrum = if cached_cross.is_some() {
                    None
                } else {
                    all_candidates
                        .iter()
                        .find(|url| *url != &used_server)
                        .cloned()
                };
                let validate_domain = state.electrum_validate_domain;
                let prev_tip_hash = state.mweb.as_ref().and_then(|mweb| {
                    mweb.sync_state
                        .tip_height
                        .and_then(|h| verified_hashes.get(&h).copied())
                });
                let local_chain_hashes = if alt_electrum.is_some() {
                    verified_hashes
                } else {
                    HashMap::new()
                };
                let peers = state.mweb_peers.clone();
                let network = state.network;
                let account_dir = state.data_dir.clone();
                let hold_spent = churn::held_unbroadcast_spends(&state.data_dir);
                (
                    used_server,
                    cached_cross.is_some(),
                    cached_warning,
                    alt_electrum,
                    validate_domain,
                    local_chain_hashes,
                    prev_tip_hash,
                    peers,
                    network,
                    account_dir,
                    hold_spent,
                    all_candidates,
                )
            };

            let runtime = if self.in_flight_broadcasts.load(Ordering::Acquire) == 0 {
                self.park_mweb(&mut guard).map_err(Self::log_sync_failure)?
            } else {
                None
            };
            let has_mweb = runtime.is_some();

            // Overlap MWEB download + tip cross-check with Electrum script/tx/anchor scan.
            let cancel = AtomicBool::new(false);
            let (electrum_ms, done, mweb_wait_ms) = std::thread::scope(|scope| {
                let used_for_stage = used_server.clone();
                let cancel_ref = &cancel;
                #[cfg(test)]
                let test_ctx = mweb::capture_test_context();
                let mweb_handle = scope.spawn(move || {
                    #[cfg(test)]
                    mweb::install_test_context(test_ctx);
                    self.run_detached_stage(
                        ParkedMweb {
                            runtime,
                            tip_height,
                            tip_hash,
                            prev_tip_hash,
                            peers,
                            network,
                            hold_spent,
                            alt_electrum,
                            validate_domain,
                            local_chain_hashes,
                            used_server: used_for_stage,
                            cached_warning,
                            run_cross_check: !cached_cross_hit,
                        },
                        Some(cancel_ref),
                    )
                });

                let electrum_step: Result<u64, (WalletError, bool)> = (|| {
                    let state = guard.as_mut().ok_or((WalletError::NotLoaded, false))?;
                    let outcome = spv::finish_electrum_spv_with_shards(
                        &mut state.wallet,
                        &client.inner,
                        prepared,
                        did_full_scan,
                        Some(&self.electrum_progress),
                        &all_candidates,
                        validate_domain,
                    )
                    .map_err(|e| (e, true))?;

                    let persist_started = std::time::Instant::now();
                    let persisted = state
                        .wallet
                        .persist(&mut state.db)
                        .map_err(|e| WalletError::Persist(e.to_string()))
                        .and_then(|_| outcome.persist_state());
                    diag::log(format!(
                        "sync: electrum persist ms={}",
                        persist_started.elapsed().as_millis() as u64
                    ));
                    persisted.map_err(|e| (e, false))?;
                    note_pegin_chain_status(state, &outcome.unreported_protected)
                        .map_err(|e| (e, false))?;
                    self.remember_electrum(used.clone());
                    crate::crashpoint::maybe_crash("sync_after_electrum_persist");
                    let electrum_ms = electrum_started.elapsed().as_millis() as u64;

                    state.last_tip_height = tip_height;
                    if outcome.tip_height == tip_height {
                        state.tip_time = Some(outcome.tip_time);
                        state.tip_time_height = tip_height;
                    } else if state.tip_time_height != tip_height {
                        state.tip_time = None;
                    }
                    if did_full_scan {
                        state.needs_full_scan = false;
                    }
                    Ok(electrum_ms)
                })();

                let step_res = match electrum_step {
                    Ok(ms) => match guard.check_lock() {
                        Ok(()) => Ok(ms),
                        Err(lock_err) => Err((lock_err, false)),
                    },
                    Err(pair) => Err(pair),
                };

                match step_res {
                    Ok(electrum_ms) => {
                        if has_mweb {
                            pass.mweb();
                        }
                        // Public commands block on this mutex. Release it before waiting on MWEB.
                        self.transparent_ready.store(true, Ordering::Release);
                        drop(guard);
                        let wait_started = std::time::Instant::now();
                        let done = mweb_handle
                            .join()
                            .map_err(|_| WalletError::Mweb("MWEB sync thread panicked".into()))
                            .map_err(Self::log_sync_failure)?;
                        let mweb_wait_ms = wait_started.elapsed().as_millis() as u64;
                        Ok((electrum_ms, done, mweb_wait_ms))
                    }
                    Err((err, forget_server)) => {
                        cancel.store(true, Ordering::Release);
                        if forget_server {
                            // A server that failed verification is not tried first again.
                            self.forget_electrum();
                            if let Some(state) = guard.as_mut() {
                                state.active_electrum_url = None;
                            }
                        }
                        // Drop `guard` before joining `mweb_handle` so the wallet mutex is never
                        // held while waiting for the background MWEB thread to unwind.
                        drop(guard);
                        if let Ok(done) = mweb_handle.join() {
                            if let Some(mut runtime) = done.parked.runtime {
                                if let Some((stale, status, warn)) = prev_mweb_snap {
                                    runtime.stale = stale;
                                    runtime.last_status = status;
                                    runtime.cross_check_warning = warn;
                                }
                                if self.restore_parked_mweb(&account_dir, runtime).is_ok() {
                                    if let Ok(mut g) = self.lock_state() {
                                        if let Some(state) = g.as_mut() {
                                            if state.data_dir == account_dir {
                                                if let Some(mweb) = state.mweb.as_mut() {
                                                    reconcile_mweb_chain_with_wallet(
                                                        &state.wallet,
                                                        mweb,
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                self.clear_detached_mweb();
                            }
                        } else {
                            self.clear_detached_mweb();
                        }
                        Err(Self::log_sync_failure(err))
                    }
                }
            })?;

            (
                used,
                used_server,
                electrum_ms,
                false,
                0u32,
                Some(client),
                account_dir,
                done,
                mweb_wait_ms,
            )
        };

        let DetachedMwebDone {
            parked,
            warnings,
            mweb_ms,
            cross_ms,
            mweb_wall_ms,
        } = done;
        let mut warnings = warnings;
        if let Some(runtime) = parked.runtime {
            self.restore_parked_mweb(&account_dir, runtime)
                .map_err(Self::log_sync_failure)?;
        }
        guard = self.lock_state().map_err(Self::log_sync_failure)?;
        {
            let state = guard
                .as_mut()
                .ok_or(WalletError::NotLoaded)
                .map_err(Self::log_sync_failure)?;
            let had_mweb = state.mweb.is_some();
            if had_mweb && state.needs_mweb_scan {
                state.needs_mweb_scan = false;
            }
            if let Some(mweb) = state.mweb.as_mut() {
                reconcile_mweb_chain_with_wallet(&state.wallet, mweb);
                let dir = state.data_dir.clone();
                let _ = mweb.persist(&dir);
            }
        }

        guard.check_lock().map_err(Self::log_sync_failure)?;
        let state = guard
            .as_mut()
            .ok_or(WalletError::NotLoaded)
            .map_err(Self::log_sync_failure)?;
        let churn_started = std::time::Instant::now();
        if state.mweb.is_some() {
            if lazy_client.is_none()
                && churn::read_job(&state.data_dir)
                    .ok()
                    .flatten()
                    .is_some_and(|job| {
                        matches!(
                            job.phase(),
                            ChurnPhase::WaitingConfirm | ChurnPhase::PausedUnscored
                        )
                    })
            {
                lazy_client = connect_electrum_prefer(state, Some(used.as_str())).ok();
            }
            let _ = drive_churn(state, lazy_client.as_ref());
        }
        let churn_ms = churn_started.elapsed().as_millis() as u64;
        diag::log(format!("sync: churn ms={churn_ms}"));

        guard.check_lock().map_err(Self::log_sync_failure)?;
        let state = guard
            .as_mut()
            .ok_or(WalletError::NotLoaded)
            .map_err(Self::log_sync_failure)?;

        // Repair peg-ins that credited MWEB without spending transparent UTXOs
        // (bug in earlier builds). Prefer Electrum raw tx; fall back to RPC.
        // Dropped peg-ins are not in `missing`: their outputs were wiped, so
        // this has to run even when there is nothing to re-fetch.
        let repair_started = std::time::Instant::now();
        if state.mweb.is_some() {
            clear_unproven_pegin_heights(state);
            forget_dropped_pegins(state);
        }
        let missing = missing_pegin_ids(state);
        let fallbacks = missing
            .iter()
            .filter(|id| self.pegin_fallback_due(id))
            .count();
        let missing_pegins = missing.len();
        let repaired = if state.mweb.is_some() && !missing.is_empty() {
            if lazy_client.is_none() {
                lazy_client = Some(
                    connect_electrum_prefer(state, Some(used.as_str()))
                        .map_err(Self::log_sync_failure)?,
                );
            }
            repair_missing_pegin_spends(self, state, lazy_client.as_ref().unwrap())
        } else {
            Ok(None)
        };
        let repair_ms = repair_started.elapsed().as_millis() as u64;
        diag::log(format!(
            "sync: pegin-repair missing={missing_pegins} fallbacks={fallbacks} ms={repair_ms}"
        ));
        if let Some(repair_warning) = repaired.map_err(Self::log_sync_failure)? {
            warnings.push(repair_warning);
        }

        meta::write_meta(&state.data_dir, &meta_from_state(state))
            .map_err(Self::log_sync_failure)?;

        let tx_count_after = state.wallet.transactions().count();
        let new_txs = prefetched_new_txs
            .saturating_add(tx_count_after.saturating_sub(tx_count_before) as u32);
        let summary_started = std::time::Instant::now();
        let summary = build_summary(state);
        let summary_ms = summary_started.elapsed().as_millis() as u64;
        diag::log(format!("sync: summary ms={summary_ms}"));
        let summary = summary.map_err(Self::log_sync_failure)?;
        guard.check_lock().map_err(Self::log_sync_failure)?;
        pass.finish();
        let total_ms = sync_started.elapsed().as_millis() as u64;
        diag::log(format!(
            "sync: done electrum_ms={electrum_ms} mweb_ms={mweb_ms} new_txs={new_txs} \
             total_ms={total_ms} electrum_reused={electrum_reused} mweb_wall_ms={mweb_wall_ms} \
             mweb_wait_ms={mweb_wait_ms} cross_ms={cross_ms} churn_ms={churn_ms} \
             repair_ms={repair_ms} summary_ms={summary_ms}"
        ));
        Ok(SyncResult {
            summary,
            new_txs,
            electrum_ms,
            mweb_ms,
            electrum_server: used_server,
            warnings,
        })
    }

    pub fn resync_mweb(&self) -> Result<(), WalletError> {
        self.resync_mweb_inner(None)
    }

    /// Switch the MWEB derivation scheme and rescan under it. Wipes local
    /// MWEB state (coins are re-discovered from the chain); transparent
    /// wallet data is untouched.
    pub fn set_mweb_scheme(&self, scheme: MwebScheme) -> Result<(), WalletError> {
        self.resync_mweb_inner(Some(scheme))
    }

    fn resync_mweb_inner(&self, new_scheme: Option<MwebScheme>) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        let mut guard = self.lock_state()?;
        let pass = self.sync_pass();
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        if let Some(scheme) = new_scheme {
            state.mweb_scheme = scheme;
        }
        state.needs_mweb_scan = true;
        meta::write_meta(&state.data_dir, &meta_from_state(state))?;
        // History survives the wipe. Copy coin heights onto it first, or every
        // spent receive and peg-in comes back as pending.
        if let Some(mweb) = state.mweb.as_mut() {
            mweb::stamp_known_history_heights(&mut mweb.history, mweb.store.db());
            mweb.persist(&state.data_dir)?;
        }
        mweb::wipe_mweb_files(&state.data_dir)?;
        crate::crashpoint::maybe_crash("resync_mweb_after_wipe");
        // A manual resync usually means something looked wrong, so re-crawl
        // rather than reusing peers that may be part of the problem.
        crate::discovery::clear_cache();
        state.mweb = Some(MwebRuntime::open(
            &state.data_dir,
            &secret,
            state.network,
            state.mweb_scheme.to_master_scheme(),
            state.account_index,
            self.secrets.sealing_key(),
        )?);
        let tip_height = state.wallet.latest_checkpoint().height();
        let tip_hash = state.wallet.latest_checkpoint().hash();
        if let Some(ref mut mweb) = state.mweb {
            pass.mweb();
            diag::log("resync_mweb: mweb download starting");
            let peers = state.mweb_peers.clone();
            let network = state.network;
            let hold_spent = churn::held_unbroadcast_spends(&state.data_dir);
            // Fresh runtime after wipe: no previous sync state, so no extension hint.
            let pending_lock = &self.pending_lock;
            let epoch_ref = &self.session_epoch;
            let start_epoch = self.session_epoch.load(Ordering::Acquire);
            self.with_mweb_progress(|progress| {
                let _ = mweb.sync_at_tip_cancellable(
                    tip_height,
                    tip_hash,
                    None,
                    &peers,
                    network,
                    Some(progress),
                    &hold_spent,
                    None,
                    Some(pending_lock),
                    Some((epoch_ref, start_epoch)),
                );
            });
            mweb.persist(&state.data_dir)?;
        }
        guard.check_lock()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        state.needs_mweb_scan = false;
        meta::write_meta(&state.data_dir, &meta_from_state(state))?;
        pass.finish();
        Ok(())
    }

    /// Estimate a network fee rate (sat/vB) from Electrum.
    pub fn estimate_fee(&self) -> Result<FeeEstimate, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let client = connect_electrum(state)?;
        let (fee_rate_sat_vb, is_fallback) = electrum::estimate_fee_rate_sat_vb(&client)?;
        Ok(FeeEstimate {
            fee_rate_sat_vb,
            is_fallback,
        })
    }

    /// Build a send without broadcasting; returns absolute fee and recipient amount.
    pub fn preview_send(&self, req: SendRequest) -> Result<SendPreview, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (fee_rate_sat_vb, psbt, recipient_script) = build_send_psbt(state, &req)?;
        let fee_sats = psbt
            .fee_amount()
            .ok_or_else(|| WalletError::BuildTx("unable to compute fee".into()))?
            .to_sat();
        let amount_sats = if req.drain {
            psbt.unsigned_tx
                .output
                .iter()
                .find(|o| o.script_pubkey == recipient_script)
                .map(|o| o.value.to_sat())
                .unwrap_or(0)
        } else {
            req.amount_sats
        };
        // Persist any change-address reveal staged by the builder.
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let creates_change = psbt.unsigned_tx.output.len() > 1;
        Ok(SendPreview {
            amount_sats,
            fee_sats,
            fee_rate_sat_vb,
            creates_change,
        })
    }

    pub fn send(&self, req: SendRequest) -> Result<SendResult, WalletError> {
        self.ensure_unlocked()?;
        // Sign under the lock, then broadcast without it. Electrum connect and
        // broadcast can take long enough that sync and other spends must not wait.
        let (
            data_dir,
            electrum_candidates,
            electrum_validate_domain,
            tx,
            fee_sats,
            hold,
            commit_handle,
        ) = {
            let mut guard = self.lock_state()?;
            let commit_handle = self.capture_commit_handle()?;
            let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;

            let (_fee_rate_sat_vb, mut psbt, _recipient_script) = build_send_psbt(state, &req)?;
            sign_and_finalize(&state.wallet, &state.signer, &mut psbt)?;

            let fee_sats = psbt
                .fee_amount()
                .ok_or_else(|| WalletError::BuildTx("unable to compute fee".into()))?
                .to_sat();
            let tx = psbt
                .extract_tx()
                .map_err(|e| WalletError::BuildTx(e.to_string()))?;
            let outpoints: Vec<_> = tx.input.iter().map(|input| input.previous_output).collect();
            let hold = CoinHold::take_public(&state.data_dir, outpoints, &self.session)?;
            (
                state.data_dir.clone(),
                electrum_candidates(state),
                state.electrum_validate_domain,
                tx,
                fee_sats,
                hold,
                commit_handle,
            )
        };

        let (client, _) = electrum::connect_first(&electrum_candidates, electrum_validate_domain)?;
        client.transaction_broadcast(&tx).map_err(|e| {
            WalletError::Electrum(crate::error::humanize_broadcast_error(&e.to_string()))
        })?;

        let result = self.commit_public_send(&data_dir, &commit_handle, tx, fee_sats);
        if result.is_err() {
            hold.defuse();
        } else {
            drop(hold);
        }
        result
    }

    fn commit_public_send(
        &self,
        source_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        tx: Transaction,
        fee_sats: u64,
    ) -> Result<SendResult, WalletError> {
        let txid = tx.compute_txid().to_string();
        // Keep local balance honest until the next sync sees the broadcast.
        self.with_account_wallet(source_dir, handle, |wallet, db| {
            wallet.apply_unconfirmed_txs([(tx.clone(), crate::mweb_history::now_ts())]);
            wallet
                .persist(db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            Ok(())
        })?;
        Ok(SendResult { txid, fee_sats })
    }

    pub fn preview_pegin(&self, req: PeginRequest) -> Result<PeginPreview, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let resolved = resolve_pegin_request(state, req)?;
        let total_from_transparent_sats = crate::tx_invariants::checked_add_money(
            resolved.amount_sats,
            resolved.transparent_fee_sats,
            "peg-in transparent total",
        )?;
        let creates_change =
            pegin_selection_creates_change(state, &resolved, total_from_transparent_sats);
        Ok(PeginPreview {
            amount_sats: resolved.amount_sats,
            private_credit_sats: resolved.amount_sats.saturating_sub(resolved.mweb_fee_sats),
            mweb_fee_sats: resolved.mweb_fee_sats,
            transparent_fee_sats: resolved.transparent_fee_sats,
            total_from_transparent_sats,
            creates_change,
            maturity_blocks: bdk_mweb::MWEB_PEGIN_MATURITY,
        })
    }

    pub fn pegin(&self, req: PeginRequest) -> Result<PeginResult, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let req = resolve_pegin_request(state, req)?;
        let route = broadcast_route(state);
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let result = mweb::pegin(&mut state.wallet, &state.signer, mweb, &route, req)?;
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        mweb.persist(&state.data_dir)?;
        Ok(result)
    }

    /// Drop a peg-in that no peer accepted, and return its transparent inputs.
    pub fn clear_pegin(&self, txid: &str) -> Result<(), WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        clear_unrelayed_pegin(state, txid)
    }

    pub fn preview_mweb_send(&self, req: MwebSendRequest) -> Result<MwebSendPreview, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let resolved = resolve_mweb_send_request(state, req)?;
        Ok(MwebSendPreview {
            amount_sats: resolved.amount_sats,
            fee_sats: resolved.fee_sats,
            creates_change: mweb_selection_creates_change(state, &resolved)?,
        })
    }

    pub fn mweb_send(&self, req: MwebSendRequest) -> Result<MwebBroadcastResult, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        // Sign under the lock, then broadcast without it so a transfer or split
        // of a different coin can start while peers are still being tried.
        let (data_dir, signed, route, hold, commit_handle) = {
            let mut guard = self.lock_state()?;
            let commit_handle = self.capture_commit_handle()?;
            let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
            let req = resolve_mweb_send_request(state, req)?;
            let route = broadcast_route(state);
            let network = state.network;
            let data_dir = state.data_dir.clone();
            let mweb = state
                .mweb
                .as_mut()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let signed = mweb::sign_mweb_send(&state.wallet, mweb, &data_dir, &req, network)?;
            let hold = CoinHold::take(&data_dir, signed.input_ids(), &self.session)?;
            (data_dir, signed, route, hold, commit_handle)
        };
        mweb::broadcast_mweb_tx(&signed.tx, &route)?;
        let result = self.with_account_mweb(&data_dir, &commit_handle, |runtime| {
            Ok(mweb::apply_signed_mweb_send(runtime, &signed))
        });
        if result.is_err() {
            hold.defuse();
        } else {
            drop(hold);
        }
        result
    }

    pub fn preview_pegout(&self, req: PegoutRequest) -> Result<PegoutPreview, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (resolved, dust_sats) = resolve_pegout_request(state, req)?;
        pegout_preview_from_resolved(&resolved, dust_sats, state)
    }

    pub fn pegout(&self, req: PegoutRequest) -> Result<MwebBroadcastResult, WalletError> {
        self.ensure_unlocked()?;
        self.refuse_if_mweb_detached()?;
        // Sign under the lock, then broadcast without it: the peer loop can take
        // minutes, and sync, coin lists and other spends must not wait on it.
        let (data_dir, signed, route, hold, commit_handle) = self.sign_pegout(req)?;
        mweb::broadcast_mweb_tx(&signed.tx, &route)?;
        let result = self.with_account_mweb(&data_dir, &commit_handle, |runtime| {
            Ok(mweb::apply_signed_pegout(runtime, &signed))
        });
        if result.is_err() {
            hold.defuse();
        } else {
            drop(hold);
        }
        result
    }

    fn sign_pegout(
        &self,
        req: PegoutRequest,
    ) -> Result<
        (
            PathBuf,
            mweb::SignedPegout,
            mweb::BroadcastRoute,
            CoinHold,
            AccountCommitHandle<'_>,
        ),
        WalletError,
    > {
        let mut guard = self.lock_state()?;
        let commit_handle = self.capture_commit_handle()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (mut req, _) = resolve_pegout_request(state, req)?;
        let mut reveal_up_to = None;
        if req.per_coin {
            let n = req.output_amounts.len();
            if n == 0 {
                return Err(WalletError::BuildTx(
                    "per-coin peg-out needs at least one public output".into(),
                ));
            }
            let start_idx = state.wallet.next_derivation_index(KeychainKind::External);
            let mut addresses = Vec::with_capacity(n);
            for i in 0..n {
                let idx = start_idx.checked_add(i as u32).ok_or_else(|| {
                    WalletError::BuildTx("external address index overflowed".into())
                })?;
                reveal_up_to = Some(idx);
                addresses.push(
                    state
                        .wallet
                        .peek_address(KeychainKind::External, idx)
                        .address
                        .to_string(),
                );
            }
            req.addresses = addresses;
        } else if req.address.trim().is_empty() {
            return Err(WalletError::InvalidAddress(
                "peg-out destination address required".into(),
            ));
        }
        let route = broadcast_route(state);
        let network = state.network;
        let data_dir = state.data_dir.clone();
        let signed = {
            let mweb = state
                .mweb
                .as_mut()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            mweb::sign_pegout(&state.wallet, mweb, &data_dir, req, network)?
        };
        let hold = CoinHold::take(&data_dir, signed.input_ids(), &self.session)?;
        if let Some(end_idx) = reveal_up_to {
            let _ = state
                .wallet
                .reveal_addresses_to(KeychainKind::External, end_idx)
                .count();
            state
                .wallet
                .persist(&mut state.db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
        }
        Ok((data_dir, signed, route, hold, commit_handle))
    }

    pub fn list_mweb_unspent(&self) -> Result<Vec<MwebUtxoRecord>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let mweb = state
            .mweb
            .as_ref()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let tip = state.wallet.latest_checkpoint().height();
        Ok(mweb::list_mweb_unspent(mweb, tip, &state.data_dir))
    }

    /// Lab-only: 32-byte scan/spend hex plus the current MWEB receive address.
    /// Callers must write this to a chmod 600 file and never log the hex.
    pub fn export_mweb_coinswapd_secrets(
        &self,
    ) -> Result<(Zeroizing<String>, Zeroizing<String>, String), WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let mut scan_bytes = mweb.keys.scan.secret_bytes();
        let scan = Zeroizing::new(hex::encode(scan_bytes));
        scan_bytes.zeroize();
        let mut spend_bytes = mweb.keys.spend.secret_bytes();
        let spend = Zeroizing::new(hex::encode(spend_bytes));
        spend_bytes.zeroize();
        let dest = mweb.receive_address(state.network)?;
        mweb.persist(&state.data_dir)?;
        Ok((scan, spend, dest))
    }

    pub fn preview_split(&self, req: SplitRequest) -> Result<SplitPreview, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        plan_split_request(state, &req)
    }

    pub fn split_coin(&self, req: SplitRequest) -> Result<SplitResult, WalletError> {
        self.ensure_unlocked()?;
        // Sign under the lock, then broadcast without it. Peer and Electrum
        // round-trips take long enough that an account switch must not wait
        // on them. The coin is reserved first so a switch cannot spend it.
        let (commit_handle, prepared) = {
            let mut guard = self.lock_state()?;
            let commit_handle = self.capture_commit_handle()?;
            let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
            let prepared = prepare_split(state, &req, &self.session)?;
            (commit_handle, prepared)
        };
        match prepared {
            PreparedSplit::Public {
                source_dir,
                electrum_candidates,
                electrum_validate_domain,
                tx,
                fee_sats,
                output_count,
                hold,
            } => {
                let (client, _) =
                    electrum::connect_first(&electrum_candidates, electrum_validate_domain)?;
                client.transaction_broadcast(&tx).map_err(|e| {
                    WalletError::Electrum(crate::error::humanize_broadcast_error(&e.to_string()))
                })?;
                let result = self.commit_public_split(
                    &source_dir,
                    &commit_handle,
                    tx,
                    fee_sats,
                    output_count,
                );
                if result.is_err() {
                    hold.defuse();
                } else {
                    drop(hold);
                }
                result
            }
            PreparedSplit::Private {
                source_dir,
                signed,
                route,
                hold,
            } => {
                mweb::broadcast_mweb_tx(&signed.tx, &route)?;
                let result = self.commit_private_split(&source_dir, &commit_handle, &signed);
                if result.is_err() {
                    hold.defuse();
                } else {
                    drop(hold);
                }
                result
            }
        }
    }

    fn commit_public_split(
        &self,
        source_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        tx: Transaction,
        fee_sats: u64,
        output_count: u32,
    ) -> Result<SplitResult, WalletError> {
        let txid = tx.compute_txid().to_string();
        self.with_account_wallet(source_dir, handle, |wallet, db| {
            wallet.apply_unconfirmed_txs([(tx.clone(), crate::mweb_history::now_ts())]);
            wallet
                .persist(db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            Ok(())
        })?;
        split_ids::record_txid(source_dir, &txid)?;
        Ok(SplitResult {
            txid,
            fee_sats,
            output_count,
        })
    }

    fn commit_private_split(
        &self,
        source_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        signed: &mweb::SignedMwebSplit,
    ) -> Result<SplitResult, WalletError> {
        let result = signed.result();
        self.with_account_mweb(source_dir, handle, |runtime| {
            mweb::apply_signed_mweb_split(runtime, signed);
            Ok(())
        })?;
        Ok(result)
    }

    fn commit_public_transfer(
        &self,
        source_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        tx: Transaction,
        fee_sats: u64,
        address: String,
        to_account_index: u32,
    ) -> Result<TransferCoinResult, WalletError> {
        let txid = tx.compute_txid().to_string();
        self.with_account_wallet(source_dir, handle, |wallet, db| {
            wallet.apply_unconfirmed_txs([(tx.clone(), crate::mweb_history::now_ts())]);
            wallet
                .persist(db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            Ok(())
        })?;
        Ok(TransferCoinResult {
            txid,
            fee_sats,
            address,
            to_account_index,
        })
    }

    fn commit_private_transfer(
        &self,
        source_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        signed: &mweb::SignedMwebSend,
        address: String,
        to_account_index: u32,
    ) -> Result<TransferCoinResult, WalletError> {
        let result = signed.result();
        self.with_account_mweb(source_dir, handle, |runtime| {
            Ok(mweb::apply_signed_mweb_send(runtime, signed))
        })?;
        Ok(TransferCoinResult {
            txid: result.wtxid,
            fee_sats: result.fee_sats,
            address,
            to_account_index,
        })
    }

    /// Run `f` on the account at `data_dir`. Uses the loaded wallet when that
    /// account is still active, otherwise opens the account files.
    fn with_account_wallet<T>(
        &self,
        data_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        f: impl FnOnce(&mut PersistedWallet<Connection>, &mut Connection) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        // Gate before the state lock: warm holds the gate, then the state lock.
        let _gate = self.lock_account_load()?;
        if let Ok(mut guard) = self.lock_state() {
            let active = guard
                .as_ref()
                .is_some_and(|state| state.data_dir == data_dir);
            if active {
                let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
                return f(&mut state.wallet, &mut state.db);
            }
            {
                let mut park = self.lock_park()?;
                if let Some(state) = park.get_mut_by_dir(data_dir) {
                    return f(&mut state.wallet, &mut state.db);
                }
            }
        }
        let meta = meta::read_meta(data_dir)?;
        let mut db = Connection::open(meta::db_path(data_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = load_params(&handle.secret, meta.network, meta.account_index)?;
        let mut wallet = PersistedWallet::load(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?
            .ok_or(WalletError::NotFound)?;
        f(&mut wallet, &mut db)
    }

    /// Run `f` on the MWEB store at `data_dir`, then persist it.
    fn with_account_mweb<T>(
        &self,
        data_dir: &Path,
        handle: &AccountCommitHandle<'_>,
        f: impl FnOnce(&mut MwebRuntime) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let _gate = self.lock_account_load()?;
        if let Ok(mut guard) = self.lock_state() {
            let active = guard
                .as_ref()
                .is_some_and(|state| state.data_dir == data_dir);
            if active {
                let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
                if let Some(mweb) = state.mweb.as_mut() {
                    let out = f(mweb)?;
                    mweb.persist(data_dir)?;
                    return Ok(out);
                }
                // `state.mweb` was detached by `park_mweb`. Open from disk using
                // the pre-broadcast commit handle, persist, and re-install into
                // `state.mweb` while invalidating the detached epoch so a later
                // stale `restore_parked_mweb` cannot overwrite this spend.
                let meta = meta::read_meta(data_dir)?;
                let mut mweb = MwebRuntime::open(
                    data_dir,
                    &handle.secret,
                    meta.network,
                    meta.mweb_scheme.to_master_scheme(),
                    meta.account_index,
                    handle.sealing_key.clone(),
                )?;
                let out = f(&mut mweb)?;
                mweb.persist(data_dir)?;
                state.mweb = Some(mweb);
                self.clear_detached_mweb();
                return Ok(out);
            }
            {
                let mut park = self.lock_park()?;
                if let Some(state) = park.get_mut_by_dir(data_dir) {
                    let dir = state.data_dir.clone();
                    if let Some(mweb) = state.mweb.as_mut() {
                        let out = f(mweb)?;
                        mweb.persist(&dir)?;
                        return Ok(out);
                    }
                    let meta = meta::read_meta(&dir)?;
                    let mut mweb = MwebRuntime::open(
                        &dir,
                        &handle.secret,
                        meta.network,
                        meta.mweb_scheme.to_master_scheme(),
                        meta.account_index,
                        handle.sealing_key.clone(),
                    )?;
                    let out = f(&mut mweb)?;
                    mweb.persist(&dir)?;
                    state.mweb = Some(mweb);
                    self.clear_detached_mweb();
                    return Ok(out);
                }
            }
        }
        let meta = meta::read_meta(data_dir)?;
        let mut mweb = MwebRuntime::open(
            data_dir,
            &handle.secret,
            meta.network,
            meta.mweb_scheme.to_master_scheme(),
            meta.account_index,
            handle.sealing_key.clone(),
        )?;
        let out = f(&mut mweb)?;
        mweb.persist(data_dir)?;
        mweb.wipe();
        Ok(out)
    }

    pub fn preview_churn(&self, req: ChurnRequest) -> Result<ChurnPreview, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let (info, frozen, job_active, from_pegin) = churn_start_facts(state, &req.output_id)?;
        let hop_fee = self_spend_hop_fee();
        let target = churn::check_start(&churn::StartCheck {
            mature: info.mature,
            frozen,
            amount_sats: info.amount,
            fee_sats: hop_fee,
            job_active,
            target_depth: req.target_depth,
        })?;
        let cover_min = churn::normalize_cover_min(req.cover_min)?;
        let _ = from_pegin;
        Ok(ChurnPreview {
            input_sats: info.amount,
            hop_fee_sats: hop_fee,
            resulting_sats: info.amount - hop_fee,
            target_depth: target,
            total_fee_sats: hop_fee.saturating_mul(target as u64),
            amount_note: CHURN_AMOUNT_NOTE.to_string(),
            quiet_block_note: crate::dto::quiet_block_note(target, hop_fee),
            has_litecoin_rpc: state
                .litecoin_rpc_url
                .as_deref()
                .is_some_and(|url| !url.trim().is_empty()),
            cover_min,
            spread_send: req.spread_send,
        })
    }

    pub fn start_churn(&self, req: ChurnRequest) -> Result<ChurnStatus, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let coin = req.output_id.trim();
        let (info, frozen, job_active, from_pegin) = churn_start_facts(state, &req.output_id)
            .inspect_err(|err| {
                diag::log(format!(
                    "self-spend: rejected Start coin={coin} from=None reason={err}"
                ));
            })?;
        let hop_fee = self_spend_hop_fee();
        let target = churn::check_start(&churn::StartCheck {
            mature: info.mature,
            frozen,
            amount_sats: info.amount,
            fee_sats: hop_fee,
            job_active,
            target_depth: req.target_depth,
        })
        .inspect_err(|err| {
            diag::log(format!(
                "self-spend: rejected Start coin={coin} from=None reason={err}"
            ));
        })?;
        let cover_min = churn::normalize_cover_min(req.cover_min).inspect_err(|err| {
            diag::log(format!(
                "self-spend: rejected Start coin={coin} from=None reason={err}"
            ));
        })?;
        let mut job = churn::new_job(
            &req.output_id,
            from_pegin || info.is_pegin,
            target,
            hop_fee,
            cover_min,
            req.spread_send,
        )?;
        prepare_churn(state, &mut job)?;
        let _ = cover_gate(Some(state));
        let job = churn::read_job(&state.data_dir)?.unwrap_or(job);
        Ok(churn::status_view(&job))
    }

    pub fn churn_status(&self) -> Result<Option<ChurnStatus>, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(churn::read_job(&state.data_dir)?.map(|job| churn::status_view(&job)))
    }

    /// Look at the mempool and broadcast an armed hop when the cover gate opens.
    /// Safe while locked: the signed transaction is already on disk.
    pub fn pump_churn_broadcast(&self, data_dir: &Path) -> Result<(), WalletError> {
        let Some(mut guard) = self.try_lock_state() else {
            return Ok(());
        };
        if let Some(state) = guard.as_mut() {
            let _ = undo_expired_local(state);
            let _ = apply_pending_local(state);
            let _ = cover_gate(Some(state));
        } else {
            let _ = cover_gate_at(None, data_dir);
        }
        Ok(())
    }

    pub fn retry_churn(&self) -> Result<ChurnStatus, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        // The load path also does this. Retry can run on a state that was already
        // open when the armed hop expired, so it has to reconcile before it signs.
        undo_expired_local(state)?;
        let mut job = churn::read_job(&state.data_dir)?.ok_or_else(|| {
            let msg = "There is no self-spend to try again.";
            diag::log(format!(
                "self-spend: rejected Retry job=none from=None reason={msg}"
            ));
            WalletError::BuildTx(msg.into())
        })?;
        churn::request_retry(&mut job)?;
        if job.needs_resign {
            resign_one_hop(state, &mut job)?;
        }
        churn::write_job(&state.data_dir, &job)?;
        let _ = cover_gate(Some(state));
        let job = churn::read_job(&state.data_dir)?
            .ok_or_else(|| WalletError::BuildTx("There is no self-spend to try again.".into()))?;
        // A saved broadcast error stays on the job for the Coins card. It is not a failed command.
        Ok(churn::status_view(&job))
    }

    pub fn cancel_churn(&self) -> Result<ChurnStatus, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let mut job = churn::read_job(&state.data_dir)?.ok_or_else(|| {
            let msg = "There is no self-spend to cancel.";
            diag::log(format!(
                "self-spend: rejected Cancel job=none from=None reason={msg}"
            ));
            WalletError::BuildTx(msg.into())
        })?;
        let shown = job.current_output_id.clone();
        // Reject the transition before recalling the hop. Cancel only changes the
        // phase, so a refusal leaves the coin store and the freeze file alone.
        churn::request_cancel(&mut job)?;
        let has_armed = churn::armed_path(&state.data_dir).is_file();
        if !has_armed {
            mweb_frozen::set_locked(&state.data_dir, &shown, false)?;
        }
        churn::write_job(&state.data_dir, &job)?;
        crate::crashpoint::maybe_crash("cancel_churn_after_write_job");
        revert_unbroadcast_hop(state, &mut job)?;
        let restored = job.current_output_id.clone();
        if restored != shown {
            churn::write_job(&state.data_dir, &job)?;
        }
        mweb_frozen::set_locked(&state.data_dir, &shown, false)?;
        if restored != shown {
            mweb_frozen::set_locked(&state.data_dir, &restored, false)?;
        }
        let _ = churn::remove_armed(&state.data_dir);
        Ok(churn::status_view(&job))
    }

    fn create_or_restore(
        &self,
        data_dir: &Path,
        secret: &MasterSecret,
        network: WalletNetwork,
        electrum_url: Option<String>,
        passphrase: &str,
        mweb_scheme: MwebScheme,
    ) -> Result<WalletSummary, WalletError> {
        if passphrase.trim().is_empty() {
            return Err(WalletError::SecretStore(
                "passphrase must not be empty".into(),
            ));
        }
        if self.exists(data_dir) {
            self.acquire_dir_lock(data_dir)?;
            if self.secrets.get_mnemonic()?.is_none() && !self.secrets.is_locked() {
                self.wipe(data_dir)?;
            } else if self.secrets.is_locked() || self.secrets.get_mnemonic()?.is_some() {
                return Err(WalletError::AlreadyExists);
            } else {
                self.wipe(data_dir)?;
            }
        }
        self.acquire_dir_lock(data_dir)?;

        self.secrets
            .set_with_passphrase(passphrase, &secret.to_stored())?;

        let rollback = |app: &Self| {
            let _ = accounts::remove_all_accounts(data_dir);
            let _ = app.secrets.delete_mnemonic();
            app.clear_insights();
            app.clear_park();
            app.release_dir_lock();
        };

        if let Err(e) = std::fs::create_dir_all(data_dir) {
            rollback(self);
            return Err(e.into());
        }
        let account_dir = match accounts::init_registry_account0(data_dir) {
            Ok(d) => d,
            Err(e) => {
                rollback(self);
                return Err(e);
            }
        };

        let mut meta = WalletMeta::new(network, electrum_url);
        meta.mweb_scheme = mweb_scheme;
        meta.account_index = 0;

        let (wallet, db, meta) = match open_created_account(&account_dir, secret, &meta) {
            Ok(v) => v,
            Err(e) => {
                rollback(self);
                return Err(e);
            }
        };

        let signer_val = match signer(secret, network, 0) {
            Ok(s) => s,
            Err(e) => {
                rollback(self);
                return Err(e);
            }
        };

        let mweb = match MwebRuntime::open(
            &account_dir,
            secret,
            network,
            mweb_scheme.to_master_scheme(),
            0,
            self.secrets.sealing_key(),
        ) {
            Ok(rt) => Some(rt),
            Err(e) => {
                rollback(self);
                return Err(e);
            }
        };

        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer_val,
            db,
            account_index: 0,
            network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            broadcast_via_own_node: meta.broadcast_via_own_node,
            mweb_peers: meta.mweb_peers,
            mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: account_dir,
            needs_full_scan: meta.needs_full_scan,
            needs_mweb_scan: meta.needs_mweb_scan,
            mweb,
        };
        let summary = match build_summary(&mut state) {
            Ok(s) => s,
            Err(e) => {
                drop(state);
                rollback(self);
                return Err(e);
            }
        };
        let mut guard = match self.lock_state() {
            Ok(g) => g,
            Err(e) => {
                drop(state);
                rollback(self);
                return Err(e);
            }
        };
        let from = if guard.is_some() {
            "Loaded"
        } else {
            "UnlockedEmpty"
        };
        self.publish_insights(&state);
        self.clear_park();
        *guard = Some(state);
        diag::log(format!(
            "lock-state: {from} -> Loaded event=Load account=0 reason=wallet created or restored"
        ));
        Ok(summary)
    }

    fn ensure_unlocked(&self) -> Result<(), WalletError> {
        if self.secrets.is_locked() {
            diag::log("lock-state: rejected command from=Locked reason=wallet is locked");
            Err(WalletError::Locked)
        } else {
            Ok(())
        }
    }

    /// Take the wallet state for an operation that needs the wallet unlocked.
    /// Refuses with [`WalletError::Locked`] once Lock was pressed.
    fn lock_state(&self) -> Result<StateGuard<'_>, WalletError> {
        let mut guard = StateGuard {
            inner: self.lock_state_raw()?,
            app: self,
        };
        if guard.inner.is_none()
            && !self.pending_lock.load(Ordering::Acquire)
            && self.secrets.is_locked()
        {
            diag::log("lock-state: rejected acquire from=Locked reason=wallet is locked");
        }
        guard.check_lock()?;
        Ok(guard)
    }

    /// Like [`Self::lock_state`] but does not refuse while locked, for work that
    /// runs before unlock and only needs the mutex as a gate. Releasing it still
    /// drops any state if the wallet is locked.
    fn lock_state_gate(&self) -> Result<StateGuard<'_>, WalletError> {
        Ok(StateGuard {
            inner: self.lock_state_raw()?,
            app: self,
        })
    }

    /// Like [`Self::lock_state`] without waiting, for background work that also
    /// runs while locked. `None` when another holder has the mutex; after Lock
    /// the guard holds no state.
    fn try_lock_state(&self) -> Option<StateGuard<'_>> {
        let inner = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        let mut guard = StateGuard { inner, app: self };
        let _ = guard.check_lock();
        Some(guard)
    }

    /// The bare mutex, skipping the lock check. Only for callers that must work
    /// while locked and leave nothing loaded: `wipe` and `discard_resident`.
    fn lock_state_raw(&self) -> Result<MutexGuard<'_, Option<WalletState>>, WalletError> {
        self.state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))
    }

    fn lock_park(&self) -> Result<MutexGuard<'_, AccountPark>, WalletError> {
        self.parked
            .lock()
            .map_err(|_| WalletError::Persist("wallet park lock poisoned".into()))
    }

    fn lock_account_load(&self) -> Result<MutexGuard<'_, ()>, WalletError> {
        self.account_load
            .lock()
            .map_err(|_| WalletError::Persist("wallet load lock poisoned".into()))
    }

    fn clear_park(&self) {
        if let Ok(mut park) = self.parked.lock() {
            park.clear();
        }
    }

    /// State lock, then park lock. `Stop` once the park is full so a warm does
    /// not derive MWEB keys it would immediately evict.
    fn warm_skip(&self, index: u32) -> Result<WarmSkip, WalletError> {
        let guard = match self.lock_state() {
            Err(WalletError::Locked) => return Ok(WarmSkip::Stop),
            guard => guard?,
        };
        let park = self.lock_park()?;
        if guard.as_ref().is_some_and(|s| s.account_index == index) || park.contains(index) {
            return Ok(WarmSkip::This);
        }
        if park.len() >= PARK_CAP {
            Ok(WarmSkip::Stop)
        } else {
            Ok(WarmSkip::Open)
        }
    }

    /// Drop a loaded account without parking it. Used before its directory is removed.
    ///
    /// Takes the load gate first so a warm cannot be inside `MwebRuntime::open`
    /// for this directory while it is deleted.
    fn discard_resident(&self, index: u32) -> Result<(), WalletError> {
        let _gate = self.lock_account_load()?;
        let mut guard = self.lock_state_raw()?;
        if guard.as_ref().is_some_and(|s| s.account_index == index) {
            *guard = None;
        }
        self.lock_park()?.drop_index(index);
        Ok(())
    }

    /// Park `state` unless lock won, or this account is already the active one
    /// (a switch waited out this warm and will install its own copy).
    fn park_if_cold(&self, state: WalletState) -> Result<(), WalletError> {
        let guard = match self.lock_state() {
            Err(WalletError::Locked) => return Ok(()),
            guard => guard?,
        };
        let mut park = self.lock_park()?;
        if guard
            .as_ref()
            .is_some_and(|active| active.account_index == state.account_index)
        {
            return Ok(());
        }
        park.insert(state);
        Ok(())
    }
}

/// The wallet state mutex, held through [`WalletApp::lock_state`]. If Lock lands
/// while it is held, releasing it drops the signer and wallet, so no holder can
/// leave them in memory after Lock.
struct StateGuard<'a> {
    inner: MutexGuard<'a, Option<WalletState>>,
    app: &'a WalletApp,
}

impl StateGuard<'_> {
    /// Early exit for long operations: drop the state now if Lock was pressed.
    fn check_lock(&mut self) -> Result<(), WalletError> {
        if !self.app.lock_requested() {
            return Ok(());
        }
        let had_pending = self.inner.is_some() || self.app.pending_lock.load(Ordering::Acquire);
        *self.inner = None;
        self.app.finish_lock();
        if had_pending {
            diag::log(
                "lock-state: LockPending -> Locked event=CheckLock reason=holder aborted on pending lock",
            );
        }
        Err(WalletError::Locked)
    }
}

impl std::ops::Deref for StateGuard<'_> {
    type Target = Option<WalletState>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for StateGuard<'_> {
    fn drop(&mut self) {
        if self.app.lock_requested() {
            let had_pending = self.inner.is_some() || self.app.pending_lock.load(Ordering::Acquire);
            *self.inner = None;
            self.app.finish_lock();
            if had_pending {
                diag::log(
                    "lock-state: LockPending -> Locked event=ReleaseGuard reason=holder released state mutex",
                );
            }
        }
    }
}

fn reconcile_mweb_chain_with_wallet(
    wallet: &PersistedWallet<Connection>,
    mweb: &mut MwebRuntime,
) -> bool {
    let wallet_tip = wallet.latest_checkpoint().height();
    let Some(mweb_tip) = mweb.sync_state.tip_height else {
        return false;
    };
    if mweb_tip > wallet_tip {
        mweb.disconnect_from(wallet_tip.saturating_add(1));
        return true;
    }
    if let Some(mweb_hash) = mweb.sync_state.tip_hash {
        if wallet
            .local_chain()
            .get(mweb_tip)
            .is_some_and(|cp| cp.hash() != mweb_hash)
        {
            mweb.disconnect_from(mweb_tip);
            return true;
        }
    }
    false
}

fn open_wallet_state(
    account_dir: &Path,
    meta: &WalletMeta,
    secret: &MasterSecret,
    sealing: Option<Zeroizing<[u8; 32]>>,
) -> Result<WalletState, WalletError> {
    let account = meta.account_index;
    let mut db = Connection::open(meta::db_path(account_dir))
        .map_err(|e| WalletError::Persist(e.to_string()))?;
    let params = load_params(secret, meta.network, account)?;
    let wallet = PersistedWallet::load(&mut db, params)
        .map_err(|e| WalletError::Persist(e.to_string()))?
        .ok_or(WalletError::NotFound)?;
    let mut mweb = MwebRuntime::open(
        account_dir,
        secret,
        meta.network,
        meta.mweb_scheme.to_master_scheme(),
        account,
        sealing,
    )?;
    if reconcile_mweb_chain_with_wallet(&wallet, &mut mweb) {
        let _ = mweb.persist(account_dir);
    }
    Ok(WalletState {
        last_tip_height: wallet.latest_checkpoint().height(),
        tip_time: None,
        tip_time_height: 0,
        wallet,
        signer: signer(secret, meta.network, account)?,
        db,
        account_index: account,
        network: meta.network,
        electrum_url: meta.electrum_url.clone(),
        electrum_validate_domain: meta.electrum_validate_domain,
        electrum_use_public_fallback: meta.electrum_use_public_fallback,
        auto_lock_minutes: meta.auto_lock_minutes,
        active_electrum_url: None,
        litecoin_rpc_url: meta.litecoin_rpc_url.clone(),
        broadcast_via_own_node: meta.broadcast_via_own_node,
        mweb_peers: meta.mweb_peers.clone(),
        mweb_scheme: meta.mweb_scheme,
        explorer_base_url: meta.explorer_base_url.clone(),
        show_fiat: meta.show_fiat,
        use_explorer_fee_hints: meta.use_explorer_fee_hints,
        insights_enabled: meta.insights_enabled,
        data_dir: account_dir.to_path_buf(),
        needs_full_scan: meta.needs_full_scan,
        needs_mweb_scan: meta.needs_mweb_scan,
        mweb: Some(mweb),
    })
}

/// Create BIP84 sqlite + meta under an account directory (does not touch the registry).
fn open_created_account(
    account_dir: &Path,
    secret: &MasterSecret,
    meta: &WalletMeta,
) -> Result<(PersistedWallet<Connection>, Connection, WalletMeta), WalletError> {
    std::fs::create_dir_all(account_dir)?;
    let db_path = meta::db_path(account_dir);
    let mut db = Connection::open(&db_path).map_err(|e| WalletError::Persist(e.to_string()))?;
    let params = create_params(secret, meta.network, meta.account_index)?;
    let mut wallet = PersistedWallet::create(&mut db, params)
        .map_err(|e| WalletError::Persist(e.to_string()))?;
    let _ = wallet.next_unused_address(KeychainKind::External);
    wallet
        .persist(&mut db)
        .map_err(|e| WalletError::Persist(e.to_string()))?;
    meta::write_meta(account_dir, meta)?;
    Ok((wallet, db, meta.clone()))
}

/// Test-only wallet app backed by an arbitrary [`SecretStore`] (typically [`crate::secrets::MemoryStore`]).
pub struct MemoryBackedApp {
    state: Mutex<Option<WalletState>>,
    parked: Mutex<AccountPark>,
    account_load: Mutex<()>,
    secrets: Arc<dyn SecretStore>,
}

impl MemoryBackedApp {
    pub fn exists(&self, data_dir: &Path) -> bool {
        accounts::wallet_exists(data_dir)
    }

    pub fn list_wallets(&self, root: &Path) -> Result<Vec<WalletListItem>, WalletError> {
        accounts::ensure_layout(root)?;
        let reg = accounts::read_registry(root)?;
        Ok(reg
            .accounts
            .iter()
            .map(|a| WalletListItem {
                index: a.index,
                name: a.name.clone(),
                is_active: a.index == reg.active_index,
            })
            .collect())
    }

    pub fn create_wallet_account(
        &self,
        root: &Path,
        req: CreateAccountRequest,
    ) -> Result<WalletSummary, WalletError> {
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        let index = reg.next_free_index();
        let name = {
            let trimmed = req.name.trim();
            if trimmed.is_empty() {
                format!("Wallet {index}")
            } else {
                trimmed.to_string()
            }
        };
        let template = {
            let guard = self
                .state
                .lock()
                .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
            let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
            meta_from_state(state)
        };
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let account_dir = accounts::account_dir(root, index);
        let meta = accounts::meta_for_new_account(&template, index);
        open_created_account(&account_dir, &secret, &meta)?;
        reg.accounts.push(accounts::AccountEntry { index, name });
        reg.active_index = index;
        accounts::write_registry(root, &reg)?;
        self.load(root)
    }

    pub fn switch_wallet(
        &self,
        root: &Path,
        req: SwitchWalletRequest,
    ) -> Result<WalletSummary, WalletError> {
        accounts::ensure_layout(root)?;
        let mut reg = accounts::read_registry(root)?;
        if reg.get(req.index).is_none() {
            return Err(WalletError::NotFound);
        }
        reg.active_index = req.index;
        accounts::write_registry(root, &reg)?;
        let _gate = self.lock_account_load()?;
        let mut guard = self.lock_mem_state()?;
        let activated = {
            let mut park = self.lock_park()?;
            activate_parked(&mut guard, &mut park, req.index)?
        };
        if let Some(summary) = activated {
            return Ok(summary);
        }
        drop(guard);
        self.load_locked(root)
    }

    pub fn preview_transfer_coin(
        &self,
        root: &Path,
        req: TransferCoinRequest,
    ) -> Result<TransferCoinPreview, WalletError> {
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let mut guard = self.lock_mem_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let prepared = {
            let mut park = self.lock_park()?;
            prepare_transfer(
                root,
                state,
                &secret,
                None,
                &req,
                DestAddressMode::Preview,
                &mut park,
            )?
        };
        finish_transfer_preview(state, prepared)
    }

    pub fn wipe(&self, data_dir: &Path) -> Result<(), WalletError> {
        let _gate = self.lock_account_load()?;
        *self.lock_mem_state()? = None;
        self.lock_park()?.clear();
        self.secrets.delete_mnemonic()?;
        accounts::remove_all_accounts(data_dir)?;
        Ok(())
    }

    pub fn create(
        &self,
        data_dir: &Path,
        req: CreateWalletRequest,
    ) -> Result<CreateWalletResponse, WalletError> {
        let mnemonic = descriptors::generate_mnemonic()?;
        let secret = MasterSecret::parse(&mnemonic, None)?;
        let summary = self.create_or_restore(
            data_dir,
            &secret,
            req.network,
            req.electrum_url,
            MwebScheme::default(),
        )?;
        Ok(CreateWalletResponse {
            mnemonic: mnemonic.to_string(),
            summary,
        })
    }

    pub fn restore(
        &self,
        data_dir: &Path,
        req: RestoreWalletRequest,
    ) -> Result<WalletSummary, WalletError> {
        let secret = MasterSecret::parse(&req.mnemonic, req.aezeed_passphrase.as_deref())?;
        self.create_or_restore(
            data_dir,
            &secret,
            req.network,
            req.electrum_url.clone(),
            req.mweb_scheme,
        )
    }

    pub fn load(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        let _gate = self.lock_account_load()?;
        self.load_locked(data_dir)
    }

    fn load_locked(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        if !self.exists(data_dir) {
            return Err(WalletError::NotFound);
        }
        accounts::ensure_layout(data_dir)?;
        let account_dir = accounts::active_account_dir(data_dir)?;
        let meta = meta::read_meta(&account_dir)?;
        let account = meta.account_index;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let mut db = Connection::open(meta::db_path(&account_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = load_params(&secret, meta.network, account)?;
        let wallet = PersistedWallet::load(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?
            .ok_or(WalletError::NotFound)?;
        let state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(&secret, meta.network, account)?,
            db,
            account_index: account,
            network: meta.network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            broadcast_via_own_node: meta.broadcast_via_own_node,
            mweb_peers: meta.mweb_peers,
            mweb_scheme: meta.mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: account_dir,
            needs_full_scan: meta.needs_full_scan,
            needs_mweb_scan: meta.needs_mweb_scan,
            mweb: None,
        };
        let mut guard = self.lock_mem_state()?;
        let mut park = self.lock_park()?;
        install_loaded(&mut guard, &mut park, state)
    }

    fn lock_mem_state(&self) -> Result<MutexGuard<'_, Option<WalletState>>, WalletError> {
        self.state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))
    }

    fn lock_park(&self) -> Result<MutexGuard<'_, AccountPark>, WalletError> {
        self.parked
            .lock()
            .map_err(|_| WalletError::Persist("wallet park lock poisoned".into()))
    }

    fn lock_account_load(&self) -> Result<MutexGuard<'_, ()>, WalletError> {
        self.account_load
            .lock()
            .map_err(|_| WalletError::Persist("wallet load lock poisoned".into()))
    }

    pub fn summary(&self) -> Result<WalletSummary, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        build_summary(state)
    }

    pub fn receive_address(&self) -> Result<String, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let address = state
            .wallet
            .reveal_next_address(KeychainKind::External)
            .to_string();
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(address)
    }

    pub fn address_reuse_hint(&self, address: &str) -> Result<AddressReuseHint, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(compute_address_reuse_hint(&state.wallet, address))
    }

    pub fn get_tx_labels(&self) -> Result<std::collections::HashMap<String, String>, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(labels::read_labels(&state.data_dir)?.labels)
    }

    pub fn set_tx_label(&self, req: SetTxLabelRequest) -> Result<(), WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        labels::set_label(&state.data_dir, &req.txid, &req.label)
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(contacts::read_contacts(&state.data_dir)?.contacts)
    }

    pub fn upsert_contact(&self, req: UpsertContactRequest) -> Result<ContactRecord, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        contacts::upsert_contact(
            &state.data_dir,
            state.network,
            req.id.as_deref(),
            &req.name,
            &req.address,
            req.kind,
        )
    }

    pub fn delete_contact(&self, req: DeleteContactRequest) -> Result<(), WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        contacts::delete_contact(&state.data_dir, &req.id)
    }

    pub fn list_unspent(&self) -> Result<Vec<UtxoRecord>, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        Ok(collect_unspent(state))
    }

    pub fn preview_split(&self, req: SplitRequest) -> Result<SplitPreview, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        plan_split_request(state, &req)
    }

    /// Test helper: build a public split PSBT and return (inputs, outputs, fee).
    pub fn public_split_io_count(
        &self,
        req: SplitRequest,
    ) -> Result<(usize, usize, u64), WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let preview = plan_split_request(state, &req)?;
        let (psbt, fee) = build_public_split_psbt(state, &req.input, &preview)?;
        Ok((
            psbt.unsigned_tx.input.len(),
            psbt.unsigned_tx.output.len(),
            fee,
        ))
    }

    pub fn set_utxo_locked(&self, req: SetUtxoLockedRequest) -> Result<(), WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        set_public_freeze(state, req)
    }

    pub fn set_mweb_utxo_locked(&self, req: SetMwebUtxoLockedRequest) -> Result<(), WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        set_private_freeze(state, req)
    }

    pub fn set_utxo_label(&self, req: SetUtxoLabelRequest) -> Result<(), WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        utxo_labels::set_label(&state.data_dir, &req.outpoint, &req.label)
    }

    pub fn list_mweb_unspent(&self) -> Result<Vec<MwebUtxoRecord>, WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let mweb = state
            .mweb
            .as_ref()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let tip = state.wallet.latest_checkpoint().height();
        Ok(mweb::list_mweb_unspent(mweb, tip, &state.data_dir))
    }

    pub fn preview_mweb_send(&self, req: MwebSendRequest) -> Result<MwebSendPreview, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let resolved = resolve_mweb_send_request(state, req)?;
        Ok(MwebSendPreview {
            amount_sats: resolved.amount_sats,
            fee_sats: resolved.fee_sats,
            creates_change: mweb_selection_creates_change(state, &resolved)?,
        })
    }

    pub fn preview_pegout(&self, req: PegoutRequest) -> Result<PegoutPreview, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (resolved, dust_sats) = resolve_pegout_request(state, req)?;
        pegout_preview_from_resolved(&resolved, dust_sats, state)
    }

    /// Test helper: mutate the in-memory wallet (for funding UTXOs in integration tests).
    pub fn with_wallet_mut<F, T>(&self, f: F) -> Result<T, WalletError>
    where
        F: FnOnce(&mut PersistedWallet<Connection>, &mut Connection) -> Result<T, WalletError>,
    {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        f(&mut state.wallet, &mut state.db)
    }

    /// Test helper: mark an external derivation index as used for reuse-detection tests.
    pub fn mark_external_used(&self, index: u32) -> Result<(), WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        state.wallet.mark_used(KeychainKind::External, index);
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(())
    }

    pub fn send(&self, req: SendRequest) -> Result<SendResult, WalletError> {
        // Minimal send for unit tests that don't hit the network: only build path errors.
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let _ = build_send_psbt(state, &req)?;
        // Unit tests that reach broadcast should not; return a placeholder.
        Err(WalletError::Electrum(
            "memory-backed test app does not broadcast".into(),
        ))
    }

    /// Test helper: resolve peg-in amounts / coin-control rules without broadcasting.
    pub fn preview_pegin(&self, req: PeginRequest) -> Result<PeginPreview, WalletError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        // Supply an explicit transparent fee so resolve does not hit Electrum.
        let req = PeginRequest {
            transparent_fee_sats: if req.transparent_fee_sats > 0 {
                req.transparent_fee_sats
            } else {
                500
            },
            ..req
        };
        let resolved = resolve_pegin_request(state, req)?;
        let total_from_transparent_sats = resolved
            .amount_sats
            .saturating_add(resolved.transparent_fee_sats);
        let creates_change =
            pegin_selection_creates_change(state, &resolved, total_from_transparent_sats);
        Ok(PeginPreview {
            amount_sats: resolved.amount_sats,
            private_credit_sats: resolved.amount_sats.saturating_sub(resolved.mweb_fee_sats),
            mweb_fee_sats: resolved.mweb_fee_sats,
            transparent_fee_sats: resolved.transparent_fee_sats,
            total_from_transparent_sats,
            creates_change,
            maturity_blocks: bdk_mweb::MWEB_PEGIN_MATURITY,
        })
    }

    fn create_or_restore(
        &self,
        data_dir: &Path,
        secret: &MasterSecret,
        network: WalletNetwork,
        electrum_url: Option<String>,
        mweb_scheme: MwebScheme,
    ) -> Result<WalletSummary, WalletError> {
        if self.exists(data_dir) {
            if self.secrets.get_mnemonic()?.is_none() {
                self.wipe(data_dir)?;
            } else {
                return Err(WalletError::AlreadyExists);
            }
        }
        let payload = secret.to_stored();
        self.secrets.set_mnemonic(&payload)?;
        let stored = self.secrets.get_mnemonic()?;
        if stored.as_ref().map(|s| s.as_str()) != Some(payload.as_str()) {
            let _ = self.secrets.delete_mnemonic();
            return Err(WalletError::SecretStore(
                "secret store did not persist mnemonic".into(),
            ));
        }
        std::fs::create_dir_all(data_dir)?;
        let account_dir = accounts::init_registry_account0(data_dir)?;
        let mut meta = WalletMeta::new(network, electrum_url);
        meta.mweb_scheme = mweb_scheme;
        meta.account_index = 0;
        let (wallet, db, meta) = open_created_account(&account_dir, secret, &meta)?;
        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(secret, network, 0)?,
            db,
            account_index: 0,
            network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            broadcast_via_own_node: meta.broadcast_via_own_node,
            mweb_peers: meta.mweb_peers,
            mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: account_dir,
            needs_full_scan: meta.needs_full_scan,
            needs_mweb_scan: meta.needs_mweb_scan,
            mweb: None,
        };
        let summary = build_summary(&mut state)?;
        *self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))? = Some(state);
        Ok(summary)
    }
}

/// Floor for a small peg-in. Real sizes from [`estimate_pegin_vb`] are higher
/// once several inputs are selected.
const PEGIN_FEE_VB_ESTIMATE: u64 = 250;
/// Extra vbytes on top of the worst-case size. A peg-in priced at the exact
/// relay floor was rejected for being 11 litoshis short.
const PEGIN_FEE_VB_BUFFER: u64 = 16;

/// One-output self-spend. The request has no fee field; every new hop pays this.
fn self_spend_hop_fee() -> u64 {
    crate::tx_invariants::min_kernel_fee(1, std::iter::empty())
}

/// Fee of 0 pays the relay minimum for the shape coin selection actually builds.
///
/// Selection at the no-change weight that sums exactly to amount + fee stays on
/// that fee. A remainder means a change output, so the fee steps up by one
/// standard output (1,800 litoshis). A selection that cannot cover the lower
/// fee returns that lower fee and leaves the caller's funds check to refuse it.
fn choose_auto_kernel_fee(
    state: &WalletState,
    amount_sats: u64,
    selected: Option<&[String]>,
    no_change_outputs: usize,
    with_change_outputs: usize,
    pegout_scripts: &[&Script],
    action: &str,
) -> Result<u64, WalletError> {
    let no_change =
        crate::tx_invariants::min_kernel_fee(no_change_outputs, pegout_scripts.iter().copied());
    let with_change =
        crate::tx_invariants::min_kernel_fee(with_change_outputs, pegout_scripts.iter().copied());
    let Ok(needed) =
        crate::tx_invariants::checked_add_money(amount_sats, no_change, "MWEB spend needed")
    else {
        return Ok(no_change);
    };
    let Some(mweb) = state.mweb.as_ref() else {
        return Ok(no_change);
    };
    let tip = state.wallet.latest_checkpoint().height();
    let Ok(frozen) = mweb_frozen::unavailable_ids(&state.data_dir) else {
        return Ok(no_change);
    };
    let coins =
        match mweb::resolve_spend_coins(mweb.store.db(), tip, &frozen, selected, needed, action) {
            Ok(coins) => coins,
            Err(_) => return Ok(no_change),
        };
    let sum = crate::tx_invariants::checked_sum_sats(
        coins.iter().map(|c| c.amount),
        "MWEB selected coins",
    )?;
    if sum == needed {
        Ok(no_change)
    } else {
        Ok(with_change)
    }
}

fn compact_size_len(n: u64) -> u64 {
    if n < 253 {
        1
    } else if n <= u16::MAX as u64 {
        3
    } else {
        5
    }
}

/// Virtual size Core uses for the transparent peg-in, plus [`PEGIN_FEE_VB_BUFFER`].
///
/// `GetTransactionWeight` bills the segwit transaction with the MWEB body
/// stripped, then adds 164 weight units per peg-in kernel (a 41-byte input at
/// the witness scale). Witness size assumes a 73-byte signature, the longest
/// standard DER encoding. `n_outputs` is the peg-in output plus change when
/// coin selection may add one.
fn estimate_pegin_vb(n_inputs: usize, n_outputs: usize) -> u64 {
    let n_inputs = n_inputs.max(1) as u64;
    let n_outputs = n_outputs.max(1) as u64;
    // P2WPKH base input is 41 bytes. Worst-case witness is stack count, a
    // 73-byte signature, and a 33-byte pubkey, each with its length byte.
    const WITNESS_PER_INPUT: u64 = 1 + 1 + 73 + 1 + 33;
    const OUTPUT_BYTES: u64 = 8 + 1 + 34;
    const PEGIN_KERNEL_WEIGHT: u64 = 164;
    let stripped = 4
        + compact_size_len(n_inputs)
        + 41 * n_inputs
        + compact_size_len(n_outputs)
        + OUTPUT_BYTES * n_outputs
        + 4;
    let total = stripped + 2 + WITNESS_PER_INPUT * n_inputs;
    let weight = stripped * 3 + total + PEGIN_KERNEL_WEIGHT;
    let vsize = weight.div_ceil(4);
    vsize
        .saturating_add(PEGIN_FEE_VB_BUFFER)
        .max(PEGIN_FEE_VB_ESTIMATE)
}

fn auto_pegin_transparent_fee(
    state: &mut WalletState,
    explicit: u64,
    estimated_vb: u64,
) -> Result<u64, WalletError> {
    if explicit > 0 {
        return crate::tx_invariants::check_money(explicit, "peg-in transparent fee");
    }
    let client = connect_electrum(state)?;
    let (rate, _) = electrum::estimate_fee_rate_sat_vb(&client)?;
    Ok(rate.saturating_mul(estimated_vb).max(500))
}

fn utxo_confirmations(
    pos: &ChainPosition<bdk_wallet::chain::ConfirmationBlockTime>,
    tip: u32,
) -> u32 {
    match pos {
        ChainPosition::Confirmed { anchor, .. } => {
            tip.saturating_sub(anchor.block_id.height).saturating_add(1)
        }
        ChainPosition::Unconfirmed { .. } => 0,
    }
}

/// Litecoin consensus maturity for a transparent outpoint (`CanonicalTxOut::is_mature`).
///
/// Ordinary outputs are always mature (`(true, 0)`), including while unconfirmed. HogEx peg-out
/// outputs require `PEGOUT_MATURITY` (6) confirmations and coinbase outputs require
/// `COINBASE_MATURITY` (100) confirmations (`tip - conf_height + 1 >= maturity`).
fn public_utxo_maturity(
    wallet: &PersistedWallet<Connection>,
    outpoint: OutPoint,
    tip: u32,
    confirmations: u32,
) -> (bool, u32) {
    let Some(txo) = wallet.canonical_view().txout(outpoint) else {
        return (true, 0);
    };
    let mature = txo.is_mature(tip);
    if mature {
        return (true, 0);
    }
    let maturity = if txo.is_on_coinbase {
        bdk_wallet::bitcoin::constants::COINBASE_MATURITY
    } else if txo.is_hogex_pegout {
        bdk_wallet::chain::PEGOUT_MATURITY
    } else {
        1
    };
    (false, maturity.saturating_sub(confirmations).max(1))
}

fn refuse_immature_public(
    wallet: &PersistedWallet<Connection>,
    outpoint: OutPoint,
    tip: u32,
    confirmations: u32,
) -> Result<(), WalletError> {
    let (mature, blocks_left) = public_utxo_maturity(wallet, outpoint, tip, confirmations);
    if mature {
        return Ok(());
    }
    let block = if confirmations == 0 {
        crate::dto::CoinBlock::Unconfirmed
    } else {
        crate::dto::CoinBlock::Maturing { blocks_left }
    };
    Err(WalletError::BuildTx(format!(
        "selected outpoint {outpoint}: {}",
        mweb::coin_block_message(block)
    )))
}

fn selectable_public_utxo_amounts(
    state: &WalletState,
    held: &std::collections::BTreeSet<OutPoint>,
) -> Vec<u64> {
    let tip = state.wallet.local_chain().tip().height();
    let mut amounts: Vec<u64> = state
        .wallet
        .list_unspent()
        .filter(|u| {
            let confs = utxo_confirmations(&u.chain_position, tip);
            !state.wallet.is_outpoint_locked(u.outpoint)
                && !held.contains(&u.outpoint)
                && public_utxo_maturity(&state.wallet, u.outpoint, tip, confs).0
        })
        .map(|u| u.txout.value.to_sat())
        .collect();
    amounts.sort_unstable_by_key(|&a| std::cmp::Reverse(a));
    amounts
}

fn resolve_pegin_request(
    state: &mut WalletState,
    req: PeginRequest,
) -> Result<PeginRequest, WalletError> {
    let mweb_fee_sats = if req.mweb_fee_sats == 0 {
        self_spend_hop_fee()
    } else {
        req.mweb_fee_sats
    };
    crate::tx_invariants::check_money(mweb_fee_sats, "peg-in MWEB fee")?;
    let min_mweb_fee = bdk_mweb::policy::min_mweb_fee(bdk_mweb::policy::mweb_weight(1, []));
    if mweb_fee_sats < min_mweb_fee {
        return Err(WalletError::BuildTx(format!(
            "MWEB fee {mweb_fee_sats} litoshis is below the minimum {min_mweb_fee} litoshis"
        )));
    }
    let selected =
        crate::tx_invariants::parse_and_dedup_outpoints(req.selected_outpoints.as_deref())?;

    let (utxo_amounts, spendable) = if let Some(ref outpoints) = selected {
        let tip = state.wallet.local_chain().tip().height();
        let mut amounts = Vec::with_capacity(outpoints.len());
        for op in outpoints {
            let Some(utxo) = state.wallet.get_utxo(*op) else {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is not an unspent output in this wallet"
                )));
            };
            if state.wallet.is_outpoint_locked(*op) {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is frozen — unfreeze it before swapping"
                )));
            }
            refuse_reserved_public(&state.data_dir, *op)?;
            let confs = utxo_confirmations(&utxo.chain_position, tip);
            refuse_immature_public(&state.wallet, *op, tip, confs)?;
            amounts.push(utxo.txout.value.to_sat());
        }
        let sum = crate::tx_invariants::checked_sum_sats(
            amounts.iter().copied(),
            "selected transparent outpoints",
        )?;
        (amounts, sum)
    } else {
        let held = mweb_frozen::public_reserved_outpoints(&state.data_dir)?;
        let amounts = selectable_public_utxo_amounts(state, &held);
        let sum = crate::tx_invariants::checked_sum_sats(
            amounts.iter().copied(),
            "spendable transparent pool",
        )?;
        (amounts, sum)
    };

    let estimated_inputs = if selected.is_some() || req.drain {
        utxo_amounts.len().max(1)
    } else {
        let mut acc = 0u64;
        let mut count = 0usize;
        for &amt in &utxo_amounts {
            acc = acc.saturating_add(amt);
            count += 1;
            if acc > req.amount_sats {
                break;
            }
        }
        count.max(1)
    };
    // Drain spends the selection with no change. Any other peg-in may add one.
    let n_outputs = if req.drain { 1 } else { 2 };
    let transparent_fee_sats = auto_pegin_transparent_fee(
        state,
        req.transparent_fee_sats,
        estimate_pegin_vb(estimated_inputs, n_outputs),
    )?;

    let amount_sats = if req.drain {
        // Drain of a manual selection empties those coins; otherwise the wallet.
        spendable.checked_sub(transparent_fee_sats).ok_or_else(|| {
            WalletError::BuildTx(format!(
                "not enough transparent funds to peg in after a ~{} litoshis miner fee",
                transparent_fee_sats
            ))
        })?
    } else {
        crate::tx_invariants::check_money(req.amount_sats, "peg-in amount")?;
        // The miner fee rides on top of the amount. Catch that here at preview
        // time, before BDK coin selection fails with a raw "BTC" error.
        let needed = crate::tx_invariants::checked_add_money(
            req.amount_sats,
            transparent_fee_sats,
            "peg-in total",
        )?;
        if needed > spendable {
            return Err(WalletError::BuildTx(format!(
                "swapping {} litoshis needs {} litoshis with the ~{} litoshis miner fee, but only {} \
                 litoshis are spendable — lower the amount or use Max",
                req.amount_sats, needed, transparent_fee_sats, spendable
            )));
        }
        req.amount_sats
    };
    if amount_sats <= mweb_fee_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-in amount {} litoshis must exceed the MWEB fee ({} litoshis) so a private coin remains",
            amount_sats, mweb_fee_sats
        )));
    }
    if amount_sats < crate::tx_invariants::PEGIN_V9_DUST_SATS {
        return Err(WalletError::BuildTx(format!(
            "peg-in amount {} litoshis is below the network dust limit ({} litoshis)",
            amount_sats,
            crate::tx_invariants::PEGIN_V9_DUST_SATS
        )));
    }
    Ok(PeginRequest {
        amount_sats,
        mweb_fee_sats,
        transparent_fee_sats,
        drain: false,
        selected_outpoints: selected.map(|ops| ops.iter().map(ToString::to_string).collect()),
    })
}

fn resolve_mweb_send_request(
    state: &WalletState,
    req: MwebSendRequest,
) -> Result<MwebSendRequest, WalletError> {
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(&state.data_dir)?;
    let selected = mweb::normalize_selected_ids(req.selected_output_ids.as_deref());
    let spendable = if let Some(ref ids) = selected {
        let coins = mweb::resolve_spend_coins(
            mweb.store.db(),
            tip,
            &frozen,
            Some(ids.as_slice()),
            0,
            "spending",
        )?;
        crate::tx_invariants::checked_sum_sats(
            coins.iter().map(|c| c.amount),
            "selected private coins",
        )?
    } else {
        mweb::spendable_mweb_sats(mweb, tip, &frozen)
    };
    let one_output = self_spend_hop_fee();
    let fee_sats = if req.fee_sats > 0 {
        req.fee_sats
    } else if req.drain {
        one_output
    } else {
        choose_auto_kernel_fee(
            state,
            req.amount_sats,
            selected.as_deref(),
            1,
            2,
            &[],
            "spending",
        )?
    };
    crate::tx_invariants::check_money(fee_sats, "private send fee")?;
    if fee_sats < one_output {
        return Err(WalletError::BuildTx(format!(
            "MWEB fee {fee_sats} litoshis is below the minimum {one_output} litoshis"
        )));
    }
    let amount_sats = if req.drain {
        spendable.checked_sub(fee_sats).ok_or_else(|| {
            WalletError::BuildTx(format!(
                "not enough private funds to send after a {} litoshis MWEB fee",
                fee_sats
            ))
        })?
    } else {
        crate::tx_invariants::check_money(req.amount_sats, "private send amount")?
    };
    if amount_sats == 0 {
        return Err(WalletError::BuildTx(
            "private send amount must be greater than zero".into(),
        ));
    }
    let needed =
        crate::tx_invariants::checked_add_money(amount_sats, fee_sats, "private send total")?;
    if needed > spendable {
        return Err(WalletError::BuildTx(format!(
            "need {needed} litoshis spendable private (amount + fee) but only {spendable} available"
        )));
    }
    // Validate MWEB stealth address early so preview fails before confirm.
    let _ = crate::tx_invariants::validate_mweb_recipient(&req.address, state.network)?;
    Ok(MwebSendRequest {
        address: req.address,
        amount_sats,
        fee_sats,
        drain: false,
        selected_output_ids: selected,
    })
}

fn pegout_preview_from_resolved(
    resolved: &PegoutRequest,
    dust_sats: u64,
    state: &WalletState,
) -> Result<PegoutPreview, WalletError> {
    let creates_change = if resolved.per_coin {
        false
    } else {
        pegout_selection_creates_change(state, resolved)?
    };
    let output_amounts = if resolved.output_amounts.is_empty() {
        vec![resolved.amount_sats]
    } else {
        resolved.output_amounts.clone()
    };
    Ok(PegoutPreview {
        amount_sats: resolved.amount_sats,
        fee_sats: resolved.fee_sats,
        dust_sats,
        creates_change,
        output_count: output_amounts.len() as u32,
        output_amounts,
        fee_output_index: resolved.fee_output_index,
    })
}

fn resolve_pegout_request(
    state: &WalletState,
    req: PegoutRequest,
) -> Result<(PegoutRequest, u64), WalletError> {
    if req.fee_sats > 0 {
        crate::tx_invariants::check_money(req.fee_sats, "peg-out fee")?;
    }
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(&state.data_dir)?;
    let selected = mweb::normalize_selected_ids(req.selected_output_ids.as_deref());
    let per_coin = req.drain;

    if per_coin {
        let dust_sats = mweb::p2wpkh_dust_sats()?;
        let coins = if let Some(ref ids) = selected {
            mweb::resolve_spend_coins(
                mweb.store.db(),
                tip,
                &frozen,
                Some(ids.as_slice()),
                0,
                "swapping",
            )?
        } else {
            mweb::spendable_pool(mweb.store.db(), tip, &frozen)
        };
        if coins.is_empty() {
            return Err(WalletError::BuildTx(
                "no spendable private coins to peg out".into(),
            ));
        }
        let script = mweb::p2wpkh_script();
        let floor = crate::tx_invariants::min_kernel_fee(
            0,
            std::iter::repeat(script.as_script()).take(coins.len()),
        );
        let fee_sats = if req.fee_sats == 0 {
            floor
        } else {
            req.fee_sats
        };
        crate::tx_invariants::check_money(fee_sats, "peg-out fee")?;
        let coin_amounts: Vec<u64> = coins.iter().map(|c| c.amount).collect();
        let plan = mweb::plan_pegout_per_coin(&coin_amounts, fee_sats, dust_sats)?;
        let amount_sats = crate::tx_invariants::checked_sum_sats(
            plan.amounts.iter().copied(),
            "peg-out output total",
        )?;
        let ids: Vec<String> = coins.iter().map(|c| hex::encode(c.output_id)).collect();
        return Ok((
            PegoutRequest {
                address: String::new(),
                amount_sats,
                fee_sats,
                drain: true,
                selected_output_ids: Some(ids),
                output_amounts: plan.amounts,
                addresses: Vec::new(),
                per_coin: true,
                fee_output_index: Some(plan.fee_output_index as u32),
            },
            dust_sats,
        ));
    }

    let amount_sats = crate::tx_invariants::check_money(req.amount_sats, "peg-out amount")?;
    let (_dest, spk, dust_sats) =
        crate::tx_invariants::validate_public_recipient(&req.address, state.network)?;
    let min_fee = crate::tx_invariants::min_kernel_fee(0, [spk.as_script()]);
    let fee_sats = if req.fee_sats > 0 {
        req.fee_sats
    } else {
        choose_auto_kernel_fee(
            state,
            amount_sats,
            selected.as_deref(),
            0,
            1,
            &[spk.as_script()],
            "swapping",
        )?
    };
    crate::tx_invariants::check_money(fee_sats, "peg-out fee")?;
    if fee_sats < min_fee {
        return Err(WalletError::BuildTx(format!(
            "peg-out fee {fee_sats} litoshis is below the MWEB minimum of {min_fee} litoshis"
        )));
    }
    let needed = crate::tx_invariants::checked_add_money(amount_sats, fee_sats, "peg-out total")?;
    if let Some(ref ids) = selected {
        mweb::resolve_spend_coins(
            mweb.store.db(),
            tip,
            &frozen,
            Some(ids.as_slice()),
            needed,
            "swapping",
        )?;
    }
    let spendable = mweb::spendable_mweb_sats(mweb, tip, &frozen);
    if amount_sats < dust_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-out amount {} litoshis is below the dust limit ({} litoshis for this address)",
            amount_sats, dust_sats
        )));
    }
    if needed > spendable {
        return Err(WalletError::BuildTx(format!(
            "need {needed} litoshis spendable private (amount + fee) but only {spendable} available"
        )));
    }
    Ok((
        PegoutRequest {
            address: req.address,
            amount_sats,
            fee_sats,
            drain: false,
            selected_output_ids: selected,
            output_amounts: vec![amount_sats],
            addresses: Vec::new(),
            per_coin: false,
            fee_output_index: None,
        },
        dust_sats,
    ))
}

struct PreparedTransfer {
    chain: SplitChain,
    to_account_index: u32,
    to_wallet_name: String,
    address: String,
    send_req: Option<SendRequest>,
    mweb_req: Option<MwebSendRequest>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DestAddressMode {
    Preview,
    PeekNext,
    CommitNext,
}

fn prepare_transfer(
    root: &Path,
    state: &WalletState,
    secret: &MasterSecret,
    sealing_key: Option<Zeroizing<[u8; 32]>>,
    req: &TransferCoinRequest,
    mode: DestAddressMode,
    park: &mut AccountPark,
) -> Result<PreparedTransfer, WalletError> {
    accounts::ensure_layout(root)?;
    let reg = accounts::read_registry(root)?;
    if req.to_account_index == state.account_index {
        return Err(WalletError::Meta(
            "cannot transfer a coin to the active wallet".into(),
        ));
    }
    let dest_entry = reg.get(req.to_account_index).ok_or(WalletError::NotFound)?;
    let to_wallet_name = dest_entry.name.clone();
    let coin_id = req.coin_id.trim();
    if coin_id.is_empty() {
        return Err(WalletError::BuildTx("coin id is required".into()));
    }

    let address = reveal_dest_address(
        root,
        secret,
        sealing_key,
        req.to_account_index,
        req.chain,
        state.network,
        mode,
        park,
    )?;

    match req.chain {
        SplitChain::Public => Ok(PreparedTransfer {
            chain: SplitChain::Public,
            to_account_index: req.to_account_index,
            to_wallet_name,
            address: address.clone(),
            send_req: Some(SendRequest {
                address,
                amount_sats: 0,
                fee_rate_sat_vb: req.fee_rate_sat_vb,
                drain: true,
                selected_outpoints: Some(vec![coin_id.to_string()]),
            }),
            mweb_req: None,
        }),
        SplitChain::Private => Ok(PreparedTransfer {
            chain: SplitChain::Private,
            to_account_index: req.to_account_index,
            to_wallet_name,
            address: address.clone(),
            send_req: None,
            mweb_req: Some(MwebSendRequest {
                address,
                amount_sats: 0,
                fee_sats: req.fee_sats,
                drain: true,
                selected_output_ids: Some(vec![coin_id.to_string()]),
            }),
        }),
    }
}

/// Use the resident destination when this session already has it open.
/// A second sqlite connection would persist past the in-memory wallet.
fn reveal_parked_dest(
    park: &mut AccountPark,
    to_account: u32,
    chain: SplitChain,
    network: WalletNetwork,
    mode: DestAddressMode,
) -> Result<Option<String>, WalletError> {
    match chain {
        SplitChain::Public => {
            let Some(state) = park.get_mut(to_account) else {
                return Ok(None);
            };
            let address = match mode {
                DestAddressMode::CommitNext => {
                    let addr = state
                        .wallet
                        .reveal_next_address(KeychainKind::External)
                        .to_string();
                    state
                        .wallet
                        .persist(&mut state.db)
                        .map_err(|e| WalletError::Persist(e.to_string()))?;
                    addr
                }
                DestAddressMode::PeekNext => {
                    let next = state.wallet.next_derivation_index(KeychainKind::External);
                    state
                        .wallet
                        .peek_address(KeychainKind::External, next)
                        .address
                        .to_string()
                }
                DestAddressMode::Preview => current_receive_address(&mut state.wallet),
            };
            Ok(Some(address))
        }
        SplitChain::Private => {
            let Some(state) = park.get_mut(to_account) else {
                return Ok(None);
            };
            if state.mweb.is_none() {
                return Ok(None);
            }
            let dir = state.data_dir.clone();
            let mweb = state
                .mweb
                .as_mut()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let address = mweb.receive_address(network)?;
            if mode == DestAddressMode::CommitNext {
                mweb.advance_receive_index();
                mweb.persist(&dir)?;
            }
            Ok(Some(address))
        }
    }
}

fn reveal_dest_address(
    root: &Path,
    secret: &MasterSecret,
    sealing_key: Option<Zeroizing<[u8; 32]>>,
    to_account: u32,
    chain: SplitChain,
    network: WalletNetwork,
    mode: DestAddressMode,
    park: &mut AccountPark,
) -> Result<String, WalletError> {
    if let Some(address) = reveal_parked_dest(park, to_account, chain, network, mode)? {
        return Ok(address);
    }
    let account_dir = accounts::account_dir(root, to_account);
    if !meta::wallet_files_exist(&account_dir) {
        return Err(WalletError::NotFound);
    }
    match chain {
        SplitChain::Public => {
            let mut db = Connection::open(meta::db_path(&account_dir))
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            let params = load_params(secret, network, to_account)?;
            let mut wallet = PersistedWallet::load(&mut db, params)
                .map_err(|e| WalletError::Persist(e.to_string()))?
                .ok_or(WalletError::NotFound)?;
            let address = match mode {
                DestAddressMode::CommitNext => {
                    let addr = wallet
                        .reveal_next_address(KeychainKind::External)
                        .to_string();
                    wallet
                        .persist(&mut db)
                        .map_err(|e| WalletError::Persist(e.to_string()))?;
                    addr
                }
                DestAddressMode::PeekNext => {
                    let next = wallet.next_derivation_index(KeychainKind::External);
                    wallet
                        .peek_address(KeychainKind::External, next)
                        .address
                        .to_string()
                }
                DestAddressMode::Preview => current_receive_address(&mut wallet),
            };
            Ok(address)
        }
        SplitChain::Private => {
            let dest_meta = meta::read_meta(&account_dir)?;
            let mut mweb = MwebRuntime::open(
                &account_dir,
                secret,
                network,
                dest_meta.mweb_scheme.to_master_scheme(),
                to_account,
                sealing_key,
            )?;
            let address = mweb.receive_address(network)?;
            if mode == DestAddressMode::CommitNext {
                mweb.advance_receive_index();
                mweb.persist(&account_dir)?;
            }
            Ok(address)
        }
    }
}

fn finish_transfer_preview(
    state: &mut WalletState,
    prepared: PreparedTransfer,
) -> Result<TransferCoinPreview, WalletError> {
    match prepared.chain {
        SplitChain::Public => {
            let send_req = prepared.send_req.expect("public transfer");
            let (fee_rate_sat_vb, psbt, recipient_script) = build_send_psbt(state, &send_req)?;
            let fee_sats = psbt
                .fee_amount()
                .ok_or_else(|| WalletError::BuildTx("unable to compute fee".into()))?
                .to_sat();
            let amount_sats = psbt
                .unsigned_tx
                .output
                .iter()
                .find(|o| o.script_pubkey == recipient_script)
                .map(|o| o.value.to_sat())
                .unwrap_or(0);
            state
                .wallet
                .persist(&mut state.db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            Ok(TransferCoinPreview {
                to_account_index: prepared.to_account_index,
                to_wallet_name: prepared.to_wallet_name,
                address: prepared.address,
                amount_sats,
                fee_sats,
                fee_rate_sat_vb: Some(fee_rate_sat_vb),
                creates_change: psbt.unsigned_tx.output.len() > 1,
            })
        }
        SplitChain::Private => {
            let mweb_req = prepared.mweb_req.expect("private transfer");
            let resolved = resolve_mweb_send_request(state, mweb_req)?;
            Ok(TransferCoinPreview {
                to_account_index: prepared.to_account_index,
                to_wallet_name: prepared.to_wallet_name,
                address: prepared.address,
                amount_sats: resolved.amount_sats,
                fee_sats: resolved.fee_sats,
                fee_rate_sat_vb: None,
                creates_change: mweb_selection_creates_change(state, &resolved)?,
            })
        }
    }
}

enum PreparedTransferBroadcast {
    Public {
        source_dir: PathBuf,
        electrum_candidates: Vec<String>,
        electrum_validate_domain: bool,
        tx: Transaction,
        fee_sats: u64,
        address: String,
        to_account_index: u32,
        hold: CoinHold,
    },
    Private {
        source_dir: PathBuf,
        signed: Box<mweb::SignedMwebSend>,
        route: mweb::BroadcastRoute,
        address: String,
        to_account_index: u32,
        hold: CoinHold,
    },
}

/// Sign a transfer and reserve its coin. Does not broadcast.
fn prepare_transfer_broadcast(
    root: &Path,
    state: &mut WalletState,
    secret: &MasterSecret,
    sealing_key: Option<Zeroizing<[u8; 32]>>,
    req: &TransferCoinRequest,
    park: &mut AccountPark,
    session: &str,
) -> Result<PreparedTransferBroadcast, WalletError> {
    let prepared = prepare_transfer(
        root,
        state,
        secret,
        sealing_key.clone(),
        req,
        DestAddressMode::PeekNext,
        park,
    )?;
    let source_dir = state.data_dir.clone();
    match prepared.chain {
        SplitChain::Public => {
            let send_req = prepared.send_req.expect("public transfer");
            let (_fee_rate_sat_vb, mut psbt, _recipient_script) =
                build_send_psbt(state, &send_req)?;
            sign_and_finalize(&state.wallet, &state.signer, &mut psbt)?;
            let fee_sats = psbt
                .fee_amount()
                .ok_or_else(|| WalletError::BuildTx("unable to compute fee".into()))?
                .to_sat();
            let tx = psbt
                .extract_tx()
                .map_err(|e| WalletError::BuildTx(e.to_string()))?;
            let outpoint = parse_outpoint(req.coin_id.trim())?;
            let hold = CoinHold::take_public(&source_dir, vec![outpoint], session)?;
            let committed = reveal_dest_address(
                root,
                secret,
                sealing_key,
                req.to_account_index,
                req.chain,
                state.network,
                DestAddressMode::CommitNext,
                park,
            )?;
            if committed != prepared.address {
                return Err(WalletError::BuildTx(
                    "destination address changed during transfer signing".into(),
                ));
            }
            Ok(PreparedTransferBroadcast::Public {
                electrum_candidates: electrum_candidates(state),
                electrum_validate_domain: state.electrum_validate_domain,
                source_dir,
                tx,
                fee_sats,
                address: prepared.address,
                to_account_index: prepared.to_account_index,
                hold,
            })
        }
        SplitChain::Private => {
            let mweb_req = prepared.mweb_req.expect("private transfer");
            let resolved = resolve_mweb_send_request(state, mweb_req)?;
            let route = broadcast_route(state);
            let network = state.network;
            let mweb = state
                .mweb
                .as_mut()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let signed =
                mweb::sign_mweb_send(&state.wallet, mweb, &source_dir, &resolved, network)?;
            let hold = CoinHold::take(&source_dir, signed.input_ids(), session)?;
            let committed = reveal_dest_address(
                root,
                secret,
                sealing_key,
                req.to_account_index,
                req.chain,
                state.network,
                DestAddressMode::CommitNext,
                park,
            )?;
            if committed != prepared.address {
                return Err(WalletError::BuildTx(
                    "destination address changed during transfer signing".into(),
                ));
            }
            Ok(PreparedTransferBroadcast::Private {
                source_dir,
                signed: Box::new(signed),
                route,
                address: prepared.address,
                to_account_index: prepared.to_account_index,
                hold,
            })
        }
    }
}

/// Build a send PSBT. Resolves fee rate from the request or Electrum.
/// Returns `(fee_rate_sat_vb, psbt, recipient_script)`.
fn build_send_psbt(
    state: &mut WalletState,
    req: &SendRequest,
) -> Result<(u64, Psbt, ScriptBuf), WalletError> {
    let (_address, recipient_script, min_non_dust) =
        crate::tx_invariants::validate_public_recipient(&req.address, state.network)?;

    let fee_rate_sat_vb = match req.fee_rate_sat_vb {
        Some(rate) if rate > 0 => rate,
        _ => {
            let client = connect_electrum(state)?;
            electrum::estimate_fee_rate_sat_vb(&client)?.0
        }
    };
    let fee_rate = crate::tx_invariants::validate_fee_rate_sat_vb(fee_rate_sat_vb)?;

    let selected =
        crate::tx_invariants::parse_and_dedup_outpoints(req.selected_outpoints.as_deref())?;

    if let Some(ref outpoints) = selected {
        let tip = state.wallet.local_chain().tip().height();
        for op in outpoints {
            let Some(utxo) = state.wallet.get_utxo(*op) else {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is not an unspent output in this wallet"
                )));
            };
            if state.wallet.is_outpoint_locked(*op) {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is frozen — unfreeze it before spending"
                )));
            }
            let confs = utxo_confirmations(&utxo.chain_position, tip);
            refuse_immature_public(&state.wallet, *op, tip, confs)?;
        }
    }
    let held = mweb_frozen::public_reserved_outpoints(&state.data_dir)?;
    if let Some(op) = selected.iter().flatten().find(|op| held.contains(op)) {
        return Err(WalletError::BuildTx(format!(
            "selected outpoint {op}: {}",
            mweb_frozen::RESERVED_MESSAGE
        )));
    }

    let mut tx_builder = state
        .wallet
        .build_tx()
        .coin_selection(crate::tx_invariants::LitecoinDustCoinSelection);
    if let Some(ref outpoints) = selected {
        tx_builder
            .add_utxos(outpoints)
            .map_err(|e| WalletError::BuildTx(e.to_string()))?;
        tx_builder.manually_selected_only();
    }
    tx_builder.unspendable(held.into_iter().collect());

    if req.drain {
        // With a manual selection, drain only those UTXOs (no drain_wallet).
        if selected.is_none() {
            tx_builder.drain_wallet();
        }
        tx_builder.drain_to(recipient_script.clone());
    } else {
        crate::tx_invariants::check_money(req.amount_sats, "send amount")?;
        if req.amount_sats < min_non_dust {
            return Err(WalletError::BuildTx(format!(
                "amount {} litoshis is below the network dust limit ({min_non_dust} litoshis for this address)",
                req.amount_sats
            )));
        }
        tx_builder.add_recipient(recipient_script.clone(), Amount::from_sat(req.amount_sats));
    }
    tx_builder.fee_rate(fee_rate);
    let psbt = tx_builder.finish().map_err(|e| {
        let msg = e.to_string();
        if msg.to_lowercase().contains("dust") {
            WalletError::BuildTx(format!(
                "output below dust limit ({min_non_dust} litoshis for this address): {msg}"
            ))
        } else {
            WalletError::BuildTx(msg)
        }
    })?;
    crate::tx_invariants::verify_transparent_psbt(&psbt)?;
    Ok((
        fee_rate_sat_vb.max(MIN_FEE_RATE_SAT_VB),
        psbt,
        recipient_script,
    ))
}

fn parse_outpoint(raw: &str) -> Result<OutPoint, WalletError> {
    OutPoint::from_str(raw.trim()).map_err(|e| {
        WalletError::BuildTx(format!(
            "invalid outpoint '{raw}' (expected txid:vout): {e}"
        ))
    })
}

fn public_split_utxo(state: &WalletState, raw: &str) -> Result<(OutPoint, u64), WalletError> {
    let op = parse_outpoint(raw)?;
    let utxo = state.wallet.get_utxo(op).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "selected outpoint {op} is not an unspent output in this wallet"
        ))
    })?;
    if state.wallet.is_outpoint_locked(op) {
        return Err(WalletError::BuildTx(format!(
            "selected outpoint {op} is frozen — unfreeze it before splitting"
        )));
    }
    refuse_reserved_public(&state.data_dir, op)?;
    let tip = state.wallet.local_chain().tip().height();
    let confirmations = utxo_confirmations(&utxo.chain_position, tip);
    if confirmations == 0 {
        return Err(WalletError::BuildTx(
            "Split is disabled until the coin is confirmed".into(),
        ));
    }
    refuse_immature_public(&state.wallet, op, tip, confirmations)?;
    Ok((op, utxo.txout.value.to_sat()))
}

enum PreparedSplit {
    Public {
        source_dir: PathBuf,
        electrum_candidates: Vec<String>,
        electrum_validate_domain: bool,
        tx: Transaction,
        fee_sats: u64,
        output_count: u32,
        hold: CoinHold,
    },
    Private {
        source_dir: PathBuf,
        signed: mweb::SignedMwebSplit,
        route: mweb::BroadcastRoute,
        hold: CoinHold,
    },
}

/// Sign a split and reserve its coin. Does not broadcast.
fn prepare_split(
    state: &mut WalletState,
    req: &SplitRequest,
    session: &str,
) -> Result<PreparedSplit, WalletError> {
    let preview = plan_split_request(state, req)?;
    let source_dir = state.data_dir.clone();
    match req.chain {
        SplitChain::Public => {
            let (psbt, fee_sats) = build_public_split_psbt(state, &req.input, &preview)?;
            let mut psbt = psbt;
            sign_and_finalize(&state.wallet, &state.signer, &mut psbt)?;
            let tx = psbt
                .extract_tx()
                .map_err(|e| WalletError::Sign(e.to_string()))?;
            let outpoint = parse_outpoint(&req.input)?;
            let hold = CoinHold::take_public(&source_dir, vec![outpoint], session)?;
            let electrum_candidates = electrum_candidates(state);
            let electrum_validate_domain = state.electrum_validate_domain;
            Ok(PreparedSplit::Public {
                source_dir,
                electrum_candidates,
                electrum_validate_domain,
                tx,
                fee_sats,
                output_count: preview.outputs.len() as u32,
                hold,
            })
        }
        SplitChain::Private => {
            let recipients: Vec<u64> = preview
                .outputs
                .iter()
                .filter(|o| !o.is_change)
                .map(|o| o.amount_sats)
                .collect();
            let route = broadcast_route(state);
            let network = state.network;
            let mweb = state
                .mweb
                .as_mut()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let signed = mweb::sign_mweb_split(
                &state.wallet,
                mweb,
                &source_dir,
                &req.input,
                &recipients,
                preview.fee_sats,
                network,
            )?;
            let hold = CoinHold::take(&source_dir, vec![signed.input_id.clone()], session)?;
            Ok(PreparedSplit::Private {
                source_dir,
                signed,
                route,
                hold,
            })
        }
    }
}

fn plan_split_request(
    state: &mut WalletState,
    req: &SplitRequest,
) -> Result<SplitPreview, WalletError> {
    match req.chain {
        SplitChain::Public => {
            let (_op, input_sats) = public_split_utxo(state, &req.input)?;
            let fee_rate_sat_vb = match req.fee_rate_sat_vb {
                Some(rate) if rate > 0 => rate,
                _ => {
                    let client = connect_electrum(state)?;
                    electrum::estimate_fee_rate_sat_vb(&client)?.0
                }
            };
            split::plan_split(&PlanParams {
                input_sats,
                equal_count: req.equal_count,
                amounts: req.amounts.clone(),
                fee_sats: req.fee_sats,
                fee_rate_sat_vb,
                public: true,
                mweb_fee: 0,
            })
        }
        SplitChain::Private => {
            let mweb = state
                .mweb
                .as_ref()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let tip = state.wallet.latest_checkpoint().height();
            let frozen = mweb_frozen::unavailable_ids(&state.data_dir)?;
            let coin = mweb::select_split_coin(mweb.store.db(), &req.input, tip, &frozen)?;
            split::plan_split(&PlanParams {
                input_sats: coin.amount,
                equal_count: req.equal_count,
                amounts: req.amounts.clone(),
                fee_sats: req.fee_sats,
                fee_rate_sat_vb: 0,
                public: false,
                mweb_fee: 0,
            })
        }
    }
}

/// Build a 1-in-N-out PSBT. Reveals N receive addresses and persists only after building & verifying.
fn build_public_split_psbt(
    state: &mut WalletState,
    input: &str,
    preview: &SplitPreview,
) -> Result<(Psbt, u64), WalletError> {
    let (op, _input_sats) = public_split_utxo(state, input)?;
    let start_idx = state.wallet.next_derivation_index(KeychainKind::External);
    let mut reveal_up_to = None;

    let recipients: Vec<(ScriptBuf, Amount)> = preview
        .outputs
        .iter()
        .filter(|o| !o.is_change)
        .enumerate()
        .map(|(i, o)| {
            let idx = start_idx.checked_add(i as u32).ok_or_else(|| {
                WalletError::BuildTx("external address index overflowed".into())
            })?;
            reveal_up_to = Some(idx);
            let addr = state.wallet.peek_address(KeychainKind::External, idx).address;
            let script = addr.script_pubkey();
            let min_non_dust = crate::tx_invariants::ltc_dust_threshold(&script);
            crate::tx_invariants::check_money(o.amount_sats, "split output")?;
            if o.amount_sats < min_non_dust {
                return Err(WalletError::BuildTx(format!(
                    "Output of {} litoshis is below the network dust limit ({min_non_dust} litoshis).",
                    o.amount_sats
                )));
            }
            Ok((script, Amount::from_sat(o.amount_sats)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut tx_builder = state
        .wallet
        .build_tx()
        .coin_selection(crate::tx_invariants::LitecoinDustCoinSelection);
    tx_builder
        .add_utxos(&[op])
        .map_err(|e| WalletError::BuildTx(e.to_string()))?;
    tx_builder.manually_selected_only();
    for (script, amount) in recipients {
        tx_builder.add_recipient(script, amount);
    }
    tx_builder.fee_absolute(Amount::from_sat(preview.fee_sats));
    let psbt = tx_builder
        .finish()
        .map_err(|e| WalletError::BuildTx(e.to_string()))?;
    if psbt.unsigned_tx.input.len() != 1 {
        return Err(WalletError::BuildTx("Split uses exactly one coin".into()));
    }
    let fee_sats = crate::tx_invariants::verify_transparent_psbt(&psbt)?;
    if fee_sats != preview.fee_sats {
        return Err(WalletError::BuildTx(format!(
            "built fee ({fee_sats} litoshis) does not match preview ({} litoshis)",
            preview.fee_sats
        )));
    }
    if let Some(end_idx) = reveal_up_to {
        let _ = state
            .wallet
            .reveal_addresses_to(KeychainKind::External, end_idx)
            .count();
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
    }
    Ok((psbt, fee_sats))
}

/// Peg-in coin selection leaves transparent change when selected inputs exceed amount+fee by at least P2WPKH dust.
fn pegin_selection_creates_change(
    state: &WalletState,
    resolved: &PeginRequest,
    total_from_transparent_sats: u64,
) -> bool {
    let dust = split::SPLIT_DUST_SATS;
    if let Some(ops) = resolved.selected_outpoints.as_ref() {
        let mut sum = 0u64;
        for raw in ops {
            let Ok(op) = parse_outpoint(raw) else {
                continue;
            };
            if let Some(utxo) = state.wallet.get_utxo(op) {
                sum = sum.saturating_add(utxo.txout.value.to_sat());
            }
        }
        return sum.saturating_sub(total_from_transparent_sats) >= dust;
    }
    let Ok(held) = mweb_frozen::public_reserved_outpoints(&state.data_dir) else {
        return false;
    };
    let amounts = selectable_public_utxo_amounts(state, &held);
    let mut sum = 0u64;
    for amt in amounts {
        sum = sum.saturating_add(amt);
        if sum >= total_from_transparent_sats {
            return sum.saturating_sub(total_from_transparent_sats) >= dust;
        }
    }
    false
}

fn mweb_selection_creates_change(
    state: &WalletState,
    req: &MwebSendRequest,
) -> Result<bool, WalletError> {
    mweb_inputs_exceed_needed(
        state,
        req.selected_output_ids.as_deref(),
        req.amount_sats,
        req.fee_sats,
        "spending",
        &[],
    )
}

fn pegout_selection_creates_change(
    state: &WalletState,
    req: &PegoutRequest,
) -> Result<bool, WalletError> {
    let (_dest, spk, _dust) =
        crate::tx_invariants::validate_public_recipient(&req.address, state.network)?;
    mweb_inputs_exceed_needed(
        state,
        req.selected_output_ids.as_deref(),
        req.amount_sats,
        req.fee_sats,
        "swapping",
        &[spk.as_script()],
    )
}

fn mweb_inputs_exceed_needed(
    state: &WalletState,
    selected: Option<&[String]>,
    amount_sats: u64,
    fee_sats: u64,
    action: &str,
    pegout_scripts: &[&Script],
) -> Result<bool, WalletError> {
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::unavailable_ids(&state.data_dir)?;
    let needed =
        crate::tx_invariants::checked_add_money(amount_sats, fee_sats, "MWEB spend needed")?;
    let coins = mweb::resolve_spend_coins(mweb.store.db(), tip, &frozen, selected, needed, action)?;
    let sum = crate::tx_invariants::checked_sum_sats(
        coins.iter().map(|c| c.amount),
        "MWEB selected coins",
    )?;
    if sum > needed {
        // Change adds one standard output (18 weight = 1,800 litoshis). A peg-out
        // script is extra weight on top of that, `ceil(script_len / 42)`.
        let total_outputs = usize::from(action == "spending") + 1;
        let min_fee =
            crate::tx_invariants::min_kernel_fee(total_outputs, pegout_scripts.iter().copied());
        if fee_sats < min_fee {
            return Err(WalletError::BuildTx(format!(
                "MWEB fee {fee_sats} litoshis is below the minimum {min_fee} litoshis when change is created"
            )));
        }
    }
    Ok(sum > needed)
}

fn collect_unspent(state: &WalletState) -> Vec<UtxoRecord> {
    let tip = state.wallet.local_chain().tip().height();
    let labels = utxo_labels::read_labels(&state.data_dir)
        .map(|f| f.labels)
        .unwrap_or_default();
    let held = mweb_frozen::public_reserved_outpoints(&state.data_dir).unwrap_or_default();
    let mut rows: Vec<UtxoRecord> = state
        .wallet
        .list_unspent()
        .map(|utxo| {
            let confirmations = utxo_confirmations(&utxo.chain_position, tip);
            let (mature, maturity_blocks_left) =
                public_utxo_maturity(&state.wallet, utxo.outpoint, tip, confirmations);
            let keychain = match utxo.keychain {
                KeychainKind::External => "external",
                KeychainKind::Internal => "internal",
            };
            let outpoint = utxo.outpoint.to_string();
            let label = labels.get(&outpoint).cloned().unwrap_or_default();
            let locked = state.wallet.is_outpoint_locked(utxo.outpoint);
            let (status, actions) = mweb::public_coin_status(&mweb::PublicCoinFacts {
                confirmations,
                mature,
                maturity_blocks_left,
                locked,
                reserved: held.contains(&utxo.outpoint),
            });
            UtxoRecord {
                outpoint,
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount_sats: utxo.txout.value.to_sat(),
                keychain: keychain.into(),
                confirmations,
                mature,
                maturity_blocks_left,
                locked,
                label,
                status,
                actions,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        b.confirmations
            .cmp(&a.confirmations)
            .then_with(|| b.amount_sats.cmp(&a.amount_sats))
            .then_with(|| a.outpoint.cmp(&b.outpoint))
    });
    rows
}

/// Find history peg-ins missing from the transparent graph and apply their spends.
/// Returns a user-facing warning when repair is still needed but no source worked.
/// Peg-in ids whose transparent transaction is not in the wallet yet.
fn missing_pegin_ids(state: &WalletState) -> Vec<String> {
    let Some(mweb) = state.mweb.as_ref() else {
        return Vec::new();
    };
    let db = mweb.store.db();
    mweb.history
        .entries
        .iter()
        .filter(|e| is_local_pegin_entry(e))
        .filter(|e| pegin_outputs_still_owed(e, db))
        .filter_map(|e| {
            let txid = parse_txid(&e.id)?;
            if state.wallet.get_tx(txid).is_some() {
                None
            } else {
                Some(e.id.clone())
            }
        })
        .collect()
}

/// How long a dead RPC node, Electrum fallback, or explorer may stall one
/// repair attempt. A missing peg-in is retried on a later sync.
const PEGIN_REPAIR_FALLBACK: std::time::Duration = std::time::Duration::from_secs(2);
/// Cap across all slow fallback sources for one missing peg-in so multiple
/// unreachable endpoints cannot stack 2-second timeouts sequentially.
const PEGIN_REPAIR_TOTAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);
/// After the slow fallbacks fail, skip them for this long. The server that
/// just synced is still asked, because that call is already connected.
const PEGIN_REPAIR_BACKOFF: std::time::Duration = std::time::Duration::from_secs(10 * 60);

struct PeginFetchFailure {
    message: String,
    /// At least two independent indexers explicitly reported that the txid does
    /// not exist in the mempool or blockchain.
    confirmed_absent: bool,
}

impl std::ops::Deref for PeginFetchFailure {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl std::fmt::Display for PeginFetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn pegin_has_onchain_mweb_output(state: &WalletState, entry_id: &str) -> bool {
    let Some(mweb) = state.mweb.as_ref() else {
        return false;
    };
    let Some(entry) = mweb.history.entries.iter().find(|e| e.id == entry_id) else {
        return false;
    };
    if entry.confirmed_height.is_some() {
        return true;
    }
    let db = mweb.store.db();
    entry.output_ids.iter().any(|oid_hex| {
        hex::decode(oid_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|id| db.get(&id).or_else(|| db.get_spent(&id)))
            .is_some_and(|coin| coin.leaf_index.is_some())
    })
}

fn prune_unlanded_pegin(state: &mut WalletState, entry_id: &str) {
    let Some(ref mut mweb) = state.mweb else {
        return;
    };
    let output_ids: Vec<String> = mweb
        .history
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .map(|e| e.output_ids.clone())
        .unwrap_or_default();
    for oid_hex in output_ids {
        if let Some(id) = hex::decode(&oid_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        {
            if mweb
                .store
                .db()
                .get(&id)
                .is_some_and(|c| c.leaf_index.is_none())
            {
                let _ = mweb.store.db_mut().mark_spent(&id);
            }
        }
    }
    mweb.history.forget_ids(&[entry_id.to_string()]);
    let _ = mweb.persist(&state.data_dir);
    diag::log(format!(
        "sync: pruned unlanded peg-in {entry_id} confirmed absent by 2+ indexers"
    ));
}

/// A peg-in txid is live only while the wallet still treats it as canonical
/// and the mempool eviction stamp has not caught up with `last_seen`.
fn peg_in_tx_still_live(wallet: &PersistedWallet<Connection>, id: &str) -> bool {
    let Some(txid) = parse_txid(id) else {
        return false;
    };
    if wallet
        .tx_graph()
        .get_tx_node(txid)
        .is_some_and(|node| node.is_evicted())
    {
        return false;
    }
    wallet.get_tx(txid).is_some()
}

/// The transparent peg-in is still unconfirmed in this wallet.
fn pegin_tx_is_unconfirmed(wallet: &PersistedWallet<Connection>, id: &str) -> bool {
    let Some(txid) = parse_txid(id) else {
        return false;
    };
    if wallet
        .tx_graph()
        .get_tx_node(txid)
        .is_some_and(|node| node.is_evicted())
    {
        return false;
    }
    matches!(
        wallet.get_tx(txid).as_ref().map(|tx| &tx.pos),
        Some(ChainPosition::Unconfirmed { .. })
    )
}

/// Drop the tip height `apply_pegin_locally` used to stamp at broadcast.
///
/// A peg-in with no output leaf is not in a block. Electrum also leaves a
/// confirmed hybrid transaction unconfirmed, so a coin that already has a leaf
/// keeps its height.
fn clear_unproven_pegin_heights(state: &mut WalletState) {
    let targets: Vec<(String, Vec<String>, Option<u32>)> = {
        let Some(mweb) = state.mweb.as_ref() else {
            return;
        };
        mweb.history
            .entries
            .iter()
            .filter(|entry| {
                is_local_pegin_entry(entry) && pegin_tx_is_unconfirmed(&state.wallet, &entry.id)
            })
            .map(|entry| {
                (
                    entry.id.clone(),
                    entry.output_ids.clone(),
                    entry.confirmed_height,
                )
            })
            .collect()
    };
    if targets.is_empty() {
        return;
    }
    let Some(mweb) = state.mweb.as_mut() else {
        return;
    };
    let mut cleared = 0u32;
    for (id, outputs, confirmed_height) in targets {
        let mut saw_leaf = false;
        let mut cleared_coin = false;
        for oid_hex in &outputs {
            let Some(oid) = hex::decode(oid_hex)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            else {
                continue;
            };
            let Some(coin) = mweb.store.db().get(&oid).cloned() else {
                continue;
            };
            if coin.leaf_index.is_some() {
                saw_leaf = true;
                continue;
            }
            if coin.block_height.is_some() {
                let mut coin = coin;
                coin.block_height = None;
                mweb.store.db_mut().insert(coin);
                cleared_coin = true;
            }
        }
        if cleared_coin && !saw_leaf && confirmed_height.is_some() {
            if let Some(entry) = mweb.history.entries.iter_mut().find(|entry| entry.id == id) {
                entry.confirmed_height = None;
            }
        }
        if cleared_coin {
            cleared += 1;
        }
    }
    if cleared == 0 {
        return;
    }
    let _ = mweb.persist(&state.data_dir);
    diag::log(format!(
        "sync: cleared broadcast height on {cleared} unconfirmed peg-in(s)"
    ));
}

fn pegin_anchor_height(wallet: &bdk_wallet::Wallet, txid: Txid) -> Option<u32> {
    match wallet.get_tx(txid)?.pos {
        ChainPosition::Confirmed { anchor, .. } => Some(anchor.block_id.height),
        ChainPosition::Unconfirmed { .. } => None,
    }
}

/// A mined peg-in is relayed, whatever the broadcast echo said. A peg-in that
/// stays out of the server's history past the grace is the one Clear can drop.
fn note_pegin_chain_status(
    state: &mut WalletState,
    unreported: &std::collections::BTreeSet<Txid>,
) -> Result<(), WalletError> {
    let now = crate::mweb_history::now_ts();
    let mut notes = Vec::new();
    let Some(mweb) = state.mweb.as_ref() else {
        return Ok(());
    };
    for entry in &mweb.history.entries {
        if !is_local_pegin_entry(entry) {
            continue;
        }
        let on_chain = pegin_output_has_leaf(entry, mweb.store.db());
        let height = entry.confirmed_height.or_else(|| {
            parse_txid(&entry.id).and_then(|id| pegin_anchor_height(&state.wallet, id))
        });
        let confirmed = height.is_some() || on_chain;
        let (relayed, absent) = if confirmed {
            (true, false)
        } else {
            let unseen = parse_txid(&entry.id).is_some_and(|id| unreported.contains(&id));
            let old = now.saturating_sub(entry.timestamp) >= PEGIN_ABSENT_GRACE_SECS;
            (entry.relayed, unseen && old)
        };
        let undated_coin = height.is_some_and(|h| {
            entry.output_ids.iter().any(|oid_hex| {
                hex::decode(oid_hex)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    .and_then(|id| mweb.store.db().get(&id))
                    .is_some_and(|coin| coin.block_height != Some(h))
            })
        });
        if entry.relayed == relayed
            && entry.absent == absent
            && (height.is_none() || entry.confirmed_height == height)
            && !undated_coin
        {
            continue;
        }
        notes.push((
            entry.id.clone(),
            relayed,
            absent,
            height,
            entry.output_ids.clone(),
            undated_coin,
        ));
    }
    if notes.is_empty() {
        return Ok(());
    }
    let Some(mweb) = state.mweb.as_mut() else {
        return Ok(());
    };
    for (id, relayed, absent, height, output_ids, undated_coin) in notes {
        if let Some(entry) = mweb.history.entries.iter_mut().find(|entry| entry.id == id) {
            entry.relayed = relayed;
            entry.absent = absent;
            if entry.confirmed_height.is_none() {
                entry.confirmed_height = height;
            }
        }
        if undated_coin {
            if let Some(h) = height {
                for oid_hex in output_ids {
                    let Some(id) = hex::decode(&oid_hex)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    else {
                        continue;
                    };
                    if mweb.store.db().get(&id).is_some() {
                        let _ = mweb.store.db_mut().set_block_height(&id, h);
                    }
                }
            }
        }
        diag::log(format!(
            "pegin: {} relayed={relayed} absent={absent} height={}",
            id,
            height.map(|h| h.to_string()).unwrap_or_else(|| "-".into())
        ));
    }
    mweb.persist(&state.data_dir)
}

fn clear_unrelayed_pegin(state: &mut WalletState, txid: &str) -> Result<(), WalletError> {
    let entry = state
        .mweb
        .as_ref()
        .and_then(|mweb| mweb.history.entries.iter().find(|entry| entry.id == txid))
        .cloned()
        .ok_or_else(|| WalletError::Mweb("That peg-in is not in this wallet.".into()))?;
    let on_chain = state
        .mweb
        .as_ref()
        .is_some_and(|mweb| pegin_output_has_leaf(&entry, mweb.store.db()));
    let tx_confirmed = parse_txid(txid).is_some_and(|id| {
        state
            .wallet
            .get_tx(id)
            .is_some_and(|tx| matches!(tx.pos, ChainPosition::Confirmed { .. }))
    });
    if !spend_can_clear(&entry, tx_confirmed, on_chain) {
        return Err(WalletError::Mweb(
            "This transaction is on the network and cannot be cleared.".into(),
        ));
    }
    if entry.kind == TxKind::Pegout {
        let Some(mweb) = state.mweb.as_mut() else {
            return Err(WalletError::Mweb("MWEB runtime not initialized".into()));
        };
        for oid_hex in entry.input_ids.iter().chain(entry.output_ids.iter()) {
            let Some(id) = hex::decode(oid_hex)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            else {
                continue;
            };
            if entry.input_ids.iter().any(|hex_id| hex_id == oid_hex) {
                let _ = mweb.store.db_mut().restore_spent(&id);
            }
            if entry.output_ids.iter().any(|hex_id| hex_id == oid_hex)
                && mweb
                    .store
                    .db()
                    .get(&id)
                    .is_some_and(|coin| coin.leaf_index.is_none())
            {
                let _ = mweb.store.db_mut().mark_spent(&id);
            }
        }
        mweb.history.forget_ids(&[txid.to_string()]);
        mweb.persist(&state.data_dir)?;
        diag::log(format!("pegout: cleared unrelayed {txid}"));
        return Ok(());
    }
    if let Some(id) = parse_txid(txid) {
        if state.wallet.get_tx(id).is_some() {
            let seen = state
                .wallet
                .tx_graph()
                .get_tx_node(id)
                .and_then(|node| node.last_seen)
                .unwrap_or(0);
            let ts = crate::mweb_history::now_ts().max(seen);
            state.wallet.apply_evicted_txs([(id, ts)]);
            state
                .wallet
                .persist(&mut state.db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
        }
    }
    let Some(mweb) = state.mweb.as_mut() else {
        return Err(WalletError::Mweb("MWEB runtime not initialized".into()));
    };
    for oid_hex in &entry.output_ids {
        let Some(id) = hex::decode(oid_hex)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        else {
            continue;
        };
        if mweb
            .store
            .db()
            .get(&id)
            .is_some_and(|coin| coin.leaf_index.is_none())
        {
            let _ = mweb.store.db_mut().mark_spent(&id);
        }
    }
    mweb.history.forget_ids(&[txid.to_string()]);
    mweb.persist(&state.data_dir)?;
    diag::log(format!("pegin: cleared unrelayed {txid}"));
    Ok(())
}

fn forget_dropped_pegins(state: &mut WalletState) {
    let dropped: Vec<String> = {
        let Some(mweb) = state.mweb.as_ref() else {
            return;
        };
        let db = mweb.store.db();
        mweb.history
            .entries
            .iter()
            .filter(|entry| {
                let tx_in_wallet = peg_in_tx_still_live(&state.wallet, &entry.id);
                is_dropped_local_pegin(entry, tx_in_wallet, pegin_outputs_still_owed(entry, db))
            })
            .map(|entry| entry.id.clone())
            .collect()
    };
    if dropped.is_empty() {
        return;
    }
    let Some(mweb) = state.mweb.as_mut() else {
        return;
    };
    let outputs: Vec<String> = mweb
        .history
        .entries
        .iter()
        .filter(|entry| dropped.iter().any(|id| id == &entry.id))
        .flat_map(|entry| entry.output_ids.clone())
        .collect();
    for oid_hex in outputs {
        let Some(id) = hex::decode(&oid_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        else {
            continue;
        };
        if mweb
            .store
            .db()
            .get(&id)
            .is_some_and(|coin| coin.leaf_index.is_none())
        {
            let _ = mweb.store.db_mut().mark_spent(&id);
        }
    }
    mweb.history.forget_ids(&dropped);
    let _ = mweb.persist(&state.data_dir);
    diag::log(format!(
        "sync: forgot {} dropped peg-in history row(s): {}",
        dropped.len(),
        dropped.join(", ")
    ));
}

fn repair_missing_pegin_spends(
    app: &WalletApp,
    state: &mut WalletState,
    client: &crate::electrum::ElectrumClient,
) -> Result<Option<String>, WalletError> {
    let missing = missing_pegin_ids(state);
    if missing.is_empty() {
        return Ok(None);
    }

    let mut repaired = 0u32;
    let mut still_missing = 0u32;
    let mut last_err: Option<String> = None;
    for id in &missing {
        let allow_fallbacks = app.pegin_fallback_due(id);
        match fetch_pegin_raw_tx(id, client, state, allow_fallbacks) {
            Ok(tx) => {
                app.note_pegin_fallback(id, false);
                mweb::apply_pegin_transparent_spend(&mut state.wallet, Arc::unwrap_or_clone(tx));
                repaired += 1;
            }
            Err(failure) => {
                if failure.confirmed_absent && !pegin_has_onchain_mweb_output(state, id) {
                    app.note_pegin_fallback(id, false);
                    prune_unlanded_pegin(state, id);
                    continue;
                }
                if allow_fallbacks {
                    app.note_pegin_fallback(id, true);
                }
                last_err = Some(failure.message);
                still_missing += 1;
            }
        }
    }
    if repaired > 0 {
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
    }
    if still_missing > 0 {
        if let Some(err) = &last_err {
            eprintln!("pegin repair: {err}");
        }
        let short = missing
            .first()
            .map(|id| {
                if id.len() > 16 {
                    format!("{}…{}", &id[..8], &id[id.len() - 8..])
                } else {
                    id.clone()
                }
            })
            .unwrap_or_default();
        Ok(Some(format!(
            "Could not repair {still_missing} peg-in spend(s) ({short}). \
             Transparent balance may be overstated. Start litecoind (RPC on {}) \
             or set Litecoin RPC in Settings, then sync again.",
            state.network.default_rpc_url()
        )))
    } else if repaired > 0 {
        Ok(Some(format!(
            "Repaired {repaired} peg-in spend(s) so transparent balance matches Private funds."
        )))
    } else {
        Ok(None)
    }
}

fn is_explicit_tx_not_found(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("no such mempool or blockchain transaction")
        || lower.contains("status code 404")
        || (lower.contains("tx ") && lower.contains(" not found"))
}

/// Fetch peg-in raw tx bytes. Electrum often omits MWEB peg-ins, so we also try
/// configured RPC, a stock local litecoind, other Electrum servers, and (mainnet)
/// a public explorer hex endpoint.
fn fetch_pegin_raw_tx(
    txid_hex: &str,
    client: &crate::electrum::ElectrumClient,
    state: &WalletState,
    allow_fallbacks: bool,
) -> Result<Arc<Transaction>, PeginFetchFailure> {
    use bdk_electrum::electrum_client::ElectrumApi;

    let mut errors: Vec<String> = Vec::new();
    let mut absent_confirmations = 0u32;
    let txid = parse_txid(txid_hex).ok_or_else(|| PeginFetchFailure {
        message: format!("invalid peg-in txid {txid_hex}"),
        confirmed_absent: false,
    })?;
    // Every source is untrusted: bytes count only when they are the asked-for tx.
    let accept = |raw: Vec<u8>, source: &str, errors: &mut Vec<String>| {
        spv::verify_transaction(&raw, &txid)
            .map_err(|e| errors.push(format!("{source}: {e}")))
            .ok()
    };

    match client.inner.transaction_get_raw(&txid) {
        Ok(raw) if !raw.is_empty() => {
            if let Some(tx) = accept(raw, "sync Electrum", &mut errors) {
                return Ok(tx);
            }
        }
        Ok(_) => errors.push("sync Electrum returned empty tx".into()),
        Err(e) => {
            let msg = e.to_string();
            if is_explicit_tx_not_found(&msg) {
                absent_confirmations += 1;
            }
            errors.push(format!("sync Electrum: {msg}"));
        }
    }

    if !allow_fallbacks {
        return Err(PeginFetchFailure {
            message: errors.join("; "),
            confirmed_absent: false,
        });
    }

    let fallback_deadline = std::time::Instant::now() + PEGIN_REPAIR_TOTAL_BUDGET;
    let remaining_timeout = |deadline: std::time::Instant| -> Option<std::time::Duration> {
        let left = deadline.checked_duration_since(std::time::Instant::now())?;
        if left.is_zero() {
            None
        } else {
            Some(left.min(PEGIN_REPAIR_FALLBACK))
        }
    };

    let mut rpc_urls: Vec<String> = Vec::new();
    if let Some(url) = &state.litecoin_rpc_url {
        rpc_urls.push(url.clone());
    }
    let local = state.network.default_rpc_url().to_string();
    if !rpc_urls.iter().any(|u| u == &local) {
        rpc_urls.push(local);
    }
    for url in &rpc_urls {
        let Some(timeout) = remaining_timeout(fallback_deadline) else {
            break;
        };
        let safe_url = crate::redact::redact_userinfo(url);
        match crate::rpc::get_raw_transaction_hex_within_for_network(
            url,
            txid_hex,
            timeout,
            Some(state.network),
        ) {
            Ok(hex) => match hex::decode(hex.trim()) {
                Ok(raw) if !raw.is_empty() => {
                    if let Some(tx) = accept(raw, &format!("RPC {safe_url}"), &mut errors) {
                        return Ok(tx);
                    }
                }
                Ok(_) => errors.push(format!("RPC {safe_url}: empty hex")),
                Err(e) => errors.push(format!("RPC {safe_url}: bad hex ({e})")),
            },
            Err(e) => {
                let msg = e.to_string();
                if is_explicit_tx_not_found(&msg) {
                    absent_confirmations += 1;
                }
                errors.push(format!("RPC {safe_url}: {msg}"));
            }
        }
    }

    if state.network == WalletNetwork::Mainnet
        && absent_confirmations < 2
        && remaining_timeout(fallback_deadline).is_some()
    {
        match fetch_tx_hex_litecoinspace(txid_hex) {
            Ok(raw) => {
                if let Some(tx) = accept(raw, "litecoinspace", &mut errors) {
                    return Ok(tx);
                }
            }
            Err(e) => {
                if is_explicit_tx_not_found(&e) {
                    absent_confirmations += 1;
                }
                errors.push(format!("litecoinspace: {e}"));
            }
        }
    }

    // Other Electrum servers may still hold the raw bytes even when the sync
    // server refuses MWEB txs. Skip them once two indexers already confirmed
    // the transaction does not exist on chain.
    for url in electrum_candidates(state) {
        if absent_confirmations >= 2 {
            break;
        }
        if state.active_electrum_url.as_deref() == Some(url.as_str()) {
            continue;
        }
        let Some(timeout) = remaining_timeout(fallback_deadline) else {
            break;
        };
        let timeout_secs = (timeout.as_secs() as u8).max(1);
        let safe_url = crate::redact::redact_userinfo(&url);
        match electrum::connect_with_timeout(&url, state.electrum_validate_domain, timeout_secs) {
            Ok(alt) => {
                if let Err(e) = electrum::handshake(&alt) {
                    errors.push(format!("{safe_url}: {e}"));
                    continue;
                }
                match alt.inner.transaction_get_raw(&txid) {
                    Ok(raw) if !raw.is_empty() => {
                        if let Some(tx) = accept(raw, &safe_url, &mut errors) {
                            return Ok(tx);
                        }
                    }
                    Ok(_) => errors.push(format!("{safe_url}: empty tx")),
                    Err(e) => {
                        let msg = e.to_string();
                        if is_explicit_tx_not_found(&msg) {
                            absent_confirmations += 1;
                        }
                        errors.push(format!("{safe_url}: {msg}"));
                    }
                }
            }
            Err(e) => errors.push(format!("{safe_url}: {e}")),
        }
    }

    Err(PeginFetchFailure {
        message: errors.join("; "),
        confirmed_absent: absent_confirmations >= 2,
    })
}

fn fetch_tx_hex_litecoinspace(txid_hex: &str) -> Result<Vec<u8>, String> {
    let url = format!("https://litecoinspace.org/api/tx/{txid_hex}/hex");
    let body = ureq::get(&url)
        .timeout(PEGIN_REPAIR_FALLBACK)
        .set("Accept", "text/plain")
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let hex = body.trim();
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("response was not hex".into());
    }
    hex::decode(hex).map_err(|e| e.to_string())
}

/// `Err` when the request's freeze or unfreeze flag is off. `None` for the
/// blocked reason means the coin is not frozen, so Unfreeze has nothing to do.
fn refuse_freeze_flag(locking: bool, actions: crate::dto::CoinActions) -> Result<(), String> {
    let allowed = if locking {
        actions.freeze
    } else {
        actions.unfreeze
    };
    if allowed {
        return Ok(());
    }
    Err(match (locking, actions.blocked) {
        (false, None) => "This coin is not frozen.".into(),
        (_, Some(block)) => mweb::coin_block_message(block),
        (true, None) => "This coin cannot be frozen.".into(),
    })
}

/// Freeze or unfreeze a private coin. A coin that is not in the listing keeps
/// today's behaviour, so a stale freeze can still be cleared.
fn set_private_freeze(
    state: &WalletState,
    req: SetMwebUtxoLockedRequest,
) -> Result<(), WalletError> {
    let target = if req.locked { "frozen" } else { "unfrozen" };
    let from = if req.locked { "unfrozen" } else { "frozen" };
    let coin = req.output_id.trim();
    if let Err(err) = refuse_churn_unfreeze(&state.data_dir, &req.output_id, req.locked) {
        diag::log(format!(
            "coin-freeze: rejected kind=private coin={coin} from={from} to={target} reason={err}"
        ));
        return Err(err);
    }
    if let Err(err) = refuse_reserved(&state.data_dir, &req.output_id) {
        diag::log(format!(
            "coin-freeze: rejected kind=private coin={coin} from={from} to={target} reason={err}"
        ));
        return Err(err);
    }
    if let Some(mweb) = state.mweb.as_ref() {
        if let Ok(id) = mweb_frozen::normalize_output_id(&req.output_id) {
            let tip = state.wallet.latest_checkpoint().height();
            if let Some(row) = mweb::list_mweb_unspent(mweb, tip, &state.data_dir)
                .into_iter()
                .find(|row| row.output_id == id)
            {
                if let Err(msg) = refuse_freeze_flag(req.locked, row.actions) {
                    diag::log(format!(
                        "coin-freeze: rejected kind=private coin={id} from={:?} to={target} reason={msg}",
                        row.status
                    ));
                    return Err(WalletError::Mweb(msg));
                }
            }
        }
    }
    mweb_frozen::set_locked(&state.data_dir, &req.output_id, req.locked)?;
    if let Ok(id) = mweb_frozen::normalize_output_id(&req.output_id) {
        diag::log(format!(
            "coin-freeze: phase {from} -> {target} kind=private coin={id} reason=user freeze command"
        ));
    }
    Ok(())
}

/// Freeze or unfreeze a public coin. An outpoint that is not in the listing
/// keeps today's behaviour.
fn set_public_freeze(
    state: &mut WalletState,
    req: SetUtxoLockedRequest,
) -> Result<(), WalletError> {
    let target = if req.locked { "frozen" } else { "unfrozen" };
    let from = if req.locked { "unfrozen" } else { "frozen" };
    let outpoint = parse_outpoint(&req.outpoint).inspect_err(|err| {
        diag::log(format!(
            "coin-freeze: rejected kind=public coin={} from={from} to={target} reason={err}",
            req.outpoint.trim()
        ));
    })?;
    if let Err(err) = refuse_reserved_public(&state.data_dir, outpoint) {
        diag::log(format!(
            "coin-freeze: rejected kind=public coin={outpoint} from={from} to={target} reason={err}"
        ));
        return Err(err);
    }
    if let Some(row) = collect_unspent(state)
        .into_iter()
        .find(|row| row.outpoint == outpoint.to_string())
    {
        if let Err(msg) = refuse_freeze_flag(req.locked, row.actions) {
            diag::log(format!(
                "coin-freeze: rejected kind=public coin={outpoint} from={:?} to={target} reason={msg}",
                row.status
            ));
            return Err(WalletError::BuildTx(msg));
        }
    }
    if req.locked {
        state.wallet.lock_outpoint(outpoint);
    } else {
        state.wallet.unlock_outpoint(outpoint);
    }
    state
        .wallet
        .persist(&mut state.db)
        .map_err(|e| WalletError::Persist(e.to_string()))?;
    diag::log(format!(
        "coin-freeze: phase {from} -> {target} kind=public coin={outpoint} reason=user freeze command"
    ));
    Ok(())
}

fn refuse_churn_unfreeze(
    data_dir: &Path,
    output_id: &str,
    locked: bool,
) -> Result<(), WalletError> {
    if locked {
        return Ok(());
    }
    if churn::held_by_active_job(data_dir, output_id)? {
        return Err(WalletError::Mweb("A self-spend has this coin.".into()));
    }
    Ok(())
}

/// A spend's hold on its inputs, from signing until the broadcast is settled.
/// Released on drop unless [`Self::defuse`] is called after a broadcast whose
/// local post-broadcast commit failed.
struct CoinHold {
    data_dir: PathBuf,
    inputs: HeldInputs,
    defused: bool,
}

enum HeldInputs {
    Private(Vec<String>),
    Public(Vec<OutPoint>),
}

impl CoinHold {
    fn take(data_dir: &Path, ids: Vec<String>, session: &str) -> Result<Self, WalletError> {
        mweb_frozen::reserve(data_dir, &ids, session)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            inputs: HeldInputs::Private(ids),
            defused: false,
        })
    }

    fn take_public(
        data_dir: &Path,
        outpoints: Vec<OutPoint>,
        session: &str,
    ) -> Result<Self, WalletError> {
        mweb_frozen::reserve_public(data_dir, &outpoints, session)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            inputs: HeldInputs::Public(outpoints),
            defused: false,
        })
    }

    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for CoinHold {
    fn drop(&mut self) {
        if self.defused {
            return;
        }
        let released = match &self.inputs {
            HeldInputs::Private(ids) => mweb_frozen::release(&self.data_dir, ids),
            HeldInputs::Public(outpoints) => mweb_frozen::release_public(&self.data_dir, outpoints),
        };
        if let Err(e) = released {
            diag::log(format!("coin hold: release failed: {e}"));
        }
    }
}

fn refuse_reserved(data_dir: &Path, output_id: &str) -> Result<(), WalletError> {
    let id = mweb_frozen::normalize_output_id(output_id)?;
    if mweb_frozen::read_ids(data_dir)?.reserved.contains_key(&id) {
        return Err(WalletError::Mweb(mweb_frozen::RESERVED_MESSAGE.into()));
    }
    Ok(())
}

fn refuse_reserved_public(data_dir: &Path, outpoint: OutPoint) -> Result<(), WalletError> {
    if mweb_frozen::public_reserved_outpoints(data_dir)?.contains(&outpoint) {
        return Err(WalletError::BuildTx(mweb_frozen::RESERVED_MESSAGE.into()));
    }
    Ok(())
}

fn hash_at(
    wallet: &PersistedWallet<Connection>,
    height: u32,
) -> Option<bdk_wallet::bitcoin::BlockHash> {
    if wallet.latest_checkpoint().height() == height {
        return Some(wallet.latest_checkpoint().hash());
    }
    wallet.local_chain().get(height).map(|cp| cp.hash())
}

/// The local chain's hash at `height`, else a header an earlier sync verified,
/// else a server header that passes Litecoin proof of work.
fn block_hash_at(
    wallet: &PersistedWallet<Connection>,
    account_dir: &Path,
    network: WalletNetwork,
    electrum: Option<&electrum::ElectrumClient>,
    height: u32,
) -> Option<bdk_wallet::bitcoin::BlockHash> {
    if let Some(hash) = hash_at(wallet, height) {
        return Some(hash);
    }
    if let Some(header) = spv::verified_header_at(account_dir, height) {
        return Some(header.block_hash());
    }
    let header = electrum?.inner.block_header(height as usize).ok()?;
    spv::verify_header_pow(&header, height, network).ok()
}

enum ResolvedHop {
    Scored { height: u32, score: churn::HopScore },
    NotYet,
    NotIncluded,
}

/// What one scoring pass saw. Formatted onto `ChurnJob::last_check`.
#[derive(Default)]
struct HopCheck {
    tip: u32,
    anchor: Option<mweb::CoinAnchor>,
    parent_mmr: Option<u64>,
    tip_mmr: Option<u64>,
    inputs_unspent: Option<bool>,
    hunt: Option<churn::LeafHunt>,
    leaf: Option<u64>,
    located: Option<churn::LeafBlock>,
    first_unread: Option<u32>,
    peers: usize,
    exit: &'static str,
}

fn fmt_opt<T: std::fmt::Debug>(v: Option<T>) -> String {
    match v {
        Some(v) => format!("{v:?}"),
        None => "-".to_string(),
    }
}

impl HopCheck {
    fn line(&self) -> String {
        format!(
            "tip={} anchor_height={} anchor_leaf={} mmr_at_broadcast={} mmr_at_tip={} \
             inputs_unspent={} hunt={} leaf={} located={} first_unread={} peers={} exit={}",
            self.tip,
            fmt_opt(self.anchor.and_then(|a| a.height)),
            fmt_opt(self.anchor.and_then(|a| a.leaf_index)),
            fmt_opt(self.parent_mmr),
            fmt_opt(self.tip_mmr),
            fmt_opt(self.inputs_unspent),
            fmt_opt(self.hunt),
            fmt_opt(self.leaf),
            fmt_opt(self.located),
            fmt_opt(self.first_unread),
            self.peers,
            self.exit,
        )
    }
}

/// Header reads for one hop. Seeded from the job's height-keyed cache and the
/// sync height map, so a pass that lost its peer halfway does not start over.
struct HopReader<'a> {
    wallet: &'a PersistedWallet<Connection>,
    account_dir: &'a Path,
    network: WalletNetwork,
    electrum: Option<&'a electrum::ElectrumClient>,
    lookup: mweb::MmrLookup,
    height_map: &'a std::collections::BTreeMap<u32, u64>,
    cache: &'a mut std::collections::BTreeMap<u32, churn::MmrSizes>,
    first_unread: Option<u32>,
}

impl HopReader<'_> {
    fn sizes_at(&mut self, height: u32) -> Option<churn::MmrSizes> {
        if let Some(hit) = self.cache.get(&height) {
            return Some(*hit);
        }
        let fetched = block_hash_at(
            self.wallet,
            self.account_dir,
            self.network,
            self.electrum,
            height,
        )
        .and_then(|hash| self.lookup.get(hash));
        match fetched {
            Some(sizes) => {
                self.cache.insert(height, sizes);
                Some(sizes)
            }
            None => {
                self.first_unread = Some(self.first_unread.map_or(height, |h| h.min(height)));
                None
            }
        }
    }

    fn output_mmr_at(&mut self, height: u32) -> Option<u64> {
        if let Some(hit) = self.cache.get(&height) {
            return Some(hit.output_mmr_size);
        }
        if let Some(size) = self.height_map.get(&height) {
            return Some(*size);
        }
        self.sizes_at(height).map(|sizes| sizes.output_mmr_size)
    }
}

/// Score the one block whose output MMR crosses `leaf`.
fn score_known_leaf(
    reader: &mut HopReader<'_>,
    check: &mut HopCheck,
    broadcast: u32,
    tip: u32,
    leaf: u64,
) -> churn::InclusionFind {
    let located =
        churn::locate_leaf_block(broadcast, tip, leaf, |height| reader.output_mmr_at(height));
    check.located = Some(located);
    let churn::LeafBlock::Found(height) = located else {
        check.exit = "leaf-not-located";
        return churn::InclusionFind::NotYet;
    };
    let Some(parent_height) = height.checked_sub(1) else {
        check.exit = "no-parent";
        return churn::InclusionFind::NotYet;
    };
    let score = churn::score_1in1_hop(reader.sizes_at(parent_height), reader.sizes_at(height));
    match score {
        churn::HopScore::Unscored => {
            check.exit = "inclusion-pair-unscored";
            churn::InclusionFind::NotYet
        }
        score => {
            check.exit = "scored";
            churn::InclusionFind::Found { height, score }
        }
    }
}

fn score_saved_window(
    state: &WalletState,
    electrum: Option<&electrum::ElectrumClient>,
    job: &churn::ChurnJob,
) -> ResolvedHop {
    let output_id = job.current_output_id.as_str();
    let Some(anchor) = state
        .mweb
        .as_ref()
        .and_then(|mweb| mweb::coin_anchor(mweb, output_id))
    else {
        return ResolvedHop::NotYet;
    };
    let tip = state.wallet.latest_checkpoint().height();
    let dated = anchor.height.unwrap_or(tip);
    match score_hop_window(
        state,
        electrum,
        job.broadcast_height,
        dated,
        anchor.leaf_index,
    ) {
        churn::InclusionFind::Found { height, score } => ResolvedHop::Scored { height, score },
        churn::InclusionFind::NotYet => ResolvedHop::NotYet,
    }
}

/// Find the hop in `(broadcast, tip]`. A leaf index picks the block. Without one,
/// the stored leafset says whether the spend landed, then the new output is
/// looked up among leaves created since broadcast.
///
/// Writes what it saw onto `job.last_check` and keeps header reads in
/// `job.header_cache`; the caller persists the job.
fn resolve_waiting_hop(
    state: &mut WalletState,
    electrum: Option<&electrum::ElectrumClient>,
    job: &mut churn::ChurnJob,
) -> ResolvedHop {
    let Some(broadcast) = job.broadcast_height else {
        job.last_check = Some("no broadcast height; scored the saved window".into());
        return score_saved_window(state, electrum, job);
    };
    let mut check = HopCheck {
        tip: state.wallet.latest_checkpoint().height(),
        ..HopCheck::default()
    };
    let resolved = resolve_after_broadcast(state, electrum, job, broadcast, &mut check);
    let line = check.line();
    eprintln!("churn check: {line}");
    job.last_check = Some(line);
    resolved
}

fn resolve_after_broadcast(
    state: &mut WalletState,
    electrum: Option<&electrum::ElectrumClient>,
    job: &mut churn::ChurnJob,
    broadcast: u32,
    check: &mut HopCheck,
) -> ResolvedHop {
    let tip = check.tip;
    if tip <= broadcast {
        check.exit = "tip-at-broadcast";
        return ResolvedHop::NotYet;
    }
    let output_id = job.current_output_id.clone();
    let Some(mweb) = state.mweb.as_ref() else {
        check.exit = "no-mweb";
        return ResolvedHop::NotYet;
    };
    let Some(anchor) = mweb::coin_anchor(mweb, &output_id) else {
        check.exit = "coin-not-unspent";
        return ResolvedHop::NotYet;
    };
    check.anchor = Some(anchor);
    check.inputs_unspent = job
        .pending_wtxid
        .as_deref()
        .and_then(|wtxid| mweb::churn_inputs_still_unspent(mweb, wtxid));
    let height_map = mweb.sync_state.height_map.clone();
    let addrs = mweb::peers_for_headers(&state.mweb_peers, state.network, mweb.last_good_peer);
    check.peers = addrs.len();
    let tip_hash = state.wallet.latest_checkpoint().hash();

    let mut reader = HopReader {
        wallet: &state.wallet,
        account_dir: &state.data_dir,
        network: state.network,
        electrum,
        lookup: mweb::MmrLookup::new(addrs, state.network),
        height_map: &height_map,
        cache: &mut job.header_cache,
        first_unread: None,
    };
    let mut new_leaf = None;
    let outcome = 'resolve: {
        let leaf = if let Some(leaf) = anchor.leaf_index {
            leaf
        } else {
            if let Some(verdict) = churn::leafset_verdict(broadcast, tip, check.inputs_unspent) {
                check.exit = match verdict {
                    churn::UndatedHop::NotIncluded => "leafset-not-included",
                    _ => "leafset-still-waiting",
                };
                break 'resolve match verdict {
                    churn::UndatedHop::NotIncluded => ResolvedHop::NotIncluded,
                    _ => ResolvedHop::NotYet,
                };
            }
            let Some(parent) = reader.output_mmr_at(broadcast) else {
                check.exit = "broadcast-header-unread";
                break 'resolve ResolvedHop::NotYet;
            };
            check.parent_mmr = Some(parent);
            let Some(tip_size) = reader.output_mmr_at(tip) else {
                check.exit = "tip-header-unread";
                break 'resolve ResolvedHop::NotYet;
            };
            check.tip_mmr = Some(tip_size);
            let hunt = if tip_size <= parent {
                churn::LeafHunt::Absent
            } else {
                match mweb::find_output_leaf(
                    reader.lookup.peers(),
                    state.network,
                    tip_hash,
                    parent,
                    tip_size,
                    &output_id,
                ) {
                    mweb::ChainLeaf::Found(leaf) => churn::LeafHunt::Found(leaf),
                    mweb::ChainLeaf::Absent => churn::LeafHunt::Absent,
                    mweb::ChainLeaf::Unread => churn::LeafHunt::Unread,
                }
            };
            check.hunt = Some(hunt);
            match churn::undated_hop(broadcast, tip, parent, tip_size, hunt, check.inputs_unspent) {
                churn::UndatedHop::UseLeaf(leaf) => {
                    new_leaf = Some(leaf);
                    leaf
                }
                churn::UndatedHop::NotIncluded => {
                    check.exit = "hunt-not-included";
                    break 'resolve ResolvedHop::NotIncluded;
                }
                churn::UndatedHop::NotYet => {
                    check.exit = "hunt-undecided";
                    break 'resolve ResolvedHop::NotYet;
                }
            }
        };
        check.leaf = Some(leaf);
        match score_known_leaf(&mut reader, check, broadcast, tip, leaf) {
            churn::InclusionFind::Found { height, score } => ResolvedHop::Scored { height, score },
            churn::InclusionFind::NotYet => ResolvedHop::NotYet,
        }
    };
    check.first_unread = reader.first_unread;
    drop(reader);

    // Sizes read for scoring also date leaves in later syncs.
    if let Some(mweb) = state.mweb.as_mut() {
        let mut changed = false;
        for (height, sizes) in job.header_cache.iter() {
            if mweb
                .sync_state
                .height_map
                .insert(*height, sizes.output_mmr_size)
                .is_none()
            {
                changed = true;
            }
        }
        if let Some(leaf) = new_leaf {
            changed |= mweb::set_coin_leaf_index(mweb, &output_id, leaf);
        }
        if changed {
            let _ = mweb.persist(&state.data_dir);
        }
    }
    outcome
}

/// Score the block in `(broadcast_height, dated_height]` that contains the hop.
/// A miss stays [`churn::InclusionFind::NotYet`] instead of pausing the job.
fn score_hop_window(
    state: &WalletState,
    electrum: Option<&electrum::ElectrumClient>,
    broadcast_height: Option<u32>,
    dated_height: u32,
    leaf_index: Option<u64>,
) -> churn::InclusionFind {
    let Some(span) = churn::header_span(broadcast_height, dated_height) else {
        return churn::InclusionFind::NotYet;
    };
    let heights: Vec<u32> = span.collect();
    let mut hashes = Vec::with_capacity(heights.len());
    let mut index_of = Vec::with_capacity(heights.len());
    for height in &heights {
        if let Some(hash) = block_hash_at(
            &state.wallet,
            &state.data_dir,
            state.network,
            electrum,
            *height,
        ) {
            index_of.push(Some(hashes.len()));
            hashes.push(hash);
        } else {
            index_of.push(None);
        }
    }
    let preferred = state.mweb.as_ref().and_then(|mweb| mweb.last_good_peer);
    let addrs = mweb::peers_for_headers(&state.mweb_peers, state.network, preferred);
    let fetched = mweb::fetch_mmr_sizes_many(&addrs, state.network, &hashes);
    let headers: Vec<(u32, Option<churn::MmrSizes>)> = heights
        .into_iter()
        .zip(index_of)
        .map(|(height, idx)| {
            let sizes = idx.and_then(|i| fetched.get(i).copied().flatten());
            (height, sizes)
        })
        .collect();
    churn::find_inclusion(&headers, leaf_index)
}

fn churn_start_facts(
    state: &WalletState,
    output_id: &str,
) -> Result<(mweb::ChurnCoinInfo, bool, bool, bool), WalletError> {
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let info = mweb::churn_coin_info(mweb, tip, output_id)?;
    let id = mweb_frozen::normalize_output_id(output_id)?;
    let frozen = mweb_frozen::unavailable_ids(&state.data_dir)?.contains(&id);
    let job_active = churn::read_job(&state.data_dir)?.is_some_and(|job| job.phase().is_active());
    let recorded = churn::depth_of(&state.data_dir, &id)?.is_some_and(|record| record.from_pegin);
    Ok((info, frozen, job_active, recorded))
}

fn hop_from_prepared(hop: &mweb::PreparedHop, local_applied: bool) -> churn::ArmedHop {
    churn::ArmedHop {
        raw_hex: hop.raw_hex.clone(),
        txid: hop.txid.clone(),
        wtxid: hop.wtxid.clone(),
        spent_output_id: hop.spent_output_id.clone(),
        created_output_id: hop.created_output_id.clone(),
        receive_index: hop.receive_index,
        fee_sats: hop.fee_sats,
        local_applied,
        broadcast: false,
    }
}

fn unconfirmed_history_ids(state: &WalletState) -> Vec<String> {
    state
        .mweb
        .as_ref()
        .map(|mweb| {
            mweb.history
                .entries
                .iter()
                .filter(|entry| entry.confirmed_height.is_none())
                .map(|entry| entry.id.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn select_churn_coin(
    state: &WalletState,
    output_id: &str,
) -> Result<bdk_mweb::MwebCoin, WalletError> {
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let file = mweb_frozen::read_ids(&state.data_dir)?;
    let mut frozen = file.ids;
    if let Ok(id) = mweb_frozen::normalize_output_id(output_id) {
        frozen.remove(&id);
    }
    frozen.extend(file.reserved.into_keys());
    mweb::select_mweb_coin(mweb.store.db(), output_id, tip, &frozen, "spending to self")
}

/// Sign the whole chain, apply only the first hop to the coin set, and arm it.
fn prepare_churn(state: &mut WalletState, job: &mut churn::ChurnJob) -> Result<(), WalletError> {
    churn::transition(job, churn::ChurnEvent::Signed)?;
    let coin = select_churn_coin(state, &job.current_output_id)?;
    let spent_id = hex::encode(coin.output_id);
    let network = state.network;
    let data_dir = state.data_dir.clone();
    let fee = job.fee_sats;
    let from_pegin = job.from_pegin;
    let hops = job.target_depth;
    let tip = state.wallet.latest_checkpoint().height();
    let unconfirmed = unconfirmed_history_ids(state);
    let mweb = state
        .mweb
        .as_mut()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let prepared =
        mweb::sign_self_spend_hops(&state.wallet, mweb, &data_dir, coin, hops, fee, network)?;
    let first = prepared
        .first()
        .cloned()
        .ok_or_else(|| WalletError::BuildTx("A self-spend must create one output.".into()))?;
    let armed_hops: Vec<churn::ArmedHop> = prepared
        .iter()
        .map(|hop| hop_from_prepared(hop, false))
        .collect();
    let own_ids = churn::snapshot_own_ids(unconfirmed, &armed_hops);
    let mut armed = churn::ArmedRecord {
        version: 1,
        hops: armed_hops,
        armed_index: 0,
        armed_at_unix: churn::unix_now(),
        armed_height: tip,
        cover_min: job.cover_min,
        send_after: None,
        own_ids,
        expired: false,
    };
    churn::write_armed(&data_dir, &armed)?;
    mweb::apply_prepared_output(
        mweb,
        &first.wtxid,
        &first.spent_output_id,
        first.created.clone(),
        first.fee_sats,
    )?;
    if let Err(e) = mweb.persist(&data_dir) {
        let _ = mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &first.wtxid);
        let _ = churn::remove_armed(&data_dir);
        return Err(e);
    }
    crate::crashpoint::maybe_crash("prepare_churn_after_mweb_persist");
    if let Some(first_hop) = armed.hops.first_mut() {
        first_hop.local_applied = true;
    }
    churn::write_armed(&data_dir, &armed)?;
    mweb_frozen::set_locked(&data_dir, &spent_id, true)?;
    mweb_frozen::set_locked(&data_dir, &first.created_output_id, true)?;
    churn::inherit_depth(&data_dir, &spent_id, &first.created_output_id, from_pegin)?;
    let _ = utxo_labels::move_label(&data_dir, &spent_id, &first.created_output_id);
    job.current_output_id = first.created_output_id.clone();
    job.created_output_id = Some(first.created_output_id);
    churn::write_job(&data_dir, job)?;
    Ok(())
}

/// One new signature after a solo pause, a missed block, or an expiry.
fn resign_one_hop(state: &mut WalletState, job: &mut churn::ChurnJob) -> Result<(), WalletError> {
    churn::transition(job, churn::ChurnEvent::Signed)?;
    let coin = select_churn_coin(state, &job.current_output_id)?;
    let spent_id = hex::encode(coin.output_id);
    let network = state.network;
    let data_dir = state.data_dir.clone();
    let fee = job.fee_sats;
    let from_pegin = job.from_pegin;
    let tip = state.wallet.latest_checkpoint().height();
    let cover_min = job.cover_min;
    let unconfirmed = unconfirmed_history_ids(state);
    let prev_armed = churn::read_armed(&data_dir)?;
    let mweb = state
        .mweb
        .as_mut()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let prepared =
        mweb::sign_self_spend_hops(&state.wallet, mweb, &data_dir, coin, 1, fee, network)?;
    let hop = prepared
        .into_iter()
        .next()
        .ok_or_else(|| WalletError::BuildTx("A self-spend must create one output.".into()))?;
    let armed_hop = hop_from_prepared(&hop, false);
    let own_ids = churn::snapshot_own_ids(unconfirmed, std::slice::from_ref(&armed_hop));
    let mut armed = churn::ArmedRecord {
        version: 1,
        hops: vec![armed_hop],
        armed_index: 0,
        armed_at_unix: churn::unix_now(),
        armed_height: tip,
        cover_min,
        send_after: None,
        own_ids,
        expired: false,
    };
    churn::write_armed(&data_dir, &armed)?;
    mweb::apply_prepared_output(
        mweb,
        &hop.wtxid,
        &hop.spent_output_id,
        hop.created.clone(),
        hop.fee_sats,
    )?;
    if let Err(e) = mweb.persist(&data_dir) {
        let _ = mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &hop.wtxid);
        match prev_armed {
            Some(prev) => {
                let _ = churn::write_armed(&data_dir, &prev);
            }
            None => {
                let _ = churn::remove_armed(&data_dir);
            }
        }
        return Err(e);
    }
    crate::crashpoint::maybe_crash("resign_churn_after_mweb_persist");
    if let Some(first_hop) = armed.hops.first_mut() {
        first_hop.local_applied = true;
    }
    churn::write_armed(&data_dir, &armed)?;
    mweb_frozen::set_locked(&data_dir, &spent_id, true)?;
    mweb_frozen::set_locked(&data_dir, &hop.created_output_id, true)?;
    churn::inherit_depth(&data_dir, &spent_id, &hop.created_output_id, from_pegin)?;
    let _ = utxo_labels::move_label(&data_dir, &spent_id, &hop.created_output_id);
    job.current_output_id = hop.created_output_id.clone();
    job.created_output_id = Some(hop.created_output_id);
    churn::write_job(&data_dir, job)?;
    Ok(())
}

fn revert_unbroadcast_hop(
    state: &mut WalletState,
    job: &mut churn::ChurnJob,
) -> Result<(), WalletError> {
    let Some(record) = churn::read_armed(&state.data_dir)? else {
        return Ok(());
    };
    let Some(hop) = record.current() else {
        return Ok(());
    };
    if hop.broadcast || !hop.local_applied {
        return Ok(());
    }
    let wtxid = hop.wtxid.clone();
    let phantom = hop.created_output_id.clone();
    let data_dir = state.data_dir.clone();
    let restored = state.mweb.as_mut().and_then(|mweb| {
        let restored = mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &wtxid);
        if restored.is_some() {
            let _ = mweb.persist(&data_dir);
        }
        restored
    });
    if let Some(restored) = restored {
        let _ = churn::revert_depth(&data_dir, &phantom, &restored);
        let _ = utxo_labels::move_label(&data_dir, &phantom, &restored);
        let _ = mweb_frozen::set_locked(&data_dir, &phantom, false);
        let _ = mweb_frozen::set_locked(&data_dir, &restored, true);
        job.current_output_id = restored;
        job.created_output_id = None;
    }
    Ok(())
}

fn rollback_uncommitted_armed(
    state: &mut WalletState,
    record: &churn::ArmedRecord,
    active_job: Option<&churn::ChurnJob>,
) -> Result<(), WalletError> {
    let Some(hop) = record.current() else {
        return Ok(());
    };
    if hop.broadcast {
        return Ok(());
    }
    let data_dir = state.data_dir.clone();
    if let Some(mweb) = state.mweb.as_mut() {
        if mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &hop.wtxid).is_some()
        {
            mweb.persist(&data_dir)?;
        }
    }
    let _ = churn::revert_depth(&data_dir, &hop.created_output_id, &hop.spent_output_id);
    let _ = utxo_labels::move_label(&data_dir, &hop.created_output_id, &hop.spent_output_id);
    let _ = mweb_frozen::set_locked(&data_dir, &hop.created_output_id, false);
    let keep_spent_locked = active_job.is_some_and(|job| {
        job.phase().is_active()
            && !job.input_spent_elsewhere
            && job.current_output_id == hop.spent_output_id
    });
    let _ = mweb_frozen::set_locked(&data_dir, &hop.spent_output_id, keep_spent_locked);
    Ok(())
}

/// Reconcile an interrupted or locked self-spend pass against the coin store,
/// freeze sidecar, and armed WAL record on account load.
fn reconcile_churn_on_load(state: &mut WalletState) -> Result<(), WalletError> {
    let data_dir = state.data_dir.clone();
    let job_opt = churn::read_job(&data_dir)?;
    let record_opt = churn::read_armed(&data_dir)?;

    match (job_opt, record_opt) {
        (None, None) => Ok(()),
        (None, Some(record)) => {
            rollback_uncommitted_armed(state, &record, None)?;
            churn::remove_armed(&data_dir)
        }
        (Some(mut job), Some(record)) if !job.phase().is_active() => {
            let shown = job.current_output_id.clone();
            revert_unbroadcast_hop(state, &mut job)?;
            let restored = job.current_output_id.clone();
            if restored != shown {
                churn::write_job(&data_dir, &job)?;
            }
            if let Some(hop) = record.current() {
                let _ = mweb_frozen::set_locked(&data_dir, &hop.spent_output_id, false);
                let _ = mweb_frozen::set_locked(&data_dir, &hop.created_output_id, false);
            }
            let _ = mweb_frozen::set_locked(&data_dir, &shown, false);
            if restored != shown {
                let _ = mweb_frozen::set_locked(&data_dir, &restored, false);
            }
            churn::remove_armed(&data_dir)
        }
        (Some(mut job), Some(mut record)) => {
            if job.input_spent_elsewhere {
                if let Some(hop) = record.current() {
                    if !hop.broadcast {
                        if let Some(mweb) = state.mweb.as_mut() {
                            mweb::drop_unbroadcast_output(mweb, &hop.wtxid, &hop.created_output_id);
                            let _ = mweb.persist(&data_dir);
                        }
                        let _ = mweb_frozen::set_locked(&data_dir, &hop.spent_output_id, false);
                        let _ = mweb_frozen::set_locked(&data_dir, &hop.created_output_id, false);
                    }
                }
                return churn::remove_armed(&data_dir);
            }

            if record.expired {
                return expire_armed(Some(state), &data_dir, &mut job, &mut record);
            }

            if let Some(hop) = record.current().cloned() {
                if !hop.broadcast {
                    if job.needs_resign
                        || (record.armed_index == 0
                            && job.current_output_id != hop.created_output_id)
                    {
                        rollback_uncommitted_armed(state, &record, Some(&job))?;
                        return churn::remove_armed(&data_dir);
                    }
                } else {
                    if matches!(
                        job.phase(),
                        ChurnPhase::WaitingForCover | ChurnPhase::WaitingToBroadcast
                    ) && (job.current_output_id != hop.created_output_id
                        || (record.armed_index == 0
                            && job.effective_depth == 0
                            && job.pending_wtxid.is_none()))
                    {
                        churn::note_broadcast(
                            &mut job,
                            &hop.wtxid,
                            &hop.created_output_id,
                            record.armed_height,
                        )?;
                        churn::write_job(&data_dir, &job)?;
                    }

                    if !hop.local_applied {
                        apply_pending_local(state)?;
                    } else {
                        let _ = mweb_frozen::set_locked(&data_dir, &hop.spent_output_id, false);
                        let _ = mweb_frozen::set_locked(&data_dir, &hop.created_output_id, true);
                    }

                    if matches!(
                        job.phase(),
                        ChurnPhase::WaitingForCover | ChurnPhase::PausedSolo
                    ) {
                        promote_after_score(state, &mut job)?;
                    }
                }
            }
            Ok(())
        }
        (Some(mut job), None) => {
            if job.phase().is_active() && !job.input_spent_elsewhere {
                let _ = mweb_frozen::set_locked(&data_dir, &job.current_output_id, true);
                if job.phase() == ChurnPhase::WaitingForCover && !job.needs_resign {
                    promote_after_score(state, &mut job)?;
                }
            }
            Ok(())
        }
    }
}

fn undo_expired_local(state: &mut WalletState) -> Result<(), WalletError> {
    let Some(mut record) = churn::read_armed(&state.data_dir)? else {
        return Ok(());
    };
    if !record.expired {
        return Ok(());
    }
    let Some(mut job) = churn::read_job(&state.data_dir)? else {
        return Ok(());
    };
    if !job.phase().is_active() {
        return churn::remove_armed(&state.data_dir);
    }
    let data_dir = state.data_dir.clone();
    expire_armed(Some(state), &data_dir, &mut job, &mut record)
}

fn apply_pending_local(state: &mut WalletState) -> Result<(), WalletError> {
    let Some(mut record) = churn::read_armed(&state.data_dir)? else {
        return Ok(());
    };
    let Some(hop) = record.current() else {
        return Ok(());
    };
    if !hop.broadcast || hop.local_applied {
        return Ok(());
    }
    if hop.raw_hex.is_empty() {
        return Ok(());
    }
    let raw_hex = hop.raw_hex.clone();
    let wtxid = hop.wtxid.clone();
    let spent = hop.spent_output_id.clone();
    let created_id = hop.created_output_id.clone();
    let receive_index = hop.receive_index;
    let fee = hop.fee_sats;
    let from_pegin = churn::read_job(&state.data_dir)?
        .map(|job| job.from_pegin)
        .unwrap_or(false);
    let data_dir = state.data_dir.clone();
    let mweb = state
        .mweb
        .as_mut()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let created = mweb::recover_hop_output_coin(mweb, &raw_hex, &created_id, receive_index)?;
    mweb::apply_prepared_output(mweb, &wtxid, &spent, created, fee)?;
    mweb.persist(&data_dir)?;
    mweb_frozen::set_locked(&data_dir, &spent, false)?;
    mweb_frozen::set_locked(&data_dir, &created_id, true)?;
    churn::inherit_depth(&data_dir, &spent, &created_id, from_pegin)?;
    let _ = utxo_labels::move_label(&data_dir, &spent, &created_id);
    if let Some(hop) = record.current_mut() {
        hop.local_applied = true;
    }
    churn::write_armed(&data_dir, &record)?;
    Ok(())
}

fn refresh_own_ids(state: &WalletState, record: &mut churn::ArmedRecord) {
    record.own_ids = churn::snapshot_own_ids(unconfirmed_history_ids(state), &record.hops);
}

fn expire_armed(
    state: Option<&mut WalletState>,
    data_dir: &Path,
    job: &mut churn::ChurnJob,
    record: &mut churn::ArmedRecord,
) -> Result<(), WalletError> {
    churn::transition(job, churn::ChurnEvent::Expired)?;
    let revert = record
        .current()
        .is_some_and(|hop| hop.local_applied && !hop.broadcast);
    churn::wipe_raw_tail(record);
    if revert {
        if let Some(state) = state {
            revert_unbroadcast_hop(state, job)?;
            churn::write_job(&state.data_dir, job)?;
            let _ = churn::remove_armed(&state.data_dir);
            return Ok(());
        }
    }
    churn::write_armed(data_dir, record)?;
    churn::write_job(data_dir, job)?;
    Ok(())
}

fn note_foreign_spend(
    state: &mut WalletState,
    job: &mut churn::ChurnJob,
    record: &mut churn::ArmedRecord,
) -> Result<(), WalletError> {
    churn::transition(job, churn::ChurnEvent::ForeignSpend)?;
    churn::write_job(&state.data_dir, job)?;
    if let Some(hop) = record.current() {
        if hop.local_applied && !hop.broadcast {
            let wtxid = hop.wtxid.clone();
            let created = hop.created_output_id.clone();
            let spent = hop.spent_output_id.clone();
            if let Some(mweb) = state.mweb.as_mut() {
                mweb::drop_unbroadcast_output(mweb, &wtxid, &created);
                let _ = mweb.persist(&state.data_dir);
            }
            // The hop froze the spent coin when it was signed. Nothing else
            // unlocks it: this hop never reaches `apply_pending_local`.
            mweb_frozen::set_locked(&state.data_dir, &spent, false)?;
            mweb_frozen::set_locked(&state.data_dir, &created, false)?;
        }
    }
    // An expired record would make the next pass report this as an expiry.
    churn::remove_armed(&state.data_dir)?;
    Ok(())
}

fn send_armed_hop(
    state: Option<&mut WalletState>,
    data_dir: &Path,
    job: &mut churn::ChurnJob,
    record: &mut churn::ArmedRecord,
    route: &mweb::BroadcastRoute,
    height: u32,
) -> Result<(), WalletError> {
    let Some(hop) = record.current() else {
        return Ok(());
    };
    if hop.broadcast || hop.raw_hex.is_empty() {
        return Ok(());
    }
    let raw = hop.raw_hex.clone();
    let wtxid = hop.wtxid.clone();
    let txid = hop.txid.clone();
    let created = hop.created_output_id.clone();
    let spent = hop.spent_output_id.clone();
    let local_applied = hop.local_applied;
    match mweb::broadcast_prepared_raw(&raw, route) {
        Ok(()) => {
            churn::note_broadcast(job, &wtxid, &created, height)?;
            if let Some(hop) = record.current_mut() {
                hop.broadcast = true;
            }
            record.own_ids.insert(wtxid);
            record.own_ids.insert(txid);
            record.send_after = None;
            churn::write_armed(data_dir, record)?;
            crate::crashpoint::maybe_crash("send_armed_after_write_armed");
            churn::write_job(data_dir, job)?;
            crate::crashpoint::maybe_crash("send_armed_after_write_job");
            if local_applied {
                // Hop 0 is already in the coin store, so it skips
                // `apply_pending_local`, which is what unlocks later hops.
                mweb_frozen::set_locked(data_dir, &spent, false)?;
            } else if let Some(state) = state {
                let _ = apply_pending_local(state);
            }
            Ok(())
        }
        Err(e) => {
            if churn::note_broadcast_error(job, e.to_string()).is_ok() {
                churn::write_job(data_dir, job)?;
            }
            Err(e)
        }
    }
}

fn promote_after_score(
    state: &mut WalletState,
    job: &mut churn::ChurnJob,
) -> Result<(), WalletError> {
    let data_dir = state.data_dir.clone();
    let Some(mut record) = churn::read_armed(&data_dir)? else {
        if job.phase() == ChurnPhase::WaitingForCover {
            churn::transition(job, churn::ChurnEvent::Finished)?;
            churn::write_job(&data_dir, job)?;
            mweb_frozen::set_locked(&data_dir, &job.current_output_id, false)?;
        }
        return Ok(());
    };
    let tip = state.wallet.latest_checkpoint().height();
    match churn::follow_score(job.phase(), record.hops_remaining()) {
        churn::ScoreFollow::Stay => {
            if job.phase() == ChurnPhase::Done {
                let _ = churn::remove_armed(&data_dir);
            }
        }
        churn::ScoreFollow::ArmNext => {
            if churn::arm_next(&mut record, churn::unix_now(), tip) {
                churn::transition(job, churn::ChurnEvent::ArmedNext)?;
                churn::write_job(&data_dir, job)?;
                churn::write_armed(&data_dir, &record)?;
            }
        }
        churn::ScoreFollow::FinishShort => {
            churn::transition(job, churn::ChurnEvent::Finished)?;
            churn::write_job(&data_dir, job)?;
            mweb_frozen::set_locked(&data_dir, &job.current_output_id, false)?;
            let _ = churn::remove_armed(&data_dir);
        }
    }
    Ok(())
}

fn cover_gate(state: Option<&mut WalletState>) -> Result<(), WalletError> {
    let Some(state) = state else {
        return Ok(());
    };
    let data_dir = state.data_dir.clone();
    cover_gate_at(Some(state), &data_dir)
}

fn cover_gate_at(mut state: Option<&mut WalletState>, data_dir: &Path) -> Result<(), WalletError> {
    let Some(mut job) = churn::read_job(data_dir)? else {
        return Ok(());
    };
    if !churn::ready_to_broadcast(&job) {
        return Ok(());
    }
    let Some(mut record) = churn::read_armed(data_dir)? else {
        return Ok(());
    };
    if record.expired {
        if let Some(state) = state.as_mut() {
            return expire_armed(Some(state), data_dir, &mut job, &mut record);
        }
        return Ok(());
    }
    let Some(hop) = record.current() else {
        return Ok(());
    };
    if hop.broadcast || hop.raw_hex.is_empty() {
        return Ok(());
    }

    let (route, wallet_tip) = match state.as_ref() {
        Some(loaded) => (
            broadcast_route(loaded),
            Some(loaded.wallet.latest_checkpoint().height()),
        ),
        None => {
            let meta = meta::read_meta(data_dir)?;
            let route = mweb::BroadcastRoute {
                data_dir: data_dir.to_path_buf(),
                rpc_url: meta.litecoin_rpc_url,
                peers: meta.mweb_peers,
                network: meta.network,
                via_own_node: meta.broadcast_via_own_node,
            };
            (route, None)
        }
    };
    let rpc_url = route.rpc_url.clone();
    let route_network = route.network;
    let tip = match wallet_tip {
        Some(height) => Some(height),
        None => rpc_url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
            .and_then(|url| crate::rpc::get_block_count_for_network(url, Some(route_network)).ok()),
    };
    if churn::armed_expired(
        record.armed_at_unix,
        record.armed_height,
        churn::unix_now(),
        tip,
    ) {
        return expire_armed(state, data_dir, &mut job, &mut record);
    }
    if let Some(loaded) = state.as_mut() {
        refresh_own_ids(loaded, &mut record);
        let hop = record.current().cloned();
        if let Some(hop) = hop {
            if !hop.broadcast
                && loaded.mweb.as_ref().is_some_and(|mweb| {
                    !mweb::prepared_input_ok(mweb, &hop.spent_output_id, false, &hop.wtxid)
                })
            {
                return note_foreign_spend(loaded, &mut job, &mut record);
            }
        }
    }

    let Some(url) = rpc_url.as_deref().filter(|url| !url.trim().is_empty()) else {
        job.cover_hold = Some(CoverHold::NoRpc);
        churn::write_job(data_dir, &job)?;
        churn::write_armed(data_dir, &record)?;
        return Ok(());
    };
    let read = match mweb::count_foreign_mweb_mempool_for_network(
        url,
        &record.own_ids,
        Some(route_network),
    ) {
        Ok(read) => read,
        Err(e) => {
            let message = e.to_string();
            diag::log(format!("self-spend: mempool read failed ({message})"));
            churn::note_cover_error(&mut job, churn::unix_now(), &message);
            job.cover_hold = Some(CoverHold::Waiting);
            churn::write_job(data_dir, &job)?;
            return Ok(());
        }
    };
    churn::note_cover_read(&mut job, &read);
    let count = read.foreign_txs;
    let step = churn::cover_step(
        read.checked_at_unix,
        count,
        record.cover_min,
        job.spread_send,
        record.send_after,
        churn::random_spread(),
    );
    match step {
        churn::CoverStep::Below => {
            record.send_after = None;
            job.spreading = false;
            job.cover_hold = Some(CoverHold::Waiting);
            churn::write_job(data_dir, &job)?;
            churn::write_armed(data_dir, &record)?;
        }
        churn::CoverStep::StartSpread { send_after } => {
            record.send_after = Some(send_after);
            job.spreading = true;
            job.cover_hold = Some(CoverHold::Waiting);
            churn::write_job(data_dir, &job)?;
            churn::write_armed(data_dir, &record)?;
        }
        churn::CoverStep::Spreading => {
            job.spreading = true;
            job.cover_hold = Some(CoverHold::Waiting);
            churn::write_job(data_dir, &job)?;
        }
        churn::CoverStep::Send => {
            job.spreading = false;
            let height = tip.unwrap_or(record.armed_height);
            let _ = send_armed_hop(state, data_dir, &mut job, &mut record, &route, height);
        }
    }
    Ok(())
}

/// Score a confirmed hop. The next hop stays signed until this one is scored,
/// then waits on the mempool gate. Broadcast failures stay on the job.
fn drive_churn(
    state: &mut WalletState,
    electrum: Option<&electrum::ElectrumClient>,
) -> Result<(), WalletError> {
    let _ = reconcile_churn_on_load(state);
    let Some(mut job) = churn::read_job(&state.data_dir)? else {
        return Ok(());
    };
    if matches!(
        job.phase(),
        ChurnPhase::WaitingConfirm | ChurnPhase::PausedUnscored
    ) {
        let output_id = job.current_output_id.clone();
        let resolved = resolve_waiting_hop(state, electrum, &mut job);
        // The check line and any header reads are worth keeping even when
        // nothing else changed.
        churn::write_job(&state.data_dir, &job)?;
        match resolved {
            ResolvedHop::Scored { height, score } => {
                let found = churn::InclusionFind::Found { height, score };
                if let Some((found_height, score)) = churn::consider_inclusion(&mut job, found)? {
                    if let Some(mweb) = state.mweb.as_mut() {
                        if mweb::set_coin_block_height(mweb, &output_id, found_height) {
                            let _ = mweb.persist(&state.data_dir);
                        }
                    }
                    let from_pegin = job.from_pegin;
                    churn::commit_score(&state.data_dir, &output_id, from_pegin, score)?;
                    crate::crashpoint::maybe_crash("drive_churn_after_commit_score");
                    churn::write_job(&state.data_dir, &job)?;
                    crate::crashpoint::maybe_crash("drive_churn_before_promote");
                    if job.phase() == ChurnPhase::Done {
                        mweb_frozen::set_locked(&state.data_dir, &output_id, false)?;
                    }
                }
            }
            ResolvedHop::NotIncluded => {
                let phantom = output_id;
                let restored = job.pending_wtxid.clone().and_then(|wtxid| {
                    let mweb = state.mweb.as_mut()?;
                    let restored =
                        mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &wtxid);
                    if restored.is_some() {
                        let _ = mweb.persist(&state.data_dir);
                    }
                    restored
                });
                if let Some(restored) = restored {
                    let _ = churn::revert_depth(&state.data_dir, &phantom, &restored);
                    let _ = utxo_labels::move_label(&state.data_dir, &phantom, &restored);
                    let _ = mweb_frozen::set_locked(&state.data_dir, &phantom, false);
                    let _ = mweb_frozen::set_locked(&state.data_dir, &restored, true);
                    churn::note_not_included(&mut job, &restored)?;
                    churn::write_job(&state.data_dir, &job)?;
                    let _ = churn::remove_armed(&state.data_dir);
                }
            }
            ResolvedHop::NotYet if job.phase() == ChurnPhase::PausedUnscored => {
                churn::transition(&mut job, churn::ChurnEvent::StillUnscored)?;
                churn::write_job(&state.data_dir, &job)?;
            }
            ResolvedHop::NotYet => {}
        }
        let _ = promote_after_score(state, &mut job);
    }
    if let Some(mut record) = churn::read_armed(&state.data_dir)? {
        refresh_own_ids(state, &mut record);
        let _ = churn::write_armed(&state.data_dir, &record);
    }
    let _ = cover_gate(Some(state));
    Ok(())
}

fn parse_txid(hex: &str) -> Option<Txid> {
    Txid::from_str(hex).ok()
}

/// Overlay MWEB activity onto the transparent history.
///
/// A peg-in's transparent tx shows up in the BDK graph after a sync; when its
/// txid matches a log entry we only tag the existing record instead of adding
/// a duplicate. All other entries (peg-outs, MWEB sends/receives) have no
/// transparent record and are appended as standalone records.
fn merge_mweb_history(records: &mut Vec<TxRecord>, mweb: &MwebRuntime, tip: u32) {
    let by_txid: std::collections::HashMap<String, usize> = records
        .iter()
        .enumerate()
        .map(|(i, r)| (r.txid.clone(), i))
        .collect();
    for entry in &mweb.history.entries {
        if let Some(&i) = by_txid.get(&entry.id) {
            records[i].kind = entry.kind;
            // The BDK row only sees the transparent side, so its fee misses the
            // MWEB fee (e.g. a peg-in costs miner + MWEB fee). The recorded
            // entry carries the full amount — prefer it.
            if entry.fee_sats.is_some() {
                records[i].fee_sats = entry.fee_sats;
            }
            // Electrum cannot confirm hybrid MWEB txs, so a peg-in can sit in
            // the BDK graph as unconfirmed forever even after the private coin
            // is dated. Overlay the MWEB height so History and spendability
            // agree with the coin store.
            if records[i].confirmations == 0 {
                if let Some(h) = mweb::history_entry_height(entry, mweb.store.db()) {
                    records[i].height = Some(h);
                    records[i].confirmations = tip.saturating_sub(h).saturating_add(1);
                }
            }
            records[i].maturity_blocks_left =
                mweb::pegin_blocks_left(records[i].kind, records[i].confirmations);
            records[i].can_clear = spend_can_clear(
                entry,
                records[i].confirmations > 0,
                pegin_output_has_leaf(entry, mweb.store.db()),
            );
            continue;
        }
        // Prefer the height resolved and persisted at sync time (covers
        // peg-outs with no change coin, and survives an MWEB resync).
        // Fall back to the coins this tx created for us (received coins,
        // or the change coin of an outgoing tx).
        let height = mweb::history_entry_height(entry, mweb.store.db());
        let confirmations = height
            .map(|h| tip.saturating_sub(h).saturating_add(1))
            .unwrap_or(0);
        let (sent_sats, received_sats) = if entry.net_sats < 0 {
            (entry.net_sats.unsigned_abs(), 0)
        } else {
            (0, entry.net_sats as u64)
        };
        records.push(TxRecord {
            txid: entry.id.clone(),
            net_sats: entry.net_sats,
            sent_sats,
            received_sats,
            fee_sats: entry.fee_sats,
            height,
            confirmations,
            timestamp: Some(entry.timestamp),
            kind: entry.kind,
            maturity_blocks_left: mweb::pegin_blocks_left(entry.kind, confirmations),
            can_clear: spend_can_clear(
                entry,
                confirmations > 0,
                pegin_output_has_leaf(entry, mweb.store.db()),
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{CoinBlock, CoinStatus};
    use crate::mweb_history::MwebHistoryEntry;

    #[test]
    fn merge_uses_persisted_confirmed_height() {
        let dir = tempfile::tempdir().unwrap();
        let secret = MasterSecret::parse(&descriptors::generate_mnemonic().unwrap(), None).unwrap();
        let mut mweb = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            MwebScheme::default().to_master_scheme(),
            0,
            None,
        )
        .unwrap();
        mweb.history.record(MwebHistoryEntry {
            id: "wtxid1".into(),
            kind: TxKind::Pegout,
            net_sats: -5_000,
            fee_sats: Some(100),
            timestamp: 1_700_000_000,
            output_ids: Vec::new(),
            input_ids: Vec::new(),
            relayed: false,
            absent: false,
            confirmed_height: Some(90),
        });
        mweb.history.record(MwebHistoryEntry {
            id: "wtxid2".into(),
            kind: TxKind::Pegout,
            net_sats: -5_000,
            fee_sats: Some(100),
            timestamp: 1_700_000_000,
            output_ids: Vec::new(),
            input_ids: Vec::new(),
            relayed: false,
            absent: false,
            confirmed_height: None,
        });
        let mut records = Vec::new();
        merge_mweb_history(&mut records, &mweb, 100);
        let confirmed = records.iter().find(|r| r.txid == "wtxid1").unwrap();
        assert_eq!(confirmed.height, Some(90));
        assert_eq!(confirmed.confirmations, 11);
        let pending = records.iter().find(|r| r.txid == "wtxid2").unwrap();
        assert_eq!(pending.height, None);
        assert_eq!(pending.confirmations, 0);
    }

    #[test]
    fn merge_overlays_mweb_height_on_unconfirmed_bdk_pegin() {
        let dir = tempfile::tempdir().unwrap();
        let secret = MasterSecret::parse(&descriptors::generate_mnemonic().unwrap(), None).unwrap();
        let mut mweb = MwebRuntime::open(
            dir.path(),
            &secret,
            WalletNetwork::Testnet,
            MwebScheme::default().to_master_scheme(),
            0,
            None,
        )
        .unwrap();
        let output_id = [0x11u8; 32];
        mweb.store.db_mut().insert(bdk_mweb::MwebCoin {
            output_id,
            commitment: [0; 33],
            amount: 1_000_000,
            address_index: 0,
            blind: [0; 32],
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
            block_height: Some(90),
            is_pegin: true,
            leaf_index: Some(4),
        });
        mweb.history.record(MwebHistoryEntry {
            id: "pegin-txid".into(),
            kind: TxKind::Pegin,
            net_sats: -1_050_000,
            fee_sats: Some(51_000),
            timestamp: 1_700_000_000,
            output_ids: vec![hex::encode(output_id)],
            input_ids: Vec::new(),
            relayed: false,
            absent: false,
            confirmed_height: None,
        });
        let mut records = vec![TxRecord {
            txid: "pegin-txid".into(),
            net_sats: -1_000_000,
            sent_sats: 1_000_000,
            received_sats: 0,
            fee_sats: Some(1_000),
            height: None,
            confirmations: 0,
            timestamp: Some(1_700_000_000),
            kind: TxKind::Transparent,
            maturity_blocks_left: None,
            can_clear: false,
        }];
        merge_mweb_history(&mut records, &mweb, 100);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, TxKind::Pegin);
        assert_eq!(records[0].fee_sats, Some(51_000));
        assert_eq!(records[0].height, Some(90));
        assert_eq!(records[0].maturity_blocks_left, None);
        assert_eq!(records[0].confirmations, 11);
    }

    #[test]
    fn unrelayed_pegin_can_be_cleared_and_a_relayed_one_cannot() {
        let mut entry = MwebHistoryEntry {
            id: "11".repeat(32),
            kind: TxKind::Pegin,
            net_sats: -1_000,
            fee_sats: Some(100),
            timestamp: 1,
            output_ids: vec!["22".repeat(32)],
            input_ids: Vec::new(),
            confirmed_height: None,
            relayed: false,
            absent: false,
        };
        assert!(
            !pegin_can_clear(&entry, false, false),
            "a missing broadcast echo is not proof it failed"
        );
        entry.absent = true;
        assert!(
            pegin_can_clear(&entry, false, false),
            "a sync looked and the peg-in was not on the network"
        );
        entry.relayed = true;
        assert!(pegin_can_clear(&entry, false, false));
        entry.confirmed_height = Some(90);
        assert!(!pegin_can_clear(&entry, false, false));
        entry.confirmed_height = None;
        assert!(!pegin_can_clear(&entry, true, false));
        assert!(!pegin_can_clear(&entry, false, true));
    }

    #[test]
    fn underpaid_pegout_can_be_cleared() {
        let input = "33".repeat(32);
        let mut entry = MwebHistoryEntry {
            id: "aa".repeat(32),
            kind: TxKind::Pegout,
            net_sats: -1_000,
            fee_sats: Some(400),
            timestamp: 1,
            output_ids: Vec::new(),
            input_ids: vec![input.clone()],
            confirmed_height: None,
            relayed: false,
            absent: false,
        };
        assert!(
            spend_can_clear(&entry, false, false),
            "400 litoshis is the old one-output kernel fee"
        );
        entry.fee_sats = Some(447);
        assert!(!spend_can_clear(&entry, false, false));
        entry.input_ids.push("44".repeat(32));
        entry.fee_sats = Some(500);
        assert!(
            spend_can_clear(&entry, false, false),
            "500 litoshis is the old two-output kernel fee"
        );
        entry.fee_sats = Some(578);
        assert!(!spend_can_clear(&entry, false, false));
        entry.fee_sats = Some(400);
        entry.confirmed_height = Some(90);
        assert!(!spend_can_clear(&entry, false, false));
    }

    #[test]
    fn nine_input_pegin_estimate_clears_the_fee_that_was_rejected() {
        // e125889d… was 708 vbytes. Pricing it as 697 vbytes at 1 lit/vB left
        // it 11 litoshis under minRelayTxFee, and every peer returned notfound.
        let vb = estimate_pegin_vb(9, 1);
        assert!(
            vb >= 708 + PEGIN_FEE_VB_BUFFER,
            "9-input peg-in estimated {vb} vbytes"
        );
        assert!(estimate_pegin_vb(9, 2) > vb);
    }

    #[test]
    fn dropped_pegin_is_not_a_maturing_history_row() {
        let mut landed = MwebHistoryEntry {
            id: "11".repeat(32),
            kind: TxKind::Pegin,
            net_sats: -1_000,
            fee_sats: Some(100),
            timestamp: 1,
            output_ids: vec!["22".repeat(32)],
            input_ids: Vec::new(),
            relayed: false,
            absent: false,
            confirmed_height: None,
        };
        assert!(
            !is_dropped_local_pegin(&landed, true, false),
            "an unconfirmed peg-in still in the wallet stays"
        );
        assert!(
            !is_dropped_local_pegin(&landed, false, true),
            "a peg-in whose coins are still in the store is repaired, not deleted"
        );
        landed.confirmed_height = Some(90);
        assert!(
            !is_dropped_local_pegin(&landed, false, false),
            "a dated peg-in stays in history"
        );
        landed.confirmed_height = None;
        assert!(
            is_dropped_local_pegin(&landed, false, false),
            "evicted peg-in with no coins left is the stuck maturing row"
        );
        landed.kind = TxKind::MwebReceive;
        landed.net_sats = 1_000;
        assert!(!is_dropped_local_pegin(&landed, false, false));
    }

    /// A node that cannot be reached must leave the reason and the time on
    /// the job, not only in the diagnostic log.
    #[test]
    fn cover_gate_keeps_a_failed_mempool_read_on_the_job() {
        let dir = tempfile::tempdir().unwrap();
        let mut meta = meta::WalletMeta::new(WalletNetwork::Testnet, None);
        // Nothing listens here; the connection is refused at once.
        meta.litecoin_rpc_url = Some("http://127.0.0.1:9".into());
        meta::write_meta(dir.path(), &meta).unwrap();

        let output_id = "ab".repeat(32);
        let mut job = churn::new_job(&output_id, false, 1, 50_000, 2, false).unwrap();
        job.set_phase_for_test(ChurnPhase::WaitingForCover);
        churn::write_job(dir.path(), &job).unwrap();
        let record = churn::ArmedRecord {
            version: 1,
            hops: vec![churn::ArmedHop {
                raw_hex: "aa".into(),
                txid: "txid".into(),
                wtxid: "wtxid".into(),
                spent_output_id: output_id.clone(),
                created_output_id: "cd".repeat(32),
                receive_index: 0,
                fee_sats: 50_000,
                local_applied: false,
                broadcast: false,
            }],
            armed_index: 0,
            armed_at_unix: churn::unix_now(),
            armed_height: 100,
            cover_min: 2,
            send_after: None,
            own_ids: std::collections::BTreeSet::new(),
            expired: false,
        };
        churn::write_armed(dir.path(), &record).unwrap();

        let before = churn::unix_now();
        cover_gate_at(None, dir.path()).unwrap();

        let job = churn::read_job(dir.path()).unwrap().unwrap();
        assert_eq!(job.phase(), ChurnPhase::WaitingForCover);
        assert_eq!(job.cover_hold, Some(CoverHold::Waiting));
        assert!(job.last_cover_check_unix.is_some_and(|t| t >= before));
        assert!(
            job.last_cover_error
                .as_deref()
                .is_some_and(|e| !e.is_empty()),
            "error should be saved: {:?}",
            job.last_cover_error
        );
        // No read worked, so there is no count to show.
        assert!(job.last_cover_count.is_none());
        // The hop was not sent.
        let record = churn::read_armed(dir.path()).unwrap().unwrap();
        assert!(!record.hops[0].broadcast);
    }

    /// A testnet wallet with a job on the "cd…" output, armed to spend "ab…".
    fn app_with_job(dir: &Path, phase: ChurnPhase, expired: bool) -> WalletApp {
        let app = WalletApp::new(dir);
        app.create(
            dir,
            crate::dto::CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
            "correct horse battery staple",
        )
        .expect("create");
        {
            let guard = app.lock_state().unwrap();
            let state = guard.as_ref().unwrap();
            let spent = "ab".repeat(32);
            let created = "cd".repeat(32);
            let mut job = churn::new_job(&spent, false, 1, 50_000, 2, false).unwrap();
            job.set_phase_for_test(phase);
            job.current_output_id = created.clone();
            job.created_output_id = Some(created.clone());
            let record = churn::ArmedRecord {
                version: 1,
                hops: vec![churn::ArmedHop {
                    raw_hex: "aa".into(),
                    txid: "txid".into(),
                    wtxid: "wtxid".into(),
                    spent_output_id: spent,
                    created_output_id: created,
                    receive_index: 0,
                    fee_sats: 50_000,
                    local_applied: true,
                    broadcast: false,
                }],
                armed_index: 0,
                armed_at_unix: churn::unix_now(),
                armed_height: 100,
                cover_min: 2,
                send_after: None,
                own_ids: std::collections::BTreeSet::new(),
                expired,
            };
            churn::write_job(&state.data_dir, &job).unwrap();
            churn::write_armed(&state.data_dir, &record).unwrap();
        }
        app
    }

    fn app_with_foreign_spent_job(dir: &Path) -> WalletApp {
        let app = app_with_job(dir, ChurnPhase::WaitingForCover, false);
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let mut job = churn::read_job(&state.data_dir).unwrap().unwrap();
            let mut record = churn::read_armed(&state.data_dir).unwrap().unwrap();
            note_foreign_spend(state, &mut job, &mut record).unwrap();
        }
        app
    }

    /// A testnet wallet holding confirmed private coins of these amounts, with their output ids.
    fn app_with_private_coins(dir: &Path, amounts: &[u64]) -> (WalletApp, Vec<String>) {
        let app = app_with_job(dir, ChurnPhase::Cancelled, false);
        let mut ids = Vec::new();
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            for (i, amount) in amounts.iter().enumerate() {
                let id = [0x40 + i as u8; 32];
                insert_private_coin(state, id, *amount, Some(0), false);
                let _ = state
                    .mweb
                    .as_mut()
                    .expect("mweb runtime")
                    .store
                    .db_mut()
                    .set_leaf_index(&id, i as u64);
                ids.push(hex::encode(id));
            }
        }
        (app, ids)
    }

    fn pegout_req(address: &str, amount_sats: u64, drain: bool, ids: &[String]) -> PegoutRequest {
        PegoutRequest {
            address: address.into(),
            amount_sats,
            fee_sats: 0,
            drain,
            selected_output_ids: Some(ids.to_vec()),
            output_amounts: Vec::new(),
            addresses: Vec::new(),
            per_coin: false,
            fee_output_index: None,
        }
    }

    /// Picking 2 of 3 coins and typing an amount sends that amount to one address from those coins.
    #[test]
    fn typed_pegout_from_selected_coins_is_one_output() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000, 9_000_000]);
        let address = app.receive_address().unwrap();
        let guard = app.lock_state().unwrap();
        let state = guard.as_ref().unwrap();

        let (resolved, _) =
            resolve_pegout_request(state, pegout_req(&address, 4_000_000, false, &ids[..2]))
                .unwrap();
        assert!(!resolved.per_coin);
        assert_eq!(resolved.output_amounts, vec![4_000_000]);
        assert_eq!(resolved.address, address);
        assert_eq!(resolved.selected_output_ids.as_deref(), Some(&ids[..2]));
    }

    /// The other coins in the wallet do not count toward a typed amount from a selection.
    #[test]
    fn typed_pegout_cannot_exceed_the_selected_coins() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000, 9_000_000]);
        let address = app.receive_address().unwrap();
        let guard = app.lock_state().unwrap();
        let state = guard.as_ref().unwrap();

        let err = resolve_pegout_request(state, pegout_req(&address, 6_000_000, false, &ids[..2]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("selected"), "{err}");
    }

    /// Max with a selection still empties each selected coin to its own address.
    #[test]
    fn max_pegout_from_selected_coins_stays_per_coin() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000, 9_000_000]);
        let guard = app.lock_state().unwrap();
        let state = guard.as_ref().unwrap();

        let (resolved, _) =
            resolve_pegout_request(state, pegout_req("", 0, true, &ids[..2])).unwrap();
        assert!(resolved.per_coin);
        assert_eq!(resolved.output_amounts.len(), 2);
    }

    /// A coin held by a spend that is still broadcasting cannot be unfrozen and picked again.
    #[test]
    fn coin_in_flight_is_not_unfreezable() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        let hold = CoinHold::take(&data_dir, vec![ids[0].clone()], &app.session).unwrap();

        let row_for = |id: &str| {
            app.list_mweb_unspent()
                .unwrap()
                .into_iter()
                .find(|c| c.output_id == id)
                .unwrap()
        };
        let row = row_for(&ids[0]);
        assert_eq!(row.status, CoinStatus::Sending);
        assert!(!row.actions.unfreeze && !row.actions.freeze && !row.actions.select);
        assert_eq!(row.actions.blocked, Some(CoinBlock::Sending));

        for locked in [false, true] {
            let err = app
                .set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
                    output_id: ids[0].clone(),
                    locked,
                })
                .unwrap_err();
            assert!(
                err.to_string().contains(mweb_frozen::RESERVED_MESSAGE),
                "{err}"
            );
        }
        let err = CoinHold::take(&data_dir, vec![ids[0].clone()], &app.session)
            .err()
            .unwrap();
        assert!(
            err.to_string().contains(mweb_frozen::RESERVED_MESSAGE),
            "{err}"
        );

        drop(hold);
        assert_eq!(row_for(&ids[0]).status, CoinStatus::Ready);
    }

    /// A testnet wallet holding confirmed public coins of these amounts, with their outpoints.
    fn app_with_public_coins(dir: &Path, amounts: &[u64]) -> (WalletApp, Vec<OutPoint>) {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::chain::BlockId;
        use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};

        let app = app_with_job(dir, ChurnPhase::Cancelled, false);
        let mut outpoints = Vec::with_capacity(amounts.len());
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_checkpoint(
                &mut state.wallet,
                BlockId {
                    height: 1,
                    hash: BlockHash::all_zeros(),
                },
            );
            for amount_sats in amounts {
                outpoints.push(receive_output_in_latest_block(
                    &mut state.wallet,
                    Amount::from_sat(*amount_sats),
                ));
            }
            state.wallet.persist(&mut state.db).unwrap();
        }
        (app, outpoints)
    }

    /// A testnet wallet holding one confirmed public coin, with its outpoint.
    fn app_with_public_coin(dir: &Path, amount_sats: u64) -> (WalletApp, OutPoint) {
        let (app, mut outpoints) = app_with_public_coins(dir, &[amount_sats]);
        (app, outpoints.remove(0))
    }

    fn insert_private_coin(
        state: &mut WalletState,
        id: [u8; 32],
        amount: u64,
        block_height: Option<u32>,
        is_pegin: bool,
    ) {
        // A zero blind does not open, so `MwebStore::from_changeset` drops the coin
        // on reload and the signer refuses it. Match `persistable_coin`.
        let mut blind: [u8; 32] = [0x0b; 32];
        blind[0] = blind[0].wrapping_add(id[0]);
        let commitment = bdk_mweb::crypto::switch_commit(
            &blind,
            amount,
            &bdk_wallet::bitcoin::secp256k1::Secp256k1::new(),
        )
        .expect("test coin commitment");
        let mweb = state.mweb.as_mut().expect("mweb runtime");
        mweb.store.db_mut().insert(bdk_mweb::MwebCoin {
            output_id: id,
            commitment,
            amount,
            address_index: 0,
            blind,
            shared_secret: [0; 32],
            spend_key: Some([1; 32]),
            block_height,
            is_pegin,
            leaf_index: Some(1),
        });
    }

    fn frozen_file_bytes(dir: &Path) -> Option<Vec<u8>> {
        std::fs::read(mweb_frozen::frozen_path(dir)).ok()
    }

    /// Private and public coins in the states `coin_status` distinguishes.
    /// The holds stay alive for as long as this value does.
    struct StatusWallet {
        app: WalletApp,
        private_frozen: String,
        private_held: String,
        public_frozen: OutPoint,
        public_held: OutPoint,
        _private_hold: CoinHold,
        _public_hold: CoinHold,
    }

    fn insert_hogex_pegout_utxo(
        wallet: &mut PersistedWallet<Connection>,
        amount: Amount,
        receive_to: bdk_wallet::test_utils::ReceiveTo,
        seed_byte: u8,
    ) -> OutPoint {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::{
            absolute::LockTime, transaction::Version, Sequence, TxIn, TxOut, Txid, WitnessProgram,
            WitnessVersion,
        };
        use bdk_wallet::test_utils::insert_tx;

        let addr = wallet.reveal_next_address(KeychainKind::External).address;
        let hog_addr = ScriptBuf::new_witness_program(
            &WitnessProgram::new(WitnessVersion::V8, &[seed_byte; 32]).unwrap(),
        );
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([seed_byte; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(100_000_000),
                    script_pubkey: hog_addr,
                },
                TxOut {
                    value: amount,
                    script_pubkey: addr.script_pubkey(),
                },
            ],
            is_hog_ex: true,
            mw_tx: None,
        };
        let txid = tx.compute_txid();
        insert_tx(wallet, tx);
        match receive_to {
            bdk_wallet::test_utils::ReceiveTo::Block(anchor) => {
                bdk_wallet::test_utils::insert_anchor(wallet, txid, anchor);
            }
            bdk_wallet::test_utils::ReceiveTo::Mempool(seen_at) => {
                bdk_wallet::test_utils::insert_seen_at(wallet, txid, seen_at);
            }
        }
        OutPoint::new(txid, 1)
    }

    fn insert_coinbase_utxo(
        wallet: &mut PersistedWallet<Connection>,
        amount: Amount,
        receive_to: bdk_wallet::test_utils::ReceiveTo,
        seed_byte: u8,
    ) -> OutPoint {
        use bdk_wallet::bitcoin::{
            absolute::LockTime, script::Builder, transaction::Version, Sequence, TxIn, TxOut,
        };
        use bdk_wallet::test_utils::insert_tx;

        let addr = wallet.reveal_next_address(KeychainKind::External).address;
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(i64::from(seed_byte)).into_script(),
                sequence: Sequence::MAX,
                witness: Default::default(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: addr.script_pubkey(),
            }],
            is_hog_ex: false,
            mw_tx: None,
        };
        let txid = tx.compute_txid();
        assert!(tx.is_coinbase());
        insert_tx(wallet, tx);
        match receive_to {
            bdk_wallet::test_utils::ReceiveTo::Block(anchor) => {
                bdk_wallet::test_utils::insert_anchor(wallet, txid, anchor);
            }
            bdk_wallet::test_utils::ReceiveTo::Mempool(seen_at) => {
                bdk_wallet::test_utils::insert_seen_at(wallet, txid, seen_at);
            }
        }
        OutPoint::new(txid, 0)
    }

    fn open_status_wallet(dir: &Path) -> StatusWallet {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
        use bdk_wallet::test_utils::{
            insert_checkpoint, receive_output, receive_output_in_latest_block, ReceiveTo,
        };

        let app = app_with_job(dir, ChurnPhase::Cancelled, false);
        let ready = [0x41; 32];
        let frozen = [0x42; 32];
        let held = [0x43; 32];
        let pending = [0x44; 32];
        let maturing = [0x45; 32];
        let (public_frozen, public_held) = {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_private_coin(state, ready, 1_000_000, Some(0), false);
            insert_private_coin(state, frozen, 1_000_000, Some(0), false);
            insert_private_coin(state, held, 1_000_000, Some(0), false);
            insert_private_coin(state, pending, 1_000_000, None, false);
            insert_private_coin(state, maturing, 1_000_000, Some(0), true);
            let block1 = BlockId {
                height: 1,
                hash: BlockHash::all_zeros(),
            };
            insert_checkpoint(&mut state.wallet, block1);
            let _confirmed =
                receive_output_in_latest_block(&mut state.wallet, Amount::from_sat(1_000_000));
            let public_frozen =
                receive_output_in_latest_block(&mut state.wallet, Amount::from_sat(1_000_000));
            let public_held =
                receive_output_in_latest_block(&mut state.wallet, Amount::from_sat(1_000_000));
            let _public_maturing = insert_hogex_pegout_utxo(
                &mut state.wallet,
                Amount::from_sat(1_000_000),
                ReceiveTo::Block(ConfirmationBlockTime {
                    block_id: block1,
                    confirmation_time: 100,
                }),
                0x91,
            );
            let _unconfirmed = receive_output(
                &mut state.wallet,
                Amount::from_sat(1_000_000),
                ReceiveTo::Mempool(1),
            );
            state.wallet.persist(&mut state.db).unwrap();
            (public_frozen, public_held)
        };
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        let private_frozen = hex::encode(frozen);
        let private_held = hex::encode(held);
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: private_frozen.clone(),
            locked: true,
        })
        .unwrap();
        app.set_utxo_locked(SetUtxoLockedRequest {
            outpoint: public_frozen.to_string(),
            locked: true,
        })
        .unwrap();
        let private_hold =
            CoinHold::take(&data_dir, vec![private_held.clone()], &app.session).unwrap();
        let public_hold =
            CoinHold::take_public(&data_dir, vec![public_held], &app.session).unwrap();
        StatusWallet {
            app,
            private_frozen,
            private_held,
            public_frozen,
            public_held,
            _private_hold: private_hold,
            _public_hold: public_hold,
        }
    }

    fn assert_flag_gates_command(
        allowed: bool,
        result: Result<(), WalletError>,
        before: &Option<Vec<u8>>,
        data_dir: &Path,
        label: &str,
    ) {
        match (allowed, result) {
            (true, Ok(())) => {}
            (false, Err(err)) => assert_eq!(
                &frozen_file_bytes(data_dir),
                before,
                "{label} changed mweb_frozen.json ({err})"
            ),
            (true, Err(err)) => {
                panic!("{label}: the flag allows it but the command refused: {err}")
            }
            (false, Ok(())) => panic!("{label}: the flag blocks it but the command accepted it"),
        }
    }

    fn public_split_req(outpoint: OutPoint) -> SplitRequest {
        SplitRequest {
            chain: SplitChain::Public,
            input: outpoint.to_string(),
            equal_count: Some(2),
            amounts: vec![],
            fee_rate_sat_vb: Some(1),
            fee_sats: 0,
        }
    }

    /// A public coin a split is still broadcasting cannot be unfrozen and picked again.
    #[test]
    fn public_coin_in_flight_is_not_unfreezable() {
        let dir = tempfile::tempdir().unwrap();
        let (app, outpoint) = app_with_public_coin(dir.path(), 1_000_000);
        let prepared = {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            prepare_split(state, &public_split_req(outpoint), &app.session).unwrap()
        };

        let row = app.list_unspent().unwrap().remove(0);
        assert_eq!(row.status, CoinStatus::Sending);
        assert!(!row.locked, "the hold is not a user freeze");
        assert!(!row.actions.unfreeze && !row.actions.freeze && !row.actions.select);
        assert!(!row.actions.split && !row.actions.transfer);
        assert_eq!(row.actions.blocked, Some(CoinBlock::Sending));

        for locked in [false, true] {
            let err = app
                .set_utxo_locked(SetUtxoLockedRequest {
                    outpoint: outpoint.to_string(),
                    locked,
                })
                .unwrap_err();
            assert!(
                err.to_string().contains(mweb_frozen::RESERVED_MESSAGE),
                "{err}"
            );
        }
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let err = prepare_split(state, &public_split_req(outpoint), &app.session)
                .err()
                .unwrap();
            assert!(
                err.to_string().contains(mweb_frozen::RESERVED_MESSAGE),
                "{err}"
            );
            let address = state
                .wallet
                .peek_address(KeychainKind::External, 5)
                .address
                .to_string();
            let err = build_send_psbt(
                state,
                &SendRequest {
                    address,
                    amount_sats: 10_000,
                    fee_rate_sat_vb: Some(1),
                    drain: false,
                    selected_outpoints: None,
                },
            )
            .err()
            .unwrap();
            assert!(
                matches!(err, WalletError::BuildTx(_)),
                "auto selection must skip the held coin: {err}"
            );
        }

        drop(prepared);
        let row = app.list_unspent().unwrap().remove(0);
        assert_eq!(row.status, CoinStatus::Ready);
        assert!(!row.locked);
    }

    /// A failed public broadcast lets the coin go and leaves no freeze behind.
    #[test]
    fn failed_public_split_releases_its_hold() {
        let dir = tempfile::tempdir().unwrap();
        let (app, outpoint) = app_with_public_coin(dir.path(), 1_000_000);
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            state.electrum_url = "tcp://127.0.0.1:9".into();
            state.active_electrum_url = None;
            state.electrum_use_public_fallback = false;
        }
        app.split_coin(public_split_req(outpoint)).unwrap_err();

        let row = app.list_unspent().unwrap().remove(0);
        assert_eq!(row.status, CoinStatus::Ready);
        assert!(!row.locked);
        let file =
            mweb_frozen::read_ids(&app.lock_state().unwrap().as_ref().unwrap().data_dir).unwrap();
        assert!(file.public_reserved.is_empty());
    }

    /// A public hold written by an earlier process is gone after the next load.
    #[test]
    fn public_hold_from_a_crashed_session_clears_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let (app, outpoint) = app_with_public_coin(dir.path(), 1_000_000);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        mweb_frozen::reserve_public(&data_dir, &[outpoint], "crashed-session").unwrap();

        app.load(dir.path()).unwrap();

        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .public_reserved
            .is_empty());
        assert_eq!(app.list_unspent().unwrap()[0].status, CoinStatus::Ready);
    }

    fn actions_off(actions: &crate::dto::CoinActions) -> bool {
        !actions.spend_to_self
            && !actions.split
            && !actions.transfer
            && !actions.select
            && !actions.freeze
            && !actions.unfreeze
    }

    /// A user freeze and an in-flight hold on two private coins do not disturb each other.
    #[test]
    fn user_freeze_and_in_flight_hold_stay_separate() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000, 1_000_000]);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[0].clone(),
            locked: true,
        })
        .unwrap();
        let hold = CoinHold::take(&data_dir, vec![ids[1].clone()], &app.session).unwrap();

        let row_for = |id: &str| {
            app.list_mweb_unspent()
                .unwrap()
                .into_iter()
                .find(|coin| coin.output_id == id)
                .unwrap()
        };
        let frozen = row_for(&ids[0]);
        assert_eq!(frozen.status, CoinStatus::Frozen);
        assert!(frozen.locked);
        assert!(frozen.actions.unfreeze);
        let sending = row_for(&ids[1]);
        assert_eq!(sending.status, CoinStatus::Sending);
        assert!(!sending.locked, "the hold is not a user freeze");
        assert!(actions_off(&sending.actions));
        assert_eq!(sending.actions.blocked, Some(CoinBlock::Sending));

        let err = CoinHold::take(&data_dir, vec![ids[0].clone()], &app.session)
            .err()
            .unwrap();
        assert!(err.to_string().contains("frozen"), "{err}");

        let reserved = mweb_frozen::read_ids(&data_dir).unwrap().reserved;
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[2].clone(),
            locked: true,
        })
        .unwrap();
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[2].clone(),
            locked: false,
        })
        .unwrap();
        assert_eq!(mweb_frozen::read_ids(&data_dir).unwrap().reserved, reserved);

        drop(hold);
        assert_eq!(row_for(&ids[1]).status, CoinStatus::Ready);
        let still_frozen = row_for(&ids[0]);
        assert_eq!(still_frozen.status, CoinStatus::Frozen);
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .ids
            .contains(&ids[0]));

        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[0].clone(),
            locked: false,
        })
        .unwrap();
        assert_eq!(row_for(&ids[0]).status, CoinStatus::Ready);
        assert!(!mweb_frozen::frozen_path(&data_dir).is_file());
    }

    /// A user freeze and an in-flight hold on two public coins do not disturb each other.
    #[test]
    fn public_user_freeze_and_in_flight_hold_stay_separate() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ops) = app_with_public_coins(dir.path(), &[1_000_000, 2_000_000, 3_000_000]);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        app.set_utxo_locked(SetUtxoLockedRequest {
            outpoint: ops[0].to_string(),
            locked: true,
        })
        .unwrap();
        let hold = CoinHold::take_public(&data_dir, vec![ops[1]], &app.session).unwrap();

        let row_for = |op: &OutPoint| {
            app.list_unspent()
                .unwrap()
                .into_iter()
                .find(|coin| coin.outpoint == op.to_string())
                .unwrap()
        };
        let frozen = row_for(&ops[0]);
        assert_eq!(frozen.status, CoinStatus::Frozen);
        assert!(frozen.locked);
        assert!(frozen.actions.unfreeze);
        let sending = row_for(&ops[1]);
        assert_eq!(sending.status, CoinStatus::Sending);
        assert!(!sending.locked, "the hold is not a user freeze");
        assert!(actions_off(&sending.actions));
        assert_eq!(sending.actions.blocked, Some(CoinBlock::Sending));
        {
            let guard = app.lock_state().unwrap();
            assert!(
                !guard.as_ref().unwrap().wallet.is_outpoint_locked(ops[1]),
                "the hold never used BDK's lock_outpoint"
            );
        }

        let reserved = mweb_frozen::read_ids(&data_dir).unwrap().public_reserved;
        app.set_utxo_locked(SetUtxoLockedRequest {
            outpoint: ops[2].to_string(),
            locked: true,
        })
        .unwrap();
        app.set_utxo_locked(SetUtxoLockedRequest {
            outpoint: ops[2].to_string(),
            locked: false,
        })
        .unwrap();
        assert_eq!(
            mweb_frozen::read_ids(&data_dir).unwrap().public_reserved,
            reserved
        );

        drop(hold);
        let released = row_for(&ops[1]);
        assert_eq!(released.status, CoinStatus::Ready);
        assert!(!released.locked);
        assert_eq!(row_for(&ops[0]).status, CoinStatus::Frozen);
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .public_reserved
            .is_empty());

        app.set_utxo_locked(SetUtxoLockedRequest {
            outpoint: ops[0].to_string(),
            locked: false,
        })
        .unwrap();
        let thawed = row_for(&ops[0]);
        assert_eq!(thawed.status, CoinStatus::Ready);
        assert!(!thawed.locked);
    }

    /// Listed rows carry exactly what `coin_status` and `public_coin_status` return.
    #[test]
    fn listed_rows_carry_exactly_the_status_function_output() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = open_status_wallet(dir.path());
        let data_dir = wallet
            .app
            .lock_state()
            .unwrap()
            .as_ref()
            .unwrap()
            .data_dir
            .clone();
        let file = mweb_frozen::read_ids(&data_dir).unwrap();

        let private_rows = wallet.app.list_mweb_unspent().unwrap();
        for status in [
            CoinStatus::Ready,
            CoinStatus::Frozen,
            CoinStatus::Sending,
            CoinStatus::Pending,
            CoinStatus::Maturing,
        ] {
            assert!(
                private_rows.iter().any(|row| row.status == status),
                "missing private {status:?}"
            );
        }
        assert_eq!(
            private_rows
                .iter()
                .find(|row| row.output_id == wallet.private_frozen)
                .unwrap()
                .status,
            CoinStatus::Frozen
        );
        assert_eq!(
            private_rows
                .iter()
                .find(|row| row.output_id == wallet.private_held)
                .unwrap()
                .status,
            CoinStatus::Sending
        );
        for row in &private_rows {
            let (status, actions) = mweb::coin_status(&mweb::CoinFacts {
                confirmations: row.confirmations,
                mature: row.mature,
                maturity_blocks_left: row.maturity_blocks_left,
                locked: row.locked,
                reserved: file.reserved.contains_key(&row.output_id),
                from_pegin: row.from_pegin,
                non_solo_blocks: row.non_solo_blocks,
                churn_phase: row.churn_phase,
            });
            assert_eq!(
                (row.status, row.actions),
                (status, actions),
                "{}",
                row.output_id
            );
        }

        let public_rows = wallet.app.list_unspent().unwrap();
        for status in [
            CoinStatus::Ready,
            CoinStatus::Frozen,
            CoinStatus::Sending,
            CoinStatus::Pending,
            CoinStatus::Maturing,
        ] {
            assert!(
                public_rows.iter().any(|row| row.status == status),
                "missing public {status:?}"
            );
        }
        assert_eq!(
            public_rows
                .iter()
                .find(|row| row.outpoint == wallet.public_frozen.to_string())
                .unwrap()
                .status,
            CoinStatus::Frozen
        );
        assert_eq!(
            public_rows
                .iter()
                .find(|row| row.outpoint == wallet.public_held.to_string())
                .unwrap()
                .status,
            CoinStatus::Sending
        );
        for row in &public_rows {
            let (status, actions) = mweb::public_coin_status(&mweb::PublicCoinFacts {
                confirmations: row.confirmations,
                mature: row.mature,
                maturity_blocks_left: row.maturity_blocks_left,
                locked: row.locked,
                reserved: file.public_reserved.contains_key(&row.outpoint),
            });
            assert_eq!(
                (row.status, row.actions),
                (status, actions),
                "{}",
                row.outpoint
            );
        }
    }

    /// `set_mweb_utxo_locked` succeeds only when the listed coin's flag says so.
    #[test]
    fn private_freeze_command_follows_the_flags() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_with_job(dir.path(), ChurnPhase::WaitingForCover, false);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        let churn_hex = churn::read_job(&data_dir)
            .unwrap()
            .unwrap()
            .current_output_id;
        let churn_id: [u8; 32] = hex::decode(&churn_hex).unwrap().try_into().unwrap();
        let ready = [0x51; 32];
        let frozen = [0x52; 32];
        let held = [0x53; 32];
        let pending = [0x54; 32];
        let maturing = [0x55; 32];
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_private_coin(state, churn_id, 1_000_000, Some(0), false);
            insert_private_coin(state, ready, 1_000_000, Some(0), false);
            insert_private_coin(state, frozen, 1_000_000, Some(0), false);
            insert_private_coin(state, held, 1_000_000, Some(0), false);
            insert_private_coin(state, pending, 1_000_000, None, false);
            insert_private_coin(state, maturing, 1_000_000, Some(0), true);
        }
        let frozen_id = hex::encode(frozen);
        let held_id = hex::encode(held);
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: frozen_id.clone(),
            locked: true,
        })
        .unwrap();
        let _hold = CoinHold::take(&data_dir, vec![held_id.clone()], &app.session).unwrap();

        let rows = app.list_mweb_unspent().unwrap();
        for status in [
            CoinStatus::Churning,
            CoinStatus::Ready,
            CoinStatus::Frozen,
            CoinStatus::Sending,
            CoinStatus::Pending,
            CoinStatus::Maturing,
        ] {
            assert!(
                rows.iter().any(|row| row.status == status),
                "missing {status:?}"
            );
        }

        let ids: Vec<String> = rows.into_iter().map(|row| row.output_id).collect();
        for id in ids {
            for locked in [true, false] {
                let row = app
                    .list_mweb_unspent()
                    .unwrap()
                    .into_iter()
                    .find(|row| row.output_id == id)
                    .unwrap();
                let allowed = if locked {
                    row.actions.freeze
                } else {
                    row.actions.unfreeze
                };
                let before = frozen_file_bytes(&data_dir);
                let result = app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
                    output_id: id.clone(),
                    locked,
                });
                assert_flag_gates_command(
                    allowed,
                    result,
                    &before,
                    &data_dir,
                    &format!("{} locked={locked} ({:?})", id, row.status),
                );
            }
        }
    }

    /// `set_utxo_locked` succeeds only when the listed coin's flag says so.
    #[test]
    fn public_freeze_command_follows_the_flags() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = open_status_wallet(dir.path());
        let data_dir = wallet
            .app
            .lock_state()
            .unwrap()
            .as_ref()
            .unwrap()
            .data_dir
            .clone();
        let rows = wallet.app.list_unspent().unwrap();
        for status in [
            CoinStatus::Ready,
            CoinStatus::Pending,
            CoinStatus::Maturing,
            CoinStatus::Frozen,
            CoinStatus::Sending,
        ] {
            assert!(
                rows.iter().any(|row| row.status == status),
                "missing {status:?}"
            );
        }
        let outpoints: Vec<String> = rows.into_iter().map(|row| row.outpoint).collect();
        for outpoint in outpoints {
            for locked in [true, false] {
                let row = wallet
                    .app
                    .list_unspent()
                    .unwrap()
                    .into_iter()
                    .find(|row| row.outpoint == outpoint)
                    .unwrap();
                let allowed = if locked {
                    row.actions.freeze
                } else {
                    row.actions.unfreeze
                };
                let locked_before = {
                    let guard = wallet.app.lock_state().unwrap();
                    guard
                        .as_ref()
                        .unwrap()
                        .wallet
                        .is_outpoint_locked(OutPoint::from_str(&outpoint).unwrap())
                };
                let before = frozen_file_bytes(&data_dir);
                let result = wallet.app.set_utxo_locked(SetUtxoLockedRequest {
                    outpoint: outpoint.clone(),
                    locked,
                });
                let refused = result.is_err();
                assert_flag_gates_command(
                    allowed,
                    result,
                    &before,
                    &data_dir,
                    &format!("{outpoint} locked={locked} ({:?})", row.status),
                );
                if refused {
                    let guard = wallet.app.lock_state().unwrap();
                    assert_eq!(
                        guard
                            .as_ref()
                            .unwrap()
                            .wallet
                            .is_outpoint_locked(OutPoint::from_str(&outpoint).unwrap()),
                        locked_before,
                        "{outpoint} lock bit changed"
                    );
                }
            }
        }
    }

    /// Spending a selected coin succeeds exactly when its `select` flag is set.
    #[test]
    fn select_flag_matches_spend_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = open_status_wallet(dir.path());

        {
            let guard = wallet.app.lock_state().unwrap();
            let state = guard.as_ref().unwrap();
            let mweb = state.mweb.as_ref().unwrap();
            let tip = state.wallet.latest_checkpoint().height();
            let frozen = mweb_frozen::unavailable_ids(&state.data_dir).unwrap();
            let rows = mweb::list_mweb_unspent(mweb, tip, &state.data_dir);
            assert!(
                rows.len() >= 5,
                "expected every private status, got {}",
                rows.len()
            );
            for row in rows {
                let result = mweb::resolve_spend_coins(
                    mweb.store.db(),
                    tip,
                    &frozen,
                    Some(std::slice::from_ref(&row.output_id)),
                    1,
                    "spending",
                );
                assert_eq!(
                    result.is_ok(),
                    row.actions.select,
                    "{} ({:?}): {result:?}",
                    row.output_id,
                    row.status
                );
            }
        }

        let address = wallet.app.receive_address().unwrap();
        let mut guard = wallet.app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        let cases: Vec<(String, bool, CoinStatus)> = collect_unspent(state)
            .into_iter()
            .map(|row| (row.outpoint, row.actions.select, row.status))
            .collect();
        assert!(cases.len() >= 5, "expected every public status");
        for (outpoint, select, status) in cases {
            let result = build_send_psbt(
                state,
                &SendRequest {
                    address: address.clone(),
                    amount_sats: 10_000,
                    fee_rate_sat_vb: Some(1),
                    drain: false,
                    selected_outpoints: Some(vec![outpoint.clone()]),
                },
            );
            assert_eq!(
                result.is_ok(),
                select,
                "{outpoint} ({status:?}): {result:?}"
            );
        }
    }

    /// HogEx peg-outs require 6 confirmations (`PEGOUT_MATURITY`) and coinbase outputs require 100
    /// (`COINBASE_MATURITY`) before becoming `Ready`. Ordinary unconfirmed public coins stay
    /// selectable (`Pending`, `select: true`).
    #[test]
    fn hogex_pegout_and_coinbase_maturity_boundaries_in_public_coins() {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::chain::{BlockId, ConfirmationBlockTime};
        use bdk_wallet::test_utils::{insert_checkpoint, receive_output, ReceiveTo};

        let dir = tempfile::tempdir().unwrap();
        let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
        let recipient = app.receive_address().unwrap();

        let (ordinary_op, hogex_op, coinbase_op) = {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let block10 = BlockId {
                height: 10,
                hash: BlockHash::from_byte_array([10; 32]),
            };
            insert_checkpoint(&mut state.wallet, block10);
            let ordinary_op = receive_output(
                &mut state.wallet,
                Amount::from_sat(1_000_000),
                ReceiveTo::Mempool(1),
            );
            let hogex_op = insert_hogex_pegout_utxo(
                &mut state.wallet,
                Amount::from_sat(2_000_000),
                ReceiveTo::Mempool(2),
                0xa1,
            );
            let coinbase_op = insert_coinbase_utxo(
                &mut state.wallet,
                Amount::from_sat(3_000_000),
                ReceiveTo::Mempool(3),
                0xb1,
            );
            state.wallet.persist(&mut state.db).unwrap();
            (ordinary_op, hogex_op, coinbase_op)
        };

        let row_for = |op: OutPoint| {
            app.list_unspent()
                .unwrap()
                .into_iter()
                .find(|r| r.outpoint == op.to_string())
                .unwrap()
        };

        // At 0 confirmations: ordinary unconfirmed public coin stays selectable (`Pending`, `mature: true`),
        // while an unconfirmed HogEx peg-out is not selectable (`Pending`, `mature: false`, `maturity_blocks_left: 6`).
        let ord0 = row_for(ordinary_op);
        assert_eq!(ord0.confirmations, 0);
        assert!(ord0.mature);
        assert_eq!(ord0.maturity_blocks_left, 0);
        assert_eq!(ord0.status, CoinStatus::Pending);
        assert_eq!(ord0.actions.blocked, Some(CoinBlock::Unconfirmed));
        assert!(ord0.actions.select && ord0.actions.freeze);
        assert!(!ord0.actions.split && !ord0.actions.transfer);

        let hog0 = row_for(hogex_op);
        assert_eq!(hog0.confirmations, 0);
        assert!(!hog0.mature);
        assert_eq!(hog0.maturity_blocks_left, 6);
        assert_eq!(hog0.status, CoinStatus::Pending);
        assert_eq!(hog0.actions.blocked, Some(CoinBlock::Unconfirmed));
        assert!(actions_off(&hog0.actions));

        // Anchor the HogEx and coinbase outputs at height 10.
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let block10 = BlockId {
                height: 10,
                hash: BlockHash::from_byte_array([10; 32]),
            };
            bdk_wallet::test_utils::insert_anchor(
                &mut state.wallet,
                hogex_op.txid,
                ConfirmationBlockTime {
                    block_id: block10,
                    confirmation_time: 100,
                },
            );
            bdk_wallet::test_utils::insert_anchor(
                &mut state.wallet,
                coinbase_op.txid,
                ConfirmationBlockTime {
                    block_id: block10,
                    confirmation_time: 100,
                },
            );
            state.wallet.persist(&mut state.db).unwrap();
        }

        // Advance tip from 10 (1 conf) through 14 (5 confs): HogEx stays Maturing with 5..=1 blocks left.
        for tip in 10..=14u32 {
            {
                let mut guard = app.lock_state().unwrap();
                let state = guard.as_mut().unwrap();
                if tip > 10 {
                    insert_checkpoint(
                        &mut state.wallet,
                        BlockId {
                            height: tip,
                            hash: BlockHash::from_byte_array([tip as u8; 32]),
                        },
                    );
                }
            }
            let confs = tip - 10 + 1;
            let expected_left = 6 - confs;
            let hog = row_for(hogex_op);
            assert_eq!(hog.confirmations, confs, "tip={tip}");
            assert!(!hog.mature, "tip={tip}");
            assert_eq!(hog.maturity_blocks_left, expected_left, "tip={tip}");
            assert_eq!(hog.status, CoinStatus::Maturing, "tip={tip}");
            assert_eq!(
                hog.actions.blocked,
                Some(CoinBlock::Maturing {
                    blocks_left: expected_left
                }),
                "tip={tip}"
            );
            assert!(actions_off(&hog.actions), "tip={tip}: {:?}", hog.actions);

            // Commands must refuse maturing HogEx coin at 1..=5 confirmations.
            assert!(
                app.set_utxo_locked(SetUtxoLockedRequest {
                    outpoint: hogex_op.to_string(),
                    locked: true,
                })
                .is_err(),
                "freeze must fail at {confs} confs"
            );
            {
                let mut guard = app.lock_state().unwrap();
                let state = guard.as_mut().unwrap();
                assert!(
                    build_send_psbt(
                        state,
                        &SendRequest {
                            address: recipient.clone(),
                            amount_sats: 10_000,
                            fee_rate_sat_vb: Some(1),
                            drain: false,
                            selected_outpoints: Some(vec![hogex_op.to_string()]),
                        },
                    )
                    .is_err(),
                    "manual send must fail at {confs} confs"
                );
                assert!(
                    plan_split_request(state, &public_split_req(hogex_op)).is_err(),
                    "split must fail at {confs} confs"
                );
                assert!(
                    resolve_pegin_request(
                        state,
                        PeginRequest {
                            amount_sats: 100_000,
                            mweb_fee_sats: 2_100,
                            transparent_fee_sats: 1_000,
                            drain: false,
                            selected_outpoints: Some(vec![hogex_op.to_string()]),
                        },
                    )
                    .is_err(),
                    "manual peg-in must fail at {confs} confs"
                );
                // Auto-selection pool for peg-in excludes the maturing 2_000_000 HogEx and 3_000_000 coinbase,
                // leaving only the 1_000_000 ordinary coin.
                let held = mweb_frozen::public_reserved_outpoints(&state.data_dir).unwrap();
                assert_eq!(
                    selectable_public_utxo_amounts(state, &held),
                    vec![1_000_000],
                    "auto peg-in pool must exclude immature HogEx and coinbase at {confs} confs"
                );
            }
        }

        // At tip = 15 (6 confirmations: `15 - 10 + 1 == 6 >= PEGOUT_MATURITY`): HogEx is Ready and spendable.
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_checkpoint(
                &mut state.wallet,
                BlockId {
                    height: 15,
                    hash: BlockHash::from_byte_array([15; 32]),
                },
            );
        }
        let hog6 = row_for(hogex_op);
        assert_eq!(hog6.confirmations, 6);
        assert!(hog6.mature);
        assert_eq!(hog6.maturity_blocks_left, 0);
        assert_eq!(hog6.status, CoinStatus::Ready);
        assert_eq!(hog6.actions.blocked, None);
        assert!(
            hog6.actions.select
                && hog6.actions.split
                && hog6.actions.transfer
                && hog6.actions.freeze
        );
        assert!(!hog6.actions.unfreeze && !hog6.actions.spend_to_self);

        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            assert!(build_send_psbt(
                state,
                &SendRequest {
                    address: recipient.clone(),
                    amount_sats: 10_000,
                    fee_rate_sat_vb: Some(1),
                    drain: false,
                    selected_outpoints: Some(vec![hogex_op.to_string()]),
                },
            )
            .is_ok());
            assert!(plan_split_request(state, &public_split_req(hogex_op)).is_ok());
            assert!(resolve_pegin_request(
                state,
                PeginRequest {
                    amount_sats: 100_000,
                    mweb_fee_sats: 2_100,
                    transparent_fee_sats: 1_000,
                    drain: false,
                    selected_outpoints: Some(vec![hogex_op.to_string()]),
                },
            )
            .is_ok());
            let held = mweb_frozen::public_reserved_outpoints(&state.data_dir).unwrap();
            assert_eq!(
                selectable_public_utxo_amounts(state, &held),
                vec![2_000_000, 1_000_000]
            );
        }

        // Coinbase boundary: at tip = 108 (99 confirmations) still Maturing with 1 block left;
        // at tip = 109 (100 confirmations) Ready.
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_checkpoint(
                &mut state.wallet,
                BlockId {
                    height: 108,
                    hash: BlockHash::from_byte_array([108; 32]),
                },
            );
        }
        let cb99 = row_for(coinbase_op);
        assert_eq!(cb99.confirmations, 99);
        assert!(!cb99.mature);
        assert_eq!(cb99.maturity_blocks_left, 1);
        assert_eq!(cb99.status, CoinStatus::Maturing);
        assert_eq!(
            cb99.actions.blocked,
            Some(CoinBlock::Maturing { blocks_left: 1 })
        );
        assert!(actions_off(&cb99.actions));

        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            insert_checkpoint(
                &mut state.wallet,
                BlockId {
                    height: 109,
                    hash: BlockHash::from_byte_array([109; 32]),
                },
            );
        }
        let cb100 = row_for(coinbase_op);
        assert_eq!(cb100.confirmations, 100);
        assert!(cb100.mature);
        assert_eq!(cb100.maturity_blocks_left, 0);
        assert_eq!(cb100.status, CoinStatus::Ready);
        assert_eq!(cb100.actions.blocked, None);
        assert!(
            cb100.actions.select
                && cb100.actions.split
                && cb100.actions.transfer
                && cb100.actions.freeze
        );
    }

    /// A hold written by an earlier process is gone after the next load.
    #[test]
    fn hold_from_a_crashed_session_clears_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        let data_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
        mweb_frozen::reserve(&data_dir, &ids, "crashed-session").unwrap();
        mweb_frozen::set_locked(&data_dir, &"ee".repeat(32), true).unwrap();

        app.load(dir.path()).unwrap();

        let file = mweb_frozen::read_ids(&data_dir).unwrap();
        assert!(file.reserved.is_empty());
        assert!(file.ids.contains(&"ee".repeat(32)), "user freezes stay");
    }

    /// A stale expired record left behind a finished job must not bring it back.
    #[test]
    fn expired_record_does_not_revive_a_finished_job() {
        for phase in [ChurnPhase::Cancelled, ChurnPhase::Done] {
            let dir = tempfile::tempdir().unwrap();
            let app = app_with_job(dir.path(), phase, true);
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();

            undo_expired_local(state).unwrap();

            let job = churn::read_job(&state.data_dir).unwrap().unwrap();
            assert_eq!(job.phase(), phase);
            assert!(job.last_error.is_none());
            assert!(churn::read_armed(&state.data_dir).unwrap().is_none());
        }
    }

    /// The next background pass must not turn a foreign spend into an expiry.
    #[test]
    fn foreign_spend_survives_the_next_pass() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_with_foreign_spent_job(dir.path());
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();

        undo_expired_local(state).unwrap();

        let job = churn::read_job(&state.data_dir).unwrap().unwrap();
        assert_eq!(job.last_error.as_deref(), Some(churn::FOREIGN_SPEND));
        assert!(!job.needs_resign);
        assert!(job.input_spent_elsewhere);
    }

    /// The coin is gone, so Try again cannot sign a new hop from it.
    #[test]
    fn retry_after_foreign_spend_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let app = app_with_foreign_spent_job(dir.path());

        let err = app.retry_churn().unwrap_err().to_string();
        assert!(err.contains("spent by another transaction"), "{err}");

        let status = app.churn_status().unwrap().unwrap();
        assert_eq!(status.phase, ChurnPhase::WaitingForCover);
        assert_eq!(status.last_error.as_deref(), Some(churn::FOREIGN_SPEND));
        assert!(!status.actions.retry);
        assert!(status.actions.cancel);

        app.cancel_churn().expect("cancel still works");
    }

    mod crash_recovery_tests;
    mod error_path_tests;
    mod spv_tests;
    mod tx_invariants_tests;
}

/// Revealed external/internal addresses for local `is_wallet` tagging.
fn revealed_address_set(wallet: &PersistedWallet<Connection>) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        if let Some(last) = wallet.derivation_index(keychain) {
            for i in 0..=last {
                set.insert(wallet.peek_address(keychain, i).address.to_string());
            }
        }
    }
    set
}

fn is_mweb_stealth_address(address: &str) -> bool {
    let lower = address.trim().to_ascii_lowercase();
    lower.starts_with("ltcmweb") || lower.starts_with("tmweb")
}

/// Used = revealed and not in `list_unused_addresses` for that keychain.
fn used_revealed_addresses(
    wallet: &PersistedWallet<Connection>,
) -> std::collections::HashSet<String> {
    let mut used = std::collections::HashSet::new();
    for keychain in [KeychainKind::External, KeychainKind::Internal] {
        let Some(last) = wallet.derivation_index(keychain) else {
            continue;
        };
        let unused: std::collections::HashSet<String> = wallet
            .list_unused_addresses(keychain)
            .map(|info| info.address.to_string())
            .collect();
        for i in 0..=last {
            let addr = wallet.peek_address(keychain, i).address.to_string();
            if !unused.contains(&addr) {
                used.insert(addr);
            }
        }
    }
    used
}

fn compute_address_reuse_hint(
    wallet: &PersistedWallet<Connection>,
    address: &str,
) -> AddressReuseHint {
    let address = address.trim();
    if address.is_empty() || is_mweb_stealth_address(address) {
        return AddressReuseHint { reused: false };
    }
    AddressReuseHint {
        reused: used_revealed_addresses(wallet).contains(address),
    }
}

fn build_summary(state: &mut WalletState) -> Result<WalletSummary, WalletError> {
    let balance = state.wallet.balance();
    let tip_height = state.wallet.local_chain().tip().height();
    let tip_time = state
        .tip_time
        .filter(|_| state.tip_time_height == tip_height);
    // Prefer the last revealed address while it is still unused so a "New
    // address" click sticks across sync/reload. Once it has been used, reveal
    // the next index instead of falling back to an earlier unused gap address.
    let receive_address = current_receive_address(&mut state.wallet);
    state
        .wallet
        .persist(&mut state.db)
        .map_err(|e| WalletError::Persist(e.to_string()))?;

    Ok(WalletSummary {
        network: state.network,
        confirmed_sats: balance.confirmed.to_sat(),
        trusted_pending_sats: balance.trusted_pending.to_sat(),
        untrusted_pending_sats: balance.untrusted_pending.to_sat(),
        immature_sats: balance.immature.to_sat(),
        total_sats: balance.total().to_sat(),
        tip_height,
        tip_time,
        receive_address,
    })
}

fn current_receive_address(wallet: &mut PersistedWallet<Connection>) -> String {
    if let Some(last_idx) = wallet.derivation_index(KeychainKind::External) {
        let last_still_unused = wallet
            .list_unused_addresses(KeychainKind::External)
            .any(|info| info.index == last_idx);
        if last_still_unused {
            return wallet
                .peek_address(KeychainKind::External, last_idx)
                .to_string();
        }
    }
    wallet
        .reveal_next_address(KeychainKind::External)
        .to_string()
}

#[cfg(test)]
mod prefetch_tests {
    use super::WalletApp;
    use crate::dto::{CreateWalletRequest, UpdateSettingsRequest};
    use crate::error::WalletError;
    use crate::meta::{self, WALLET_DB_FILE, WALLET_META_FILE};
    use crate::network::WalletNetwork;

    fn point_at_invalid_electrum(app: &WalletApp) {
        let settings = app.settings().expect("settings");
        app.update_settings(UpdateSettingsRequest {
            electrum_url: "ssl://example.invalid:51002".into(),
            electrum_validate_domain: settings.electrum_validate_domain,
            electrum_use_public_fallback: false,
            auto_lock_minutes: settings.auto_lock_minutes,
            litecoin_rpc_url: settings.litecoin_rpc_url,
            broadcast_via_own_node: settings.broadcast_via_own_node,
            mweb_peers: settings.mweb_peers,
            explorer_base_url: settings.explorer_base_url,
            show_fiat: settings.show_fiat,
            use_explorer_fee_hints: settings.use_explorer_fee_hints,
            insights_enabled: settings.insights_enabled,
        })
        .expect("disable public electrum fallback");
    }

    #[test]
    fn locked_watch_only_keeps_receive_address() {
        let dir = tempfile::tempdir().unwrap();
        let app = WalletApp::new(dir.path());
        let created = app
            .create(
                dir.path(),
                CreateWalletRequest {
                    network: WalletNetwork::Testnet,
                    electrum_url: None,
                },
                "correct horse battery staple",
            )
            .expect("create");
        app.lock();
        assert!(app.is_locked());

        let peeked = WalletApp::watch_only_receive_address(dir.path()).expect("watch only");
        assert_eq!(peeked, created.summary.receive_address);
        assert!(app.is_locked(), "reading the public db must not unlock");
    }

    #[test]
    fn failed_prefetch_stays_locked_and_leaves_db() {
        let dir = tempfile::tempdir().unwrap();
        let app = WalletApp::new(dir.path());
        app.create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: Some("ssl://example.invalid:51002".into()),
            },
            "correct horse battery staple",
        )
        .expect("create");
        point_at_invalid_electrum(&app);
        app.lock();

        let account = app.active_account_dir(dir.path()).expect("account dir");
        let db_path = account.join(WALLET_DB_FILE);
        let meta_path = account.join(WALLET_META_FILE);
        let db_before = std::fs::read(&db_path).expect("db");
        let meta_before = std::fs::read(&meta_path).expect("meta");
        let meta = meta::read_meta(&account).expect("meta struct");
        assert!(meta.needs_full_scan);

        let err = app
            .prefetch_transparent(dir.path())
            .expect_err("invalid electrum host");
        assert!(matches!(err, WalletError::Electrum(_)), "{err}");
        assert!(app.is_locked());
        assert!(
            matches!(app.summary(), Err(WalletError::Locked)),
            "prefetch must not leave a session loaded"
        );
        assert_eq!(std::fs::read(&db_path).expect("db after"), db_before);
        assert_eq!(std::fs::read(&meta_path).expect("meta after"), meta_before);
    }
}

/// Pins the lock lifecycle described in `docs/LOCK_LIFECYCLE.md`.
#[cfg(test)]
mod lock_lifecycle_tests {
    use super::WalletApp;
    use crate::dto::{CreateWalletRequest, UnlockRequest};
    use crate::error::WalletError;
    use crate::lock::{LockEvent, LockState, LOCK_TRANSITIONS};
    use crate::network::WalletNetwork;
    use std::path::Path;
    use std::sync::atomic::Ordering;

    const PASSPHRASE: &str = "correct horse battery staple";

    fn unlocked_app(dir: &Path) -> WalletApp {
        let app = WalletApp::new(dir);
        app.create(
            dir,
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
            PASSPHRASE,
        )
        .expect("create");
        assert!(!app.is_locked());
        assert!(app.state.lock().unwrap().is_some());
        app
    }

    fn state_loaded(app: &WalletApp) -> bool {
        app.state.lock().unwrap().is_some()
    }

    /// Unlocked and loaded, then Lock with the mutex free: Locked and empty at once.
    #[test]
    fn lock_with_a_free_mutex_drops_state_and_park() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());

        app.lock();

        assert!(app.is_locked());
        assert!(!state_loaded(&app));
        assert!(!app.pending_lock.load(Ordering::Acquire));
        assert!(app.parked.lock().unwrap().slots.is_empty());
        assert!(matches!(app.summary(), Err(WalletError::Locked)));
    }

    /// Lock while a long operation holds the mutex: secrets go at once, state goes
    /// when that holder calls `check_lock` (or releases the guard).
    #[test]
    fn lock_during_a_held_mutex_defers_to_check_lock() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let mut guard = app.lock_state().unwrap();

        app.lock();
        assert!(app.is_locked(), "the mnemonic is wiped without waiting");
        assert!(app.pending_lock.load(Ordering::Acquire));
        assert!(guard.is_some(), "state waits for the holder");

        assert!(matches!(guard.check_lock(), Err(WalletError::Locked)));
        assert!(guard.is_none());
        assert!(!app.pending_lock.load(Ordering::Acquire));
    }

    /// Electrum has been persisted and the MWEB runtime is parked off the mutex.
    /// Public balance stays readable, private spend waits, and Lock still wins.
    #[test]
    fn public_summary_is_readable_while_mweb_is_detached() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let before = app.combined_summary().expect("combined");
        assert_ne!(before.mweb_status, "MWEB unavailable");

        let mut guard = app.lock_state().unwrap();
        let runtime = app
            .park_mweb(&mut guard)
            .unwrap()
            .expect("wallet has an MWEB runtime");
        drop(guard);

        let during = app
            .summary()
            .expect("public summary while confidential sync holds the runtime");
        assert_eq!(
            during.confirmed_sats, before.transparent.confirmed_sats,
            "transparent balance is the persisted one"
        );
        let combined = app.combined_summary().expect("snapshot while detached");
        assert_eq!(combined.mweb_total_sats, before.mweb_total_sats);
        assert_ne!(combined.mweb_status, "MWEB unavailable");
        let account_dir = {
            let guard = app.lock_state().unwrap();
            guard.as_ref().unwrap().data_dir.clone()
        };
        let rejected = app
            .mweb_send(crate::dto::MwebSendRequest {
                address: "ltcmweb1qqnotarealaddress".into(),
                amount_sats: 1,
                fee_sats: 0,
                drain: false,
                selected_output_ids: None,
            })
            .expect_err("private send waits for confidential sync");
        assert!(
            rejected
                .to_string()
                .contains("Confidential sync is still running"),
            "{rejected}"
        );

        app.restore_parked_mweb(&account_dir, runtime)
            .expect("reattach");
        let after = app
            .mweb_send(crate::dto::MwebSendRequest {
                address: "ltcmweb1qqnotarealaddress".into(),
                amount_sats: 1,
                fee_sats: 0,
                drain: false,
                selected_output_ids: None,
            })
            .expect_err("bad address, not the detach refusal");
        assert!(
            !after
                .to_string()
                .contains("Confidential sync is still running"),
            "{after}"
        );

        let mut guard = app.lock_state().unwrap();
        let runtime = app.park_mweb(&mut guard).unwrap().expect("park again");
        drop(guard);
        app.lock();
        let err = app
            .restore_parked_mweb(&account_dir, runtime)
            .expect_err("lock wins over reattach");
        assert!(matches!(err, WalletError::Locked), "{err}");
        assert!(app.is_locked());
        assert!(!state_loaded(&app));
    }

    /// A resync that fails after the download step must not leave pollers
    /// reading "downloading" until the next successful pass.
    #[test]
    fn failed_resync_leaves_the_sync_phase_idle() {
        crate::discovery::go_offline_for_test();
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let data_dir = {
            let mut guard = app.state.lock().unwrap();
            let state = guard.as_mut().unwrap();
            state.mweb_peers.clear();
            state.data_dir.clone()
        };
        std::fs::create_dir_all(crate::meta::mweb_seal_counter_path(&data_dir)).unwrap();

        assert!(
            app.resync_mweb().is_err(),
            "persist cannot write the seal counter"
        );

        assert_eq!(app.mweb_sync_progress().phase, crate::SyncPhase::Idle);
    }

    #[test]
    fn a_pass_dropped_mid_step_resets_to_idle() {
        let dir = tempfile::tempdir().unwrap();
        let app = WalletApp::new(dir.path());
        let phase = || app.mweb_sync_progress().phase;

        let pass = app.sync_pass();
        pass.electrum(true);
        assert_eq!(phase(), crate::SyncPhase::ElectrumFullScan);
        pass.mweb();
        assert_eq!(phase(), crate::SyncPhase::MwebDownload);
        drop(pass);

        assert_eq!(phase(), crate::SyncPhase::Idle);
    }

    #[test]
    fn a_finished_pass_shows_done_until_the_next_pass_ends() {
        let dir = tempfile::tempdir().unwrap();
        let app = WalletApp::new(dir.path());
        let phase = || app.mweb_sync_progress().phase;

        let pass = app.sync_pass();
        pass.electrum(false);
        pass.finish();
        assert_eq!(phase(), crate::SyncPhase::Done);

        let next = app.sync_pass();
        assert_eq!(
            phase(),
            crate::SyncPhase::Done,
            "starting a pass writes nothing"
        );
        drop(next);
        assert_eq!(phase(), crate::SyncPhase::Idle);
    }

    /// Unlock decrypts the mnemonic only. Loading the wallet is a separate step.
    #[test]
    fn unlock_does_not_load_state() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        app.lock();

        app.unlock(UnlockRequest {
            passphrase: PASSPHRASE.into(),
        })
        .expect("unlock");

        assert!(!app.is_locked());
        assert!(!state_loaded(&app));
        app.load(dir.path()).expect("load");
        assert!(state_loaded(&app));
    }

    /// The broadcast pump runs while locked. It must not unlock or load anything.
    #[test]
    fn pump_while_locked_stays_locked_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let account = app.active_account_dir(dir.path()).unwrap();
        app.lock();

        app.pump_churn_broadcast(&account).expect("pump");

        assert!(app.is_locked());
        assert!(!state_loaded(&app));
    }

    /// Lock that races a short holder: the holder never checks, but releasing
    /// the guard drops the state before the next pump can reuse it.
    #[test]
    fn lock_racing_a_short_holder_still_drops_state() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let guard = app.lock_state().unwrap();
        app.lock();
        drop(guard);

        // The next background pump is the first thing to touch the state.
        let account = app.active_account_dir(dir.path()).unwrap();
        app.pump_churn_broadcast(&account).expect("pump");

        assert!(app.is_locked());
        assert!(!state_loaded(&app), "signer and wallet are still in memory");
    }

    /// Releasing a guard taken before Lock is enough; nothing else has to run.
    #[test]
    fn lock_during_holder_drops_state_on_release() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let guard = app.lock_state().unwrap();

        app.lock();
        drop(guard);

        assert!(app.is_locked());
        assert!(!state_loaded(&app), "signer and wallet are still in memory");
        assert!(!app.pending_lock.load(Ordering::Acquire));
        assert!(app.parked.lock().unwrap().slots.is_empty());
    }

    /// Once locked, ordinary holders are refused instead of seeing an empty state.
    #[test]
    fn lock_state_refuses_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        app.lock();

        assert!(matches!(app.lock_state(), Err(WalletError::Locked)));
    }

    /// The state `crate::lock::LockState` names for what the app holds now.
    /// `held` is the guard a test is holding, since the mutex is then taken.
    fn observe(app: &WalletApp, held: Option<&super::StateGuard<'_>>) -> LockState {
        let loaded = match held {
            Some(guard) => guard.is_some(),
            None => state_loaded(app),
        };
        let pending = app.pending_lock.load(Ordering::Acquire);
        match (app.is_locked(), pending, loaded) {
            (true, false, false) => LockState::Locked,
            (false, false, false) => LockState::UnlockedEmpty,
            (false, false, true) => LockState::Loaded,
            (true, true, true) => LockState::LockPending,
            other => panic!("(locked, pending, loaded) = {other:?} is not in the lock table"),
        }
    }

    /// Every row of `LOCK_TRANSITIONS`, reproduced on a real app.
    #[test]
    fn lock_table_matches_behavior() {
        for (from, event, to) in LOCK_TRANSITIONS {
            let dir = tempfile::tempdir().unwrap();
            let app = unlocked_app(dir.path());
            let mut held = None;
            match from {
                LockState::Locked => app.lock(),
                LockState::UnlockedEmpty => {
                    app.lock();
                    app.unlock(UnlockRequest {
                        passphrase: PASSPHRASE.into(),
                    })
                    .unwrap();
                }
                LockState::Loaded => {}
                LockState::LockPending => {
                    held = Some(app.lock_state().unwrap());
                    app.lock();
                }
            }
            assert_eq!(observe(&app, held.as_ref()), *from, "setup for {event:?}");

            match event {
                LockEvent::Unlock => app
                    .unlock(UnlockRequest {
                        passphrase: PASSPHRASE.into(),
                    })
                    .unwrap(),
                LockEvent::Load => {
                    app.load(dir.path()).unwrap();
                }
                LockEvent::Lock => app.lock(),
                LockEvent::LockWhileHeld => {
                    held = Some(app.lock_state().unwrap());
                    app.lock();
                }
                LockEvent::CheckLock => {
                    let guard = held.as_mut().expect("a held guard");
                    assert!(matches!(guard.check_lock(), Err(WalletError::Locked)));
                }
                LockEvent::ReleaseGuard => held = None,
            }
            assert_eq!(observe(&app, held.as_ref()), *to, "{event:?} from {from:?}");
        }
    }

    /// Run one deterministic random walk against `app` starting from `start`
    /// (`Loaded` or `Locked`), using an explicit mutex-holder model
    /// (`held: Option<StateGuard>`):
    /// - While `held.is_some()`, only `Lock`, `CheckLock`, and `ReleaseGuard`
    ///   are generated (`Load` and `LockWhileHeld` would deadlock on the same
    ///   thread's mutex; `Unlock` while `LockPending` is the documented "Known
    ///   edge" in `docs/LOCK_LIFECYCLE.md`).
    /// - `CheckLock` drops `held` immediately after observing `Err(Locked)`,
    ///   matching how real holders exit on `guard.check_lock()?`.
    /// - `ReleaseGuard` drops `held`.
    /// - Replay a single failing seed by creating `unlocked_app` once and
    ///   calling `walk_lock(&app, dir.path(), seed, start, STEPS, &mut hits)`.
    fn walk_lock(
        app: &WalletApp,
        data_dir: &Path,
        seed: u64,
        start: LockState,
        steps_per_walk: usize,
        hit_rows: &mut [bool],
    ) {
        use rand::{rngs::StdRng, Rng, SeedableRng};

        // Only events that can actually be called in the current mutex state:
        // `CheckLock` and `ReleaseGuard` require a held `StateGuard`; while a
        // guard is held, `Load` and `LockWhileHeld` would deadlock on this
        // thread's mutex.
        const FREE_EVENTS: [LockEvent; 4] = [
            LockEvent::Unlock,
            LockEvent::Load,
            LockEvent::Lock,
            LockEvent::LockWhileHeld,
        ];
        const HELD_EVENTS: [LockEvent; 3] = [
            LockEvent::Lock,
            LockEvent::CheckLock,
            LockEvent::ReleaseGuard,
        ];

        let mut rng = StdRng::seed_from_u64(seed);
        match start {
            LockState::Locked => app.lock(),
            LockState::UnlockedEmpty => {
                app.lock();
                app.unlock(UnlockRequest {
                    passphrase: PASSPHRASE.into(),
                })
                .unwrap();
            }
            LockState::Loaded => {
                if app.is_locked() {
                    app.unlock(UnlockRequest {
                        passphrase: PASSPHRASE.into(),
                    })
                    .unwrap();
                }
                if !state_loaded(app) {
                    app.load(data_dir).unwrap();
                }
            }
            LockState::LockPending => unreachable!("walk_lock starts with no held guard"),
        }
        let mut held: Option<super::StateGuard<'_>> = None;
        let mut steps: Vec<String> = Vec::with_capacity(steps_per_walk);

        for step in 0..steps_per_walk {
            let from = observe(app, held.as_ref());
            assert_eq!(
                from == LockState::LockPending,
                held.is_some(),
                "seed={seed} mutex model drifted before step {step}: state={from:?} held={}\nsteps={steps:#?}",
                held.is_some()
            );

            let choices: &[LockEvent] = if held.is_some() {
                &HELD_EVENTS
            } else {
                &FREE_EVENTS
            };
            let event = choices[rng.gen_range(0..choices.len())];

            match event {
                LockEvent::Unlock => {
                    let _ = app.unlock(UnlockRequest {
                        passphrase: PASSPHRASE.into(),
                    });
                }
                LockEvent::Load => {
                    let _ = app.load(data_dir);
                }
                LockEvent::Lock => app.lock(),
                LockEvent::LockWhileHeld => {
                    // Mirrors wallet commands: `let guard = self.lock_state()?;
                    // let _ = guard.as_ref().ok_or(WalletError::NotLoaded)?;`
                    if let Ok(guard) = app.lock_state() {
                        if guard.is_some() {
                            held = Some(guard);
                            app.lock();
                        }
                    }
                }
                LockEvent::CheckLock => {
                    let mut guard = held
                        .take()
                        .expect("CheckLock is only generated when a guard is held");
                    let res = guard.check_lock();
                    assert!(
                        matches!(res, Err(WalletError::Locked)),
                        "seed={seed} CheckLock in {from:?} expected Err(Locked), got {res:?}\nsteps={steps:#?}"
                    );
                    drop(guard);
                }
                LockEvent::ReleaseGuard => {
                    let guard = held
                        .take()
                        .expect("ReleaseGuard is only generated when a guard is held");
                    drop(guard);
                }
            }

            let after = observe(app, held.as_ref());
            steps.push(format!("#{step}: {from:?} + {event:?} -> {after:?}"));

            assert_eq!(
                after == LockState::LockPending,
                held.is_some(),
                "seed={seed} mutex model drifted after step {step}: state={after:?} held={}\nsteps={steps:#?}",
                held.is_some()
            );

            if let Some(idx) = LOCK_TRANSITIONS
                .iter()
                .position(|(f, e, _)| *f == from && *e == event)
            {
                hit_rows[idx] = true;
                let expected = LOCK_TRANSITIONS[idx].2;
                assert_eq!(
                    after, expected,
                    "seed={seed} row ({from:?}, {event:?}) expected {expected:?}, got {after:?}\nsteps={steps:#?}"
                );
            } else {
                assert_eq!(
                    after, from,
                    "seed={seed} unmapped event {event:?} from {from:?} changed state to {after:?}\nsteps={steps:#?}"
                );
            }
        }

        drop(held);
    }

    /// Model-based random walks over `LOCK_TRANSITIONS` on a real `WalletApp`.
    /// Checks mapped transitions, unmapped no-op stability, legal `(locked,
    /// pending, loaded)` triples via `observe()`, and full row coverage.
    #[test]
    fn lock_random_walks_match_table_and_cover_all_rows() {
        const SEEDS: u64 = 5;
        const STEPS: usize = 8;

        const STARTS: [LockState; 3] = [
            LockState::Loaded,
            LockState::UnlockedEmpty,
            LockState::Locked,
        ];

        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let mut hit_rows = vec![false; LOCK_TRANSITIONS.len()];
        for seed in 0..SEEDS {
            let start = STARTS[(seed as usize) % STARTS.len()];
            walk_lock(&app, dir.path(), seed, start, STEPS, &mut hit_rows);
        }

        for (idx, (from, event, to)) in LOCK_TRANSITIONS.iter().enumerate() {
            assert!(
                hit_rows[idx],
                "row ({from:?}, {event:?} -> {to:?}) was never exercised across {SEEDS}×{STEPS} walks"
            );
        }
    }

    /// Wipe is offered on the locked screen, so it must not need an unlock.
    #[test]
    fn wipe_works_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        app.lock();

        app.wipe(dir.path()).expect("wipe");

        assert!(!app.exists(dir.path()));
        assert!(!state_loaded(&app));
    }

    #[test]
    fn pegin_raw_tx_error_redacts_rpc_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let electrum_addr = listener.local_addr().unwrap();
        let closed_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_rpc_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let app = unlocked_app(dir.path());
        let client =
            crate::electrum::connect_with_timeout(&format!("tcp://{electrum_addr}"), false, 2)
                .unwrap();

        let err = {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            state.electrum_use_public_fallback = false;
            state.electrum_url = format!("tcp://{electrum_addr}");
            state.active_electrum_url = Some(state.electrum_url.clone());
            state.litecoin_rpc_url = Some(format!(
                "http://rpcadmin:SuperSecretRpcPass42@127.0.0.1:{closed_rpc_port}"
            ));
            super::fetch_pegin_raw_tx(&"11".repeat(32), &client, state, true)
                .expect_err("closed electrum + closed rpc must fail")
        };
        let _ = handle.join();

        assert!(
            !err.contains("SuperSecretRpcPass42") && !err.contains("rpcadmin:"),
            "fetch_pegin_raw_tx leaked RPC credentials in error: {err}"
        );
    }
}

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use bdk_electrum::electrum_client::ElectrumApi;
use bdk_mweb::mweb_sync::SyncProgress;

use bdk_wallet::bitcoin::consensus::encode::deserialize;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, Psbt, ScriptBuf, Txid};
use bdk_wallet::chain::ChainPosition;
use bdk_wallet::miniscript::descriptor::KeyMapWrapper;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet};

use crate::churn;
use crate::contacts;
use crate::descriptors::{self, create_params, load_params, sign_and_finalize, signer};
use crate::diag;
use crate::dto::{
    AddressReuseHint, ChurnPhase, ChurnPreview, ChurnRequest, ChurnStatus, CombinedSummary,
    ContactRecord, CoverHold, CreateWalletRequest, CreateWalletResponse, DeleteContactRequest,
    DiagnosticsBundle, ElectrumProbe, FeeEstimate, MigrateEncryptRequest, MwebBroadcastResult,
    MwebScheme, MwebSendPreview, MwebSendRequest, MwebUtxoRecord, PeginPreview, PeginRequest,
    PeginResult, PegoutPreview, PegoutRequest, RestoreWalletRequest, RevealMnemonicRequest,
    RevealMnemonicResponse, SendPreview, SendRequest, SendResult, SetMwebUtxoLockedRequest,
    SetTxLabelRequest, SetUtxoLabelRequest, SetUtxoLockedRequest, SplitChain, SplitPreview,
    SplitRequest, SplitResult, SyncPhase, SyncResult, TxKind, TxRecord, UnlockRequest,
    UpdateSettingsRequest, UpsertContactRequest, UtxoRecord, WalletSettings, WalletSummary,
    CHURN_AMOUNT_NOTE, DEFAULT_MWEB_FEE_SATS,
};
use crate::electrum::{self, BATCH_SIZE, MIN_FEE_RATE_SAT_VB, STOP_GAP};
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
use crate::utxo_labels;
use crate::{MNEMONIC_ENC_FILE, MNEMONIC_FILE};

struct WalletState {
    wallet: PersistedWallet<Connection>,
    /// Caller-owned transparent signing keys (see [`descriptors::signer`]); the wallet itself
    /// holds no secrets. Lives and dies with this state, i.e. cleared on `lock()`.
    signer: KeyMapWrapper,
    db: Connection,
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
        network: state.network,
        electrum_url: state.electrum_url.clone(),
        electrum_validate_domain: state.electrum_validate_domain,
        electrum_use_public_fallback: state.electrum_use_public_fallback,
        auto_lock_minutes: state.auto_lock_minutes,
        needs_full_scan: state.needs_full_scan,
        needs_mweb_scan: state.needs_mweb_scan,
        litecoin_rpc_url: state.litecoin_rpc_url.clone(),
        mweb_peers: state.mweb_peers.clone(),
        mweb_scheme: state.mweb_scheme,
        explorer_base_url: state.explorer_base_url.clone(),
        show_fiat: state.show_fiat,
        use_explorer_fee_hints: state.use_explorer_fee_hints,
        insights_enabled: state.insights_enabled,
    }
}

/// Candidate Electrum URLs in try order: last-good this session, configured,
/// then (unless the user opted out) the built-in public defaults.
fn electrum_candidates(state: &WalletState) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    if let Some(active) = &state.active_electrum_url {
        urls.push(active.clone());
    }
    if !urls.contains(&state.electrum_url) {
        urls.push(state.electrum_url.clone());
    }
    if state.electrum_use_public_fallback {
        for default in state.network.default_electrum_urls() {
            let default = default.to_string();
            if !urls.contains(&default) {
                urls.push(default);
            }
        }
    }
    urls
}

/// Connect with fallback across [`electrum_candidates`], remembering what worked.
fn connect_electrum(
    state: &mut WalletState,
) -> Result<crate::electrum::ElectrumClient, WalletError> {
    let candidates = electrum_candidates(state);
    let (client, used) = electrum::connect_first(&candidates, state.electrum_validate_domain)?;
    if used != state.electrum_url {
        diag::log(format!(
            "electrum: configured server unavailable; using fallback {used}"
        ));
    }
    state.active_electrum_url = Some(used);
    Ok(client)
}

/// Explorer settings Insights needs. Kept off the wallet mutex so a litview
/// refresh does not wait out Electrum or MWEB sync.
struct InsightsEndpoint {
    enabled: bool,
    base_url: String,
}

/// Application-facing wallet handle. BDK types stay private.
pub struct WalletApp {
    state: Mutex<Option<WalletState>>,
    secrets: Arc<EncryptedFileSecretStore>,
    /// Shared MWEB download progress; lives outside the state mutex so it can be
    /// polled while a sync (which holds that mutex) is in flight.
    mweb_progress: Arc<SyncProgress>,
    mweb_sync_active: AtomicBool,
    /// Coarse sync phase for UI polling (see [`SyncPhase`]).
    sync_phase: AtomicU8,
    /// Set when [`Self::lock`] cannot take the state mutex (e.g. sync in flight).
    /// The holder must drop in-memory wallet state before returning.
    pending_lock: AtomicBool,
    /// Copied from wallet state on load and settings save. Insights reads this
    /// instead of the wallet mutex.
    insights_endpoint: Mutex<Option<InsightsEndpoint>>,
}

impl WalletApp {
    /// Create a wallet app with encrypted file-backed mnemonic storage under `data_dir`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            state: Mutex::new(None),
            secrets: Arc::new(EncryptedFileSecretStore::new(
                data_dir.join(MNEMONIC_ENC_FILE),
                data_dir.join(MNEMONIC_FILE),
            )),
            mweb_progress: Arc::new(SyncProgress::default()),
            mweb_sync_active: AtomicBool::new(false),
            sync_phase: AtomicU8::new(SyncPhase::Idle.as_u8()),
            pending_lock: AtomicBool::new(false),
            insights_endpoint: Mutex::new(None),
        }
    }

    fn set_sync_phase(&self, phase: SyncPhase) {
        self.sync_phase.store(phase.as_u8(), Ordering::Relaxed);
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
        }
    }

    /// Redacted support bundle for Export diagnostics (no secrets).
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

        let Ok(guard) = self.state.try_lock() else {
            bundle
                .recent_log_lines
                .push("note: wallet busy (sync in progress); meta snapshot skipped".into());
            return bundle;
        };
        let Some(state) = guard.as_ref() else {
            return bundle;
        };

        bundle.network = Some(format!("{:?}", state.network).to_lowercase());
        bundle.electrum_url = Some(state.electrum_url.clone());
        bundle.electrum_validate_domain = Some(state.electrum_validate_domain);
        bundle.electrum_use_public_fallback = Some(state.electrum_use_public_fallback);
        bundle.active_electrum_url = state.active_electrum_url.clone();
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
            secrets,
        }
    }

    pub fn exists(&self, data_dir: &Path) -> bool {
        meta::wallet_files_exist(data_dir)
    }

    pub fn is_locked(&self) -> bool {
        self.secrets.is_locked()
    }

    /// 32-byte secp256k1 secret for LitVM (`m/44'/60'/0'/0/0`). Requires unlock.
    /// Caller must zeroize after use. Never log this value.
    pub fn litvm_account_secret(&self) -> Result<[u8; 32], WalletError> {
        self.ensure_unlocked()?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        secret.litvm_account_secret()
    }

    pub fn needs_migration(&self) -> bool {
        self.secrets.needs_migration()
    }

    pub fn unlock(&self, req: UnlockRequest) -> Result<(), WalletError> {
        self.secrets.unlock(&req.passphrase)
    }

    /// Re-verify the wallet passphrase and return the stored recovery secret for display.
    ///
    /// Always re-decrypts (does not trust an already-unlocked session). Plaintext
    /// legacy stores (awaiting migration) have no passphrase to check.
    pub fn reveal_mnemonic(
        &self,
        req: RevealMnemonicRequest,
    ) -> Result<RevealMnemonicResponse, WalletError> {
        if self.secrets.needs_migration() {
            // Plaintext store — nothing to verify against.
        } else {
            self.secrets.unlock(&req.passphrase)?;
        }
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let (phrase, aezeed_passphrase) = secret.backup_material();
        Ok(RevealMnemonicResponse {
            kind: secret.kind().to_string(),
            phrase,
            aezeed_passphrase,
        })
    }

    /// Lock immediately: wipe the decrypted mnemonic, then drop in-memory wallet
    /// state if the state mutex is free. When sync (or another long op) holds the
    /// mutex, set [`Self::pending_lock`] so that holder discards state before return.
    ///
    /// Does **not** block on an in-flight sync.
    pub fn lock(&self) {
        self.secrets.lock();
        self.clear_insights();
        self.pending_lock.store(true, Ordering::Release);
        match self.state.try_lock() {
            Ok(mut guard) => {
                *guard = None;
                self.pending_lock.store(false, Ordering::Release);
            }
            Err(TryLockError::WouldBlock) => {
                // Sync/send holds the state; secrets are already cleared.
            }
            Err(TryLockError::Poisoned(poisoned)) => {
                let mut guard = poisoned.into_inner();
                *guard = None;
                self.pending_lock.store(false, Ordering::Release);
            }
        }
    }

    /// If the user locked while we held `guard`, drop wallet state and report locked.
    fn abort_if_locked(
        &self,
        guard: &mut MutexGuard<'_, Option<WalletState>>,
    ) -> Result<(), WalletError> {
        if !self.pending_lock.load(Ordering::Acquire) && !self.secrets.is_locked() {
            return Ok(());
        }
        **guard = None;
        self.clear_insights();
        self.secrets.lock();
        self.pending_lock.store(false, Ordering::Release);
        Err(WalletError::Locked)
    }

    pub fn migrate_encrypt(&self, req: MigrateEncryptRequest) -> Result<(), WalletError> {
        self.secrets.migrate_encrypt(&req.passphrase)
    }

    /// Delete wallet files and mnemonic secret. Safe if already absent.
    pub fn wipe(&self, data_dir: &Path) -> Result<(), WalletError> {
        *self.lock_state()? = None;
        self.clear_insights();
        self.secrets.delete_mnemonic()?;
        meta::remove_wallet_files(data_dir)?;
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
        Ok(CreateWalletResponse { mnemonic, summary })
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
            req.electrum_url,
            passphrase,
            req.mweb_scheme,
        )
    }

    pub fn load(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        self.ensure_unlocked()?;
        if !self.exists(data_dir) {
            return Err(WalletError::NotFound);
        }

        let meta = meta::read_meta(data_dir)?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;

        let mut db = Connection::open(meta::db_path(data_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = load_params(&secret, meta.network)?;
        let wallet = PersistedWallet::load(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?
            .ok_or(WalletError::NotFound)?;

        let mweb = MwebRuntime::open(
            data_dir,
            &secret,
            meta.network,
            meta.mweb_scheme.to_master_scheme(),
            self.secrets.sealing_key(),
        )
        .ok();

        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(&secret, meta.network)?,
            db,
            network: meta.network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            mweb_peers: meta.mweb_peers,
            mweb_scheme: meta.mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: data_dir.to_path_buf(),
            needs_full_scan: meta.needs_full_scan,
            needs_mweb_scan: meta.needs_mweb_scan,
            mweb,
        };
        let summary = build_summary(&mut state)?;
        self.publish_insights(&state);
        *self.lock_state()? = Some(state);
        Ok(summary)
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
        } else {
            Ok(CombinedSummary {
                transparent,
                mweb_confirmed_sats: 0,
                mweb_unconfirmed_sats: 0,
                mweb_immature_sats: 0,
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
                let net_sats = received_sats as i64 - sent_sats as i64;
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
        let outpoint = parse_outpoint(&req.outpoint)?;
        if req.locked {
            state.wallet.lock_outpoint(outpoint);
        } else {
            state.wallet.unlock_outpoint(outpoint);
        }
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(())
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
        refuse_churn_unfreeze(&state.data_dir, &req.output_id, req.locked)?;
        mweb_frozen::set_locked(&state.data_dir, &req.output_id, req.locked)
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
        let (tip_height, latency_ms) = electrum::probe_tip(&url, state.electrum_validate_domain)?;
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
        state.electrum_url = req.electrum_url.trim().to_string();
        state.electrum_validate_domain = req.electrum_validate_domain;
        state.electrum_use_public_fallback = req.electrum_use_public_fallback;
        state.auto_lock_minutes = req.auto_lock_minutes;
        // New configured server should be tried first on the next connection.
        state.active_electrum_url = None;
        state.litecoin_rpc_url = req
            .litecoin_rpc_url
            .map(|s| crate::rpc::normalize_rpc_url(&s))
            .filter(|s| !s.is_empty());
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

    /// Build a litview `/tx/{txid}` URL (no network).
    pub fn explorer_tx_url(&self, txid: &str) -> Result<String, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        crate::explorer::tx_url(&state.explorer_base_url, txid)
    }

    /// Build a litview `/block/{hash}` URL (no network).
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

    pub fn sync(&self) -> Result<SyncResult, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;

        let electrum_started = std::time::Instant::now();
        let client = connect_electrum(state)?;
        client.populate_tx_cache(state.wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));

        let tx_count_before = state.wallet.transactions().count();
        let did_full_scan = state.needs_full_scan;
        let prev_tip = state.last_tip_height;

        if did_full_scan {
            self.set_sync_phase(SyncPhase::ElectrumFullScan);
            diag::log("sync: electrum full_scan starting");
            let request = state.wallet.start_full_scan();
            let update = client
                .full_scan(request, STOP_GAP, BATCH_SIZE, false)
                .map_err(|e| {
                    self.set_sync_phase(SyncPhase::Idle);
                    WalletError::Electrum(e.to_string())
                })?;
            state.wallet.apply_update(update).map_err(|e| {
                self.set_sync_phase(SyncPhase::Idle);
                WalletError::Electrum(e.to_string())
            })?;
        } else {
            self.set_sync_phase(SyncPhase::ElectrumSync);
            let request = state.wallet.start_sync_with_revealed_spks();
            let update = client.sync(request, BATCH_SIZE, false).map_err(|e| {
                self.set_sync_phase(SyncPhase::Idle);
                WalletError::Electrum(e.to_string())
            })?;
            state.wallet.apply_update(update).map_err(|e| {
                self.set_sync_phase(SyncPhase::Idle);
                WalletError::Electrum(e.to_string())
            })?;
        }

        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let electrum_ms = electrum_started.elapsed().as_millis() as u64;

        let tip_height = state.wallet.latest_checkpoint().height();
        let tip_hash = state.wallet.latest_checkpoint().hash();

        if tip_height < prev_tip {
            if let Some(ref mut mweb) = state.mweb {
                mweb.disconnect_from(tip_height.saturating_add(1));
            }
        }
        state.last_tip_height = tip_height;
        let timed_height = state.wallet.local_chain().tip().height();
        match electrum::header_time(&client, timed_height) {
            Ok(time) => {
                state.tip_time = Some(time);
                state.tip_time_height = timed_height;
            }
            Err(_) => {
                if state.tip_time_height != timed_height {
                    state.tip_time = None;
                }
            }
        }

        if did_full_scan {
            state.needs_full_scan = false;
        }

        // Privacy-preserving second opinion: compare the served chain against
        // an independent server (headers only, never our scripts).
        let mut warnings: Vec<String> = Vec::new();
        let used_server = state
            .active_electrum_url
            .clone()
            .unwrap_or_else(|| state.electrum_url.clone());
        if let Some(alt) = electrum_candidates(state)
            .into_iter()
            .find(|url| *url != used_server)
        {
            let chain = state.wallet.local_chain();
            let local_hash_at = |height: u32| chain.get(height).map(|cp| cp.hash());
            match electrum::cross_check_tip(
                &alt,
                state.electrum_validate_domain,
                tip_height,
                &local_hash_at,
            ) {
                Ok(Some(warning)) => warnings.push(warning),
                Ok(None) => {}
                // Unreachable second server is not a finding; skip quietly.
                Err(_) => {}
            }
        }

        // Skip the long MWEB pass if the user locked during Electrum sync.
        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;

        // MWEB sync (best-effort; peer failure → stale, not hard error).
        let mut mweb_ms = 0u64;
        if let Some(ref mut mweb) = state.mweb {
            self.set_sync_phase(SyncPhase::MwebDownload);
            diag::log("sync: mweb download starting");
            let mweb_started = std::time::Instant::now();
            let peers = state.mweb_peers.clone();
            let network = state.network;
            // Hash on the current chain at the previous MWEB sync height, so the syncer
            // can detect a pure extension and skip the full UTXO re-download.
            let prev_tip_hash = mweb
                .sync_state
                .tip_height
                .and_then(|h| state.wallet.local_chain().get(h))
                .map(|cp| cp.hash());
            self.with_mweb_progress(|progress| {
                let _ = mweb.sync_at_tip(
                    tip_height,
                    tip_hash,
                    prev_tip_hash,
                    &peers,
                    network,
                    Some(progress),
                );
            });
            if state.needs_mweb_scan {
                state.needs_mweb_scan = false;
            }
            if let Some(warning) = mweb.cross_check_warning.clone() {
                warnings.push(warning);
            }
            let _ = mweb.persist(&state.data_dir);
            mweb_ms = mweb_started.elapsed().as_millis() as u64;
            diag::log(format!("sync: mweb finished in {mweb_ms} ms"));
        }

        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        if state.mweb.is_some() {
            let _ = drive_churn(state, Some(&client));
        }

        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;

        // Repair peg-ins that credited MWEB without spending transparent UTXOs
        // (bug in earlier builds). Prefer Electrum raw tx; fall back to RPC.
        if state.mweb.is_some() {
            if let Some(repair_warning) = repair_missing_pegin_spends(state, &client)? {
                warnings.push(repair_warning);
            }
        }

        meta::write_meta(&state.data_dir, &meta_from_state(state))?;

        let tx_count_after = state.wallet.transactions().count();
        let new_txs = tx_count_after.saturating_sub(tx_count_before) as u32;
        let summary = build_summary(state)?;
        self.abort_if_locked(&mut guard)?;
        self.set_sync_phase(SyncPhase::Done);
        diag::log(format!(
            "sync: done electrum_ms={electrum_ms} mweb_ms={mweb_ms} new_txs={new_txs}"
        ));
        // Leave Done briefly visible to pollers, then idle on next pollers' natural gap.
        // Callers that poll after sync returns still see Done once.
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
        let mut guard = self.lock_state()?;
        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        mweb::wipe_mweb_files(&state.data_dir)?;
        // A manual resync usually means something looked wrong, so re-crawl
        // rather than reusing peers that may be part of the problem.
        crate::discovery::clear_cache();
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        if let Some(scheme) = new_scheme {
            state.mweb_scheme = scheme;
            let mut meta = meta_from_state(state);
            meta.needs_mweb_scan = true;
            meta::write_meta(&state.data_dir, &meta)?;
        }
        state.mweb = Some(MwebRuntime::open(
            &state.data_dir,
            &secret,
            state.network,
            state.mweb_scheme.to_master_scheme(),
            self.secrets.sealing_key(),
        )?);
        state.needs_mweb_scan = true;
        let tip_height = state.wallet.latest_checkpoint().height();
        let tip_hash = state.wallet.latest_checkpoint().hash();
        if let Some(ref mut mweb) = state.mweb {
            self.set_sync_phase(SyncPhase::MwebDownload);
            diag::log("resync_mweb: mweb download starting");
            let peers = state.mweb_peers.clone();
            let network = state.network;
            // Fresh runtime after wipe: no previous sync state, so no extension hint.
            self.with_mweb_progress(|progress| {
                let _ =
                    mweb.sync_at_tip(tip_height, tip_hash, None, &peers, network, Some(progress));
            });
            mweb.persist(&state.data_dir)?;
        }
        self.abort_if_locked(&mut guard)?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        state.needs_mweb_scan = false;
        self.set_sync_phase(SyncPhase::Done);
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
        let mut guard = self.lock_state()?;
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

        let client = connect_electrum(state)?;
        client.transaction_broadcast(&tx).map_err(|e| {
            WalletError::Electrum(crate::error::humanize_broadcast_error(&e.to_string()))
        })?;

        // Keep local balance honest until the next sync sees the broadcast.
        state
            .wallet
            .apply_unconfirmed_txs([(tx.clone(), crate::mweb_history::now_ts())]);

        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;

        Ok(SendResult {
            txid: tx.compute_txid().to_string(),
            fee_sats,
        })
    }

    pub fn preview_pegin(&self, req: PeginRequest) -> Result<PeginPreview, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
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
        })
    }

    pub fn pegin(&self, req: PeginRequest) -> Result<PeginResult, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let req = resolve_pegin_request(state, req)?;
        let rpc_url = state.litecoin_rpc_url.clone();
        let peers = state.mweb_peers.clone();
        let network = state.network;
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let result = mweb::pegin(
            &mut state.wallet,
            &state.signer,
            mweb,
            rpc_url.as_deref(),
            &peers,
            req,
            network,
        )?;
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        mweb.persist(&state.data_dir)?;
        Ok(result)
    }

    pub fn preview_mweb_send(&self, req: MwebSendRequest) -> Result<MwebSendPreview, WalletError> {
        self.ensure_unlocked()?;
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
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let req = resolve_mweb_send_request(state, req)?;
        let rpc_url = state.litecoin_rpc_url.clone();
        let peers = state.mweb_peers.clone();
        let network = state.network;
        let data_dir = state.data_dir.clone();
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let result = mweb::mweb_send(
            &state.wallet,
            mweb,
            &data_dir,
            rpc_url.as_deref(),
            &peers,
            req,
            network,
        )?;
        mweb.persist(&data_dir)?;
        Ok(result)
    }

    pub fn preview_pegout(&self, req: PegoutRequest) -> Result<PegoutPreview, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (resolved, dust_sats) = resolve_pegout_request(state, req)?;
        pegout_preview_from_resolved(&resolved, dust_sats, state)
    }

    pub fn pegout(&self, req: PegoutRequest) -> Result<MwebBroadcastResult, WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let (mut req, _) = resolve_pegout_request(state, req)?;
        if req.per_coin {
            let n = req.output_amounts.len();
            if n == 0 {
                return Err(WalletError::BuildTx(
                    "per-coin peg-out needs at least one public output".into(),
                ));
            }
            let mut addresses = Vec::with_capacity(n);
            for _ in 0..n {
                addresses.push(
                    state
                        .wallet
                        .reveal_next_address(KeychainKind::External)
                        .to_string(),
                );
            }
            state
                .wallet
                .persist(&mut state.db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            req.addresses = addresses;
        } else if req.address.trim().is_empty() {
            return Err(WalletError::InvalidAddress(
                "peg-out destination address required".into(),
            ));
        }
        let rpc_url = state.litecoin_rpc_url.clone();
        let peers = state.mweb_peers.clone();
        let network = state.network;
        let data_dir = state.data_dir.clone();
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let result = mweb::pegout(
            &state.wallet,
            mweb,
            &data_dir,
            rpc_url.as_deref(),
            &peers,
            req,
            network,
        )?;
        mweb.persist(&data_dir)?;
        Ok(result)
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
    pub fn export_mweb_coinswapd_secrets(&self) -> Result<(String, String, String), WalletError> {
        self.ensure_unlocked()?;
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let mweb = state
            .mweb
            .as_mut()
            .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
        let scan = hex::encode(mweb.keys.scan.secret_bytes());
        let spend = hex::encode(mweb.keys.spend.secret_bytes());
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
        let mut guard = self.lock_state()?;
        let state = guard.as_mut().ok_or(WalletError::NotLoaded)?;
        let preview = plan_split_request(state, &req)?;
        match req.chain {
            SplitChain::Public => {
                let (psbt, fee_sats) = build_public_split_psbt(state, &req.input, &preview)?;
                let mut psbt = psbt;
                sign_and_finalize(&state.wallet, &state.signer, &mut psbt)?;
                let tx = psbt
                    .extract_tx()
                    .map_err(|e| WalletError::Sign(e.to_string()))?;
                let client = connect_electrum(state)?;
                client.transaction_broadcast(&tx).map_err(|e| {
                    WalletError::Electrum(crate::error::humanize_broadcast_error(&e.to_string()))
                })?;
                state
                    .wallet
                    .apply_unconfirmed_txs([(tx.clone(), crate::mweb_history::now_ts())]);
                state
                    .wallet
                    .persist(&mut state.db)
                    .map_err(|e| WalletError::Persist(e.to_string()))?;
                let txid = tx.compute_txid().to_string();
                split_ids::record_txid(&state.data_dir, &txid)?;
                Ok(SplitResult {
                    txid,
                    fee_sats,
                    output_count: preview.outputs.len() as u32,
                })
            }
            SplitChain::Private => {
                let recipients: Vec<u64> = preview
                    .outputs
                    .iter()
                    .filter(|o| !o.is_change)
                    .map(|o| o.amount_sats)
                    .collect();
                let rpc_url = state.litecoin_rpc_url.clone();
                let peers = state.mweb_peers.clone();
                let network = state.network;
                let data_dir = state.data_dir.clone();
                let mweb = state
                    .mweb
                    .as_mut()
                    .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
                let result = mweb::mweb_split(
                    &state.wallet,
                    mweb,
                    &data_dir,
                    rpc_url.as_deref(),
                    &peers,
                    &req.input,
                    &recipients,
                    preview.fee_sats,
                    network,
                )?;
                mweb.persist(&data_dir)?;
                Ok(result)
            }
        }
    }

    pub fn preview_churn(&self, req: ChurnRequest) -> Result<ChurnPreview, WalletError> {
        self.ensure_unlocked()?;
        let guard = self.lock_state()?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        let (info, frozen, job_active, from_pegin) = churn_start_facts(state, &req.output_id)?;
        let target = churn::check_start(&churn::StartCheck {
            mature: info.mature,
            frozen,
            amount_sats: info.amount,
            fee_sats: DEFAULT_MWEB_FEE_SATS,
            job_active,
            target_depth: req.target_depth,
        })?;
        let cover_min = churn::normalize_cover_min(req.cover_min)?;
        let _ = from_pegin;
        Ok(ChurnPreview {
            input_sats: info.amount,
            hop_fee_sats: DEFAULT_MWEB_FEE_SATS,
            resulting_sats: info.amount - DEFAULT_MWEB_FEE_SATS,
            target_depth: target,
            total_fee_sats: DEFAULT_MWEB_FEE_SATS.saturating_mul(target as u64),
            amount_note: CHURN_AMOUNT_NOTE.to_string(),
            quiet_block_note: crate::dto::quiet_block_note(target).to_string(),
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
        let (info, frozen, job_active, from_pegin) = churn_start_facts(state, &req.output_id)?;
        let target = churn::check_start(&churn::StartCheck {
            mature: info.mature,
            frozen,
            amount_sats: info.amount,
            fee_sats: DEFAULT_MWEB_FEE_SATS,
            job_active,
            target_depth: req.target_depth,
        })?;
        let cover_min = churn::normalize_cover_min(req.cover_min)?;
        let mut job = churn::new_job(
            &req.output_id,
            from_pegin || info.is_pegin,
            target,
            DEFAULT_MWEB_FEE_SATS,
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
        let mut guard = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(()),
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
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
        let mut job = churn::read_job(&state.data_dir)?
            .ok_or_else(|| WalletError::BuildTx("There is no self-spend to try again.".into()))?;
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
        let mut job = churn::read_job(&state.data_dir)?
            .ok_or_else(|| WalletError::BuildTx("There is no self-spend to cancel.".into()))?;
        let shown = job.current_output_id.clone();
        revert_unbroadcast_hop(state, &mut job)?;
        let restored = job.current_output_id.clone();
        churn::request_cancel(&mut job)?;
        churn::write_job(&state.data_dir, &job)?;
        let _ = churn::remove_armed(&state.data_dir);
        mweb_frozen::set_locked(&state.data_dir, &shown, false)?;
        if restored != shown {
            mweb_frozen::set_locked(&state.data_dir, &restored, false)?;
        }
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
            if self.secrets.get_mnemonic()?.is_none() && !self.secrets.is_locked() {
                self.wipe(data_dir)?;
            } else if self.secrets.is_locked() || self.secrets.get_mnemonic()?.is_some() {
                return Err(WalletError::AlreadyExists);
            } else {
                self.wipe(data_dir)?;
            }
        }

        self.secrets
            .set_with_passphrase(passphrase, &secret.to_stored())?;

        std::fs::create_dir_all(data_dir)?;

        let create_db =
            || -> Result<(PersistedWallet<Connection>, Connection, WalletMeta), WalletError> {
                let db_path = meta::db_path(data_dir);
                let mut db =
                    Connection::open(&db_path).map_err(|e| WalletError::Persist(e.to_string()))?;
                let params = create_params(secret, network)?;
                let mut wallet = PersistedWallet::create(&mut db, params)
                    .map_err(|e| WalletError::Persist(e.to_string()))?;

                let _ = wallet.next_unused_address(KeychainKind::External);
                wallet
                    .persist(&mut db)
                    .map_err(|e| WalletError::Persist(e.to_string()))?;

                let mut meta = WalletMeta::new(network, electrum_url.clone());
                meta.mweb_scheme = mweb_scheme;
                meta::write_meta(data_dir, &meta)?;
                Ok((wallet, db, meta))
            };

        let (wallet, db, meta) = match create_db() {
            Ok(v) => v,
            Err(e) => {
                let _ = meta::remove_wallet_files(data_dir);
                let _ = self.secrets.delete_mnemonic();
                return Err(e);
            }
        };

        let mweb = MwebRuntime::open(
            data_dir,
            secret,
            network,
            mweb_scheme.to_master_scheme(),
            self.secrets.sealing_key(),
        )
        .ok();

        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(secret, network)?,
            db,
            network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            mweb_peers: meta.mweb_peers,
            mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: data_dir.to_path_buf(),
            needs_full_scan: meta.needs_full_scan,
            needs_mweb_scan: meta.needs_mweb_scan,
            mweb,
        };
        let summary = build_summary(&mut state)?;
        self.publish_insights(&state);
        *self.lock_state()? = Some(state);
        Ok(summary)
    }

    fn ensure_unlocked(&self) -> Result<(), WalletError> {
        if self.secrets.is_locked() {
            Err(WalletError::Locked)
        } else {
            Ok(())
        }
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, Option<WalletState>>, WalletError> {
        self.state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))
    }
}

/// Test-only wallet app backed by an arbitrary [`SecretStore`] (typically [`crate::secrets::MemoryStore`]).
pub struct MemoryBackedApp {
    state: Mutex<Option<WalletState>>,
    secrets: Arc<dyn SecretStore>,
}

impl MemoryBackedApp {
    pub fn exists(&self, data_dir: &Path) -> bool {
        meta::wallet_files_exist(data_dir)
    }

    pub fn wipe(&self, data_dir: &Path) -> Result<(), WalletError> {
        *self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))? = None;
        self.secrets.delete_mnemonic()?;
        meta::remove_wallet_files(data_dir)?;
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
        Ok(CreateWalletResponse { mnemonic, summary })
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
            req.electrum_url,
            req.mweb_scheme,
        )
    }

    pub fn load(&self, data_dir: &Path) -> Result<WalletSummary, WalletError> {
        if !self.exists(data_dir) {
            return Err(WalletError::NotFound);
        }
        let meta = meta::read_meta(data_dir)?;
        let stored = self
            .secrets
            .get_mnemonic()?
            .ok_or(WalletError::MissingMnemonic)?;
        let secret = MasterSecret::from_stored(&stored)?;
        let mut db = Connection::open(meta::db_path(data_dir))
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = load_params(&secret, meta.network)?;
        let wallet = PersistedWallet::load(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?
            .ok_or(WalletError::NotFound)?;
        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(&secret, meta.network)?,
            db,
            network: meta.network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            mweb_peers: meta.mweb_peers,
            mweb_scheme: meta.mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: data_dir.to_path_buf(),
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
        let outpoint = parse_outpoint(&req.outpoint)?;
        if req.locked {
            state.wallet.lock_outpoint(outpoint);
        } else {
            state.wallet.unlock_outpoint(outpoint);
        }
        state
            .wallet
            .persist(&mut state.db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(())
    }

    pub fn set_mweb_utxo_locked(&self, req: SetMwebUtxoLockedRequest) -> Result<(), WalletError> {
        let guard = self
            .state
            .lock()
            .map_err(|_| WalletError::Persist("wallet state lock poisoned".into()))?;
        let state = guard.as_ref().ok_or(WalletError::NotLoaded)?;
        refuse_churn_unfreeze(&state.data_dir, &req.output_id, req.locked)?;
        mweb_frozen::set_locked(&state.data_dir, &req.output_id, req.locked)
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
        if stored.as_deref() != Some(payload.as_str()) {
            let _ = self.secrets.delete_mnemonic();
            return Err(WalletError::SecretStore(
                "secret store did not persist mnemonic".into(),
            ));
        }
        std::fs::create_dir_all(data_dir)?;
        let db_path = meta::db_path(data_dir);
        let mut db = Connection::open(&db_path).map_err(|e| WalletError::Persist(e.to_string()))?;
        let params = create_params(secret, network)?;
        let mut wallet = PersistedWallet::create(&mut db, params)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let _ = wallet.next_unused_address(KeychainKind::External);
        wallet
            .persist(&mut db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        let mut meta = WalletMeta::new(network, electrum_url);
        meta.mweb_scheme = mweb_scheme;
        meta::write_meta(data_dir, &meta)?;
        let mut state = WalletState {
            last_tip_height: wallet.latest_checkpoint().height(),
            tip_time: None,
            tip_time_height: 0,
            wallet,
            signer: signer(secret, network)?,
            db,
            network,
            electrum_url: meta.electrum_url,
            electrum_validate_domain: meta.electrum_validate_domain,
            electrum_use_public_fallback: meta.electrum_use_public_fallback,
            auto_lock_minutes: meta.auto_lock_minutes,
            active_electrum_url: None,
            litecoin_rpc_url: meta.litecoin_rpc_url,
            mweb_peers: meta.mweb_peers,
            mweb_scheme,
            explorer_base_url: meta.explorer_base_url,
            show_fiat: meta.show_fiat,
            use_explorer_fee_hints: meta.use_explorer_fee_hints,
            insights_enabled: meta.insights_enabled,
            data_dir: data_dir.to_path_buf(),
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

/// Estimated vbytes for a typical peg-in (1–2 inputs + HogEx output + change).
const PEGIN_FEE_VB_ESTIMATE: u64 = 250;

fn auto_mweb_fee(explicit: u64) -> u64 {
    if explicit == 0 {
        DEFAULT_MWEB_FEE_SATS
    } else {
        explicit
    }
}

fn auto_pegin_transparent_fee(state: &mut WalletState, explicit: u64) -> Result<u64, WalletError> {
    if explicit > 0 {
        return Ok(explicit);
    }
    let client = connect_electrum(state)?;
    let (rate, _) = electrum::estimate_fee_rate_sat_vb(&client)?;
    Ok(rate.saturating_mul(PEGIN_FEE_VB_ESTIMATE).max(500))
}

fn resolve_pegin_request(
    state: &mut WalletState,
    req: PeginRequest,
) -> Result<PeginRequest, WalletError> {
    let mweb_fee_sats = auto_mweb_fee(req.mweb_fee_sats);
    let transparent_fee_sats = auto_pegin_transparent_fee(state, req.transparent_fee_sats)?;
    let selected = req
        .selected_outpoints
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(parse_outpoint)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .filter(|v| !v.is_empty());

    let spendable = if let Some(ref outpoints) = selected {
        let mut sum = 0u64;
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
            sum = sum.saturating_add(utxo.txout.value.to_sat());
        }
        sum
    } else {
        state.wallet.balance().trusted_spendable().to_sat()
    };

    let amount_sats = if req.drain {
        // Drain of a manual selection empties those coins; otherwise the wallet.
        spendable.checked_sub(transparent_fee_sats).ok_or_else(|| {
            WalletError::BuildTx(format!(
                "not enough transparent funds to peg in after a ~{} litoshis miner fee",
                transparent_fee_sats
            ))
        })?
    } else {
        // The miner fee rides on top of the amount. Catch that here at preview
        // time, before BDK coin selection fails with a raw "BTC" error.
        let needed = req.amount_sats.saturating_add(transparent_fee_sats);
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
    let fee_sats = auto_mweb_fee(req.fee_sats);
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(&state.data_dir)?.ids;
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
        coins.iter().map(|c| c.amount).sum()
    } else {
        mweb::spendable_mweb_sats(mweb, tip, &frozen)
    };
    let amount_sats = if req.drain {
        spendable.checked_sub(fee_sats).ok_or_else(|| {
            WalletError::BuildTx(format!(
                "not enough private funds to send after a {} litoshis MWEB fee",
                fee_sats
            ))
        })?
    } else {
        req.amount_sats
    };
    if amount_sats == 0 {
        return Err(WalletError::BuildTx(
            "private send amount must be greater than zero".into(),
        ));
    }
    if amount_sats.saturating_add(fee_sats) > spendable {
        return Err(WalletError::BuildTx(format!(
            "need {} litoshis spendable private (amount + fee) but only {} available",
            amount_sats.saturating_add(fee_sats),
            spendable
        )));
    }
    // Validate address early so preview fails before confirm.
    let net = state.network.to_bitcoin_network();
    let _ = Address::from_str(&req.address)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .require_network(net)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
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
    let fee_sats = auto_mweb_fee(req.fee_sats);
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(&state.data_dir)?.ids;
    let selected = mweb::normalize_selected_ids(req.selected_output_ids.as_deref());
    let per_coin = req.drain || selected.is_some();
    let dust_sats = if !per_coin && !req.address.trim().is_empty() {
        let net = state.network.to_bitcoin_network();
        let dest = Address::from_str(&req.address)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .require_network(net)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
        let dust_relay = FeeRate::from_sat_per_vb(30)
            .ok_or_else(|| WalletError::BuildTx("internal dust fee rate".into()))?;
        dest.script_pubkey()
            .minimal_non_dust_custom(dust_relay)
            .to_sat()
    } else {
        mweb::p2wpkh_dust_sats()?
    };

    if per_coin {
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
        let coin_amounts: Vec<u64> = coins.iter().map(|c| c.amount).collect();
        let plan = mweb::plan_pegout_per_coin(&coin_amounts, fee_sats, dust_sats)?;
        let amount_sats = plan.amounts.iter().copied().sum();
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

    let spendable = mweb::spendable_mweb_sats(mweb, tip, &frozen);
    let amount_sats = req.amount_sats;
    if amount_sats < dust_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-out amount {} litoshis is below the dust limit ({} litoshis for this address)",
            amount_sats, dust_sats
        )));
    }
    if amount_sats.saturating_add(fee_sats) > spendable {
        return Err(WalletError::BuildTx(format!(
            "need {} litoshis spendable private (amount + fee) but only {} available",
            amount_sats.saturating_add(fee_sats),
            spendable
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

/// Build a send PSBT. Resolves fee rate from the request or Electrum.
/// Returns `(fee_rate_sat_vb, psbt, recipient_script)`.
fn build_send_psbt(
    state: &mut WalletState,
    req: &SendRequest,
) -> Result<(u64, Psbt, ScriptBuf), WalletError> {
    let network = state.network.to_bitcoin_network();
    let address = Address::from_str(&req.address)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .require_network(network)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

    let fee_rate_sat_vb = match req.fee_rate_sat_vb {
        Some(rate) if rate > 0 => rate,
        _ => {
            let client = connect_electrum(state)?;
            electrum::estimate_fee_rate_sat_vb(&client)?.0
        }
    };
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_vb).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "fee_rate_sat_vb must be non-zero (got {fee_rate_sat_vb})"
        ))
    })?;

    let dust_relay = FeeRate::from_sat_per_vb(30)
        .ok_or_else(|| WalletError::BuildTx("internal dust fee rate".into()))?;
    let recipient_script = address.script_pubkey();
    let min_non_dust = recipient_script.minimal_non_dust_custom(dust_relay);

    let selected = req
        .selected_outpoints
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(parse_outpoint)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .filter(|v| !v.is_empty());

    if let Some(ref outpoints) = selected {
        for op in outpoints {
            if state.wallet.get_utxo(*op).is_none() {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is not an unspent output in this wallet"
                )));
            }
            if state.wallet.is_outpoint_locked(*op) {
                return Err(WalletError::BuildTx(format!(
                    "selected outpoint {op} is frozen — unfreeze it before spending"
                )));
            }
        }
    }

    let mut tx_builder = state.wallet.build_tx();
    if let Some(ref outpoints) = selected {
        tx_builder
            .add_utxos(outpoints)
            .map_err(|e| WalletError::BuildTx(e.to_string()))?;
        tx_builder.manually_selected_only();
    }

    if req.drain {
        // With a manual selection, drain only those UTXOs (no drain_wallet).
        if selected.is_none() {
            tx_builder.drain_wallet();
        }
        tx_builder.drain_to(recipient_script.clone());
    } else {
        let amount = Amount::from_sat(req.amount_sats);
        if amount < min_non_dust {
            return Err(WalletError::BuildTx(format!(
                "amount {} litoshis is below the network dust limit ({} litoshis for this address)",
                req.amount_sats,
                min_non_dust.to_sat()
            )));
        }
        tx_builder.add_recipient(recipient_script.clone(), amount);
    }
    tx_builder.fee_rate(fee_rate);
    let psbt = tx_builder.finish().map_err(|e| {
        let msg = e.to_string();
        if msg.to_lowercase().contains("dust") {
            WalletError::BuildTx(format!(
                "output below dust limit ({} litoshis for this address): {msg}",
                min_non_dust.to_sat()
            ))
        } else {
            WalletError::BuildTx(msg)
        }
    })?;
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
    let tip = state.wallet.local_chain().tip().height();
    let confirmations = match utxo.chain_position {
        ChainPosition::Confirmed { anchor, .. } => {
            tip.saturating_sub(anchor.block_id.height).saturating_add(1)
        }
        ChainPosition::Unconfirmed { .. } => 0,
    };
    if confirmations == 0 {
        return Err(WalletError::BuildTx(
            "Split is disabled until the coin is confirmed".into(),
        ));
    }
    Ok((op, utxo.txout.value.to_sat()))
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
                mweb_fee: DEFAULT_MWEB_FEE_SATS,
            })
        }
        SplitChain::Private => {
            let mweb = state
                .mweb
                .as_ref()
                .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
            let tip = state.wallet.latest_checkpoint().height();
            let frozen = mweb_frozen::read_ids(&state.data_dir)?.ids;
            let coin = mweb::select_split_coin(mweb.store.db(), &req.input, tip, &frozen)?;
            split::plan_split(&PlanParams {
                input_sats: coin.amount,
                equal_count: req.equal_count,
                amounts: req.amounts.clone(),
                fee_sats: req.fee_sats,
                fee_rate_sat_vb: 0,
                public: false,
                mweb_fee: auto_mweb_fee(req.fee_sats),
            })
        }
    }
}

/// Build a 1-in-N-out PSBT. Reveals N receive addresses and persists before return.
fn build_public_split_psbt(
    state: &mut WalletState,
    input: &str,
    preview: &SplitPreview,
) -> Result<(Psbt, u64), WalletError> {
    let (op, _input_sats) = public_split_utxo(state, input)?;
    let dust_relay = FeeRate::from_sat_per_vb(30)
        .ok_or_else(|| WalletError::BuildTx("internal dust fee rate".into()))?;

    let recipients: Vec<(ScriptBuf, Amount)> = preview
        .outputs
        .iter()
        .filter(|o| !o.is_change)
        .map(|o| {
            let addr = state.wallet.reveal_next_address(KeychainKind::External);
            let script = addr.script_pubkey();
            let min_non_dust = script.minimal_non_dust_custom(dust_relay);
            let amount = Amount::from_sat(o.amount_sats);
            if amount < min_non_dust {
                return Err(WalletError::BuildTx(format!(
                    "Output of {} litoshis is below the network dust limit ({} litoshis).",
                    o.amount_sats,
                    min_non_dust.to_sat()
                )));
            }
            Ok((script, amount))
        })
        .collect::<Result<Vec<_>, _>>()?;

    state
        .wallet
        .persist(&mut state.db)
        .map_err(|e| WalletError::Persist(e.to_string()))?;

    let mut tx_builder = state.wallet.build_tx();
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
    let fee_sats = psbt
        .fee_amount()
        .ok_or_else(|| WalletError::BuildTx("unable to compute fee".into()))?
        .to_sat();
    if fee_sats != preview.fee_sats {
        return Err(WalletError::BuildTx(format!(
            "built fee ({fee_sats} litoshis) does not match preview ({} litoshis)",
            preview.fee_sats
        )));
    }
    Ok((psbt, fee_sats))
}

/// Manual peg-in coin selection leaves transparent change when inputs exceed amount+fee.
fn pegin_selection_creates_change(
    state: &WalletState,
    resolved: &PeginRequest,
    total_from_transparent_sats: u64,
) -> bool {
    let Some(ops) = resolved.selected_outpoints.as_ref() else {
        return false;
    };
    let mut sum = 0u64;
    for raw in ops {
        let Ok(op) = parse_outpoint(raw) else {
            continue;
        };
        if let Some(utxo) = state.wallet.get_utxo(op) {
            sum = sum.saturating_add(utxo.txout.value.to_sat());
        }
    }
    sum > total_from_transparent_sats
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
    )
}

fn pegout_selection_creates_change(
    state: &WalletState,
    req: &PegoutRequest,
) -> Result<bool, WalletError> {
    mweb_inputs_exceed_needed(
        state,
        req.selected_output_ids.as_deref(),
        req.amount_sats,
        req.fee_sats,
        "swapping",
    )
}

fn mweb_inputs_exceed_needed(
    state: &WalletState,
    selected: Option<&[String]>,
    amount_sats: u64,
    fee_sats: u64,
    action: &str,
) -> Result<bool, WalletError> {
    let mweb = state
        .mweb
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
    let tip = state.wallet.latest_checkpoint().height();
    let frozen = mweb_frozen::read_ids(&state.data_dir)?.ids;
    let needed = amount_sats.saturating_add(fee_sats);
    let coins = mweb::resolve_spend_coins(mweb.store.db(), tip, &frozen, selected, needed, action)?;
    let sum: u64 = coins.iter().map(|c| c.amount).sum();
    Ok(sum > needed)
}

fn collect_unspent(state: &WalletState) -> Vec<UtxoRecord> {
    let tip = state.wallet.local_chain().tip().height();
    let labels = utxo_labels::read_labels(&state.data_dir)
        .map(|f| f.labels)
        .unwrap_or_default();
    let mut rows: Vec<UtxoRecord> = state
        .wallet
        .list_unspent()
        .map(|utxo| {
            let confirmations = match utxo.chain_position {
                ChainPosition::Confirmed { anchor, .. } => {
                    tip.saturating_sub(anchor.block_id.height).saturating_add(1)
                }
                ChainPosition::Unconfirmed { .. } => 0,
            };
            let keychain = match utxo.keychain {
                KeychainKind::External => "external",
                KeychainKind::Internal => "internal",
            };
            let outpoint = utxo.outpoint.to_string();
            let label = labels.get(&outpoint).cloned().unwrap_or_default();
            UtxoRecord {
                outpoint,
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount_sats: utxo.txout.value.to_sat(),
                keychain: keychain.into(),
                confirmations,
                locked: state.wallet.is_outpoint_locked(utxo.outpoint),
                label,
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
fn repair_missing_pegin_spends(
    state: &mut WalletState,
    client: &crate::electrum::ElectrumClient,
) -> Result<Option<String>, WalletError> {
    let Some(mweb) = state.mweb.as_ref() else {
        return Ok(None);
    };
    let missing: Vec<String> = mweb
        .history
        .entries
        .iter()
        .filter(|e| e.kind == TxKind::Pegin)
        .filter_map(|e| {
            let txid = parse_txid(&e.id)?;
            if state.wallet.get_tx(txid).is_some() {
                None
            } else {
                Some(e.id.clone())
            }
        })
        .collect();
    if missing.is_empty() {
        return Ok(None);
    }

    let mut repaired = 0u32;
    let mut still_missing = 0u32;
    let mut last_err: Option<String> = None;
    for id in &missing {
        match fetch_pegin_raw_tx(id, client, state) {
            Ok(bytes) => match deserialize::<bdk_wallet::bitcoin::Transaction>(&bytes) {
                Ok(tx) => {
                    mweb::apply_pegin_transparent_spend(&mut state.wallet, tx);
                    repaired += 1;
                }
                Err(e) => {
                    last_err = Some(format!("decode {id}: {e}"));
                    still_missing += 1;
                }
            },
            Err(e) => {
                last_err = Some(e);
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

/// Fetch peg-in raw tx bytes. Electrum often omits MWEB peg-ins, so we also try
/// configured RPC, a stock local litecoind, other Electrum servers, and (mainnet)
/// a public explorer hex endpoint.
fn fetch_pegin_raw_tx(
    txid_hex: &str,
    client: &crate::electrum::ElectrumClient,
    state: &WalletState,
) -> Result<Vec<u8>, String> {
    use bdk_electrum::electrum_client::ElectrumApi;

    let mut errors: Vec<String> = Vec::new();
    let txid = parse_txid(txid_hex).ok_or_else(|| format!("invalid peg-in txid {txid_hex}"))?;

    match client.inner.transaction_get_raw(&txid) {
        Ok(raw) if !raw.is_empty() => return Ok(raw),
        Ok(_) => errors.push("sync Electrum returned empty tx".into()),
        Err(e) => errors.push(format!("sync Electrum: {e}")),
    }

    let mut rpc_urls: Vec<String> = Vec::new();
    if let Some(url) = &state.litecoin_rpc_url {
        rpc_urls.push(url.clone());
    }
    let local = state.network.default_rpc_url().to_string();
    if !rpc_urls.iter().any(|u| u == &local) {
        rpc_urls.push(local);
    }
    for url in &rpc_urls {
        match crate::rpc::get_raw_transaction_hex(url, txid_hex) {
            Ok(hex) => match hex::decode(hex.trim()) {
                Ok(raw) if !raw.is_empty() => return Ok(raw),
                Ok(_) => errors.push(format!("RPC {url}: empty hex")),
                Err(e) => errors.push(format!("RPC {url}: bad hex ({e})")),
            },
            Err(e) => errors.push(format!("RPC {url}: {e}")),
        }
    }

    // Other Electrum servers may still hold the raw bytes even when the sync
    // server refuses MWEB txs.
    for url in electrum_candidates(state) {
        if state.active_electrum_url.as_deref() == Some(url.as_str()) {
            continue;
        }
        match electrum::connect_with_timeout(&url, state.electrum_validate_domain, 10) {
            Ok(alt) => match alt.inner.transaction_get_raw(&txid) {
                Ok(raw) if !raw.is_empty() => return Ok(raw),
                Ok(_) => errors.push(format!("{url}: empty tx")),
                Err(e) => errors.push(format!("{url}: {e}")),
            },
            Err(e) => errors.push(format!("{url}: {e}")),
        }
    }

    if state.network == WalletNetwork::Mainnet {
        match fetch_tx_hex_litecoinspace(txid_hex) {
            Ok(raw) => return Ok(raw),
            Err(e) => errors.push(format!("litecoinspace: {e}")),
        }
    }

    Err(errors.join("; "))
}

fn fetch_tx_hex_litecoinspace(txid_hex: &str) -> Result<Vec<u8>, String> {
    let url = format!("https://litecoinspace.org/api/tx/{txid_hex}/hex");
    let body = ureq::get(&url)
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

fn hash_at(
    wallet: &PersistedWallet<Connection>,
    height: u32,
) -> Option<bdk_wallet::bitcoin::BlockHash> {
    if wallet.latest_checkpoint().height() == height {
        return Some(wallet.latest_checkpoint().hash());
    }
    wallet.local_chain().get(height).map(|cp| cp.hash())
}

fn block_hash_at(
    wallet: &PersistedWallet<Connection>,
    electrum: Option<&electrum::ElectrumClient>,
    height: u32,
) -> Option<bdk_wallet::bitcoin::BlockHash> {
    if let Some(hash) = hash_at(wallet, height) {
        return Some(hash);
    }
    let header = electrum?.inner.block_header(height as usize).ok()?;
    Some(header.block_hash())
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
        let fetched = block_hash_at(self.wallet, self.electrum, height)
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
        if let Some(hash) = block_hash_at(&state.wallet, electrum, *height) {
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
    let frozen = mweb_frozen::read_ids(&state.data_dir)?.ids.contains(&id);
    let job_active = churn::read_job(&state.data_dir)?.is_some_and(|job| job.phase.is_active());
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
        created_coin: serde_json::to_value(&hop.created).ok(),
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
    let mut frozen = mweb_frozen::read_ids(&state.data_dir)?.ids;
    if let Ok(id) = mweb_frozen::normalize_output_id(output_id) {
        frozen.remove(&id);
    }
    mweb::select_mweb_coin(mweb.store.db(), output_id, tip, &frozen, "spending to self")
}

/// Sign the whole chain, apply only the first hop to the coin set, and arm it.
fn prepare_churn(state: &mut WalletState, job: &mut churn::ChurnJob) -> Result<(), WalletError> {
    let coin = select_churn_coin(state, &job.current_output_id)?;
    let spent_id = hex::encode(coin.output_id);
    let network = state.network;
    let data_dir = state.data_dir.clone();
    let fee = job.fee_sats;
    let from_pegin = job.from_pegin;
    let hops = job.target_depth;
    let tip = state.wallet.latest_checkpoint().height();
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
    mweb::apply_prepared_output(
        mweb,
        &first.wtxid,
        &first.spent_output_id,
        first.created.clone(),
        first.fee_sats,
    )?;
    mweb.persist(&data_dir)?;
    mweb_frozen::set_locked(&data_dir, &spent_id, true)?;
    mweb_frozen::set_locked(&data_dir, &first.created_output_id, true)?;
    churn::inherit_depth(&data_dir, &spent_id, &first.created_output_id, from_pegin)?;
    let _ = utxo_labels::move_label(&data_dir, &spent_id, &first.created_output_id);
    let armed_hops: Vec<churn::ArmedHop> = prepared
        .iter()
        .enumerate()
        .map(|(i, hop)| hop_from_prepared(hop, i == 0))
        .collect();
    let own_ids = churn::snapshot_own_ids(unconfirmed_history_ids(state), &armed_hops);
    let armed = churn::ArmedRecord {
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
    job.current_output_id = first.created_output_id.clone();
    job.created_output_id = Some(first.created_output_id);
    churn::mark_waiting_for_cover(job);
    churn::write_armed(&data_dir, &armed)?;
    churn::write_job(&data_dir, job)?;
    Ok(())
}

/// One new signature after a solo pause, a missed block, or an expiry.
fn resign_one_hop(state: &mut WalletState, job: &mut churn::ChurnJob) -> Result<(), WalletError> {
    let coin = select_churn_coin(state, &job.current_output_id)?;
    let spent_id = hex::encode(coin.output_id);
    let network = state.network;
    let data_dir = state.data_dir.clone();
    let fee = job.fee_sats;
    let from_pegin = job.from_pegin;
    let tip = state.wallet.latest_checkpoint().height();
    let cover_min = job.cover_min;
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
    mweb::apply_prepared_output(
        mweb,
        &hop.wtxid,
        &hop.spent_output_id,
        hop.created.clone(),
        hop.fee_sats,
    )?;
    mweb.persist(&data_dir)?;
    mweb_frozen::set_locked(&data_dir, &spent_id, true)?;
    mweb_frozen::set_locked(&data_dir, &hop.created_output_id, true)?;
    churn::inherit_depth(&data_dir, &spent_id, &hop.created_output_id, from_pegin)?;
    let _ = utxo_labels::move_label(&data_dir, &spent_id, &hop.created_output_id);
    let armed_hop = hop_from_prepared(&hop, true);
    let own_ids = churn::snapshot_own_ids(
        unconfirmed_history_ids(state),
        std::slice::from_ref(&armed_hop),
    );
    let armed = churn::ArmedRecord {
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
    job.current_output_id = hop.created_output_id.clone();
    job.created_output_id = Some(hop.created_output_id);
    churn::mark_waiting_for_cover(job);
    churn::write_armed(&data_dir, &armed)?;
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
    let from_pegin = job.from_pegin;
    let data_dir = state.data_dir.clone();
    let restored = state.mweb.as_mut().and_then(|mweb| {
        let restored = mweb::recall_unlanded_spend(&mut mweb.history, mweb.store.db_mut(), &wtxid);
        if restored.is_some() {
            let _ = mweb.persist(&data_dir);
        }
        restored
    });
    if let Some(restored) = restored {
        let _ = churn::inherit_depth(&data_dir, &phantom, &restored, from_pegin);
        let _ = utxo_labels::move_label(&data_dir, &phantom, &restored);
        let _ = mweb_frozen::set_locked(&data_dir, &phantom, false);
        let _ = mweb_frozen::set_locked(&data_dir, &restored, true);
        job.current_output_id = restored;
        job.created_output_id = None;
    }
    Ok(())
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
    let Some(coin_json) = hop.created_coin.clone() else {
        return Ok(());
    };
    let wtxid = hop.wtxid.clone();
    let spent = hop.spent_output_id.clone();
    let created_id = hop.created_output_id.clone();
    let fee = hop.fee_sats;
    let from_pegin = churn::read_job(&state.data_dir)?
        .map(|job| job.from_pegin)
        .unwrap_or(false);
    let created = mweb::coin_from_value(&coin_json)?;
    let data_dir = state.data_dir.clone();
    let mweb = state
        .mweb
        .as_mut()
        .ok_or_else(|| WalletError::Mweb("MWEB runtime not initialized".into()))?;
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
    let revert = record
        .current()
        .is_some_and(|hop| hop.local_applied && !hop.broadcast);
    churn::wipe_raw_tail(record);
    job.needs_resign = true;
    job.last_error = Some(churn::EXPIRED_SPEND.into());
    job.cover_hold = None;
    job.phase = ChurnPhase::WaitingForCover;
    if revert {
        if let Some(state) = state {
            revert_unbroadcast_hop(state, job)?;
            let _ = churn::remove_armed(&state.data_dir);
            churn::write_job(&state.data_dir, job)?;
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
    if let Some(hop) = record.current() {
        if hop.local_applied && !hop.broadcast {
            let wtxid = hop.wtxid.clone();
            let created = hop.created_output_id.clone();
            if let Some(mweb) = state.mweb.as_mut() {
                mweb::drop_unbroadcast_output(mweb, &wtxid, &created);
                let _ = mweb.persist(&state.data_dir);
            }
        }
    }
    churn::wipe_raw_tail(record);
    job.needs_resign = false;
    job.last_error = Some(churn::FOREIGN_SPEND.into());
    job.cover_hold = None;
    job.phase = ChurnPhase::WaitingForCover;
    churn::write_armed(&state.data_dir, record)?;
    churn::write_job(&state.data_dir, job)?;
    Ok(())
}

fn send_armed_hop(
    state: Option<&mut WalletState>,
    data_dir: &Path,
    job: &mut churn::ChurnJob,
    record: &mut churn::ArmedRecord,
    rpc_url: Option<&str>,
    peers: &[String],
    network: crate::network::WalletNetwork,
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
    let local_applied = hop.local_applied;
    match mweb::broadcast_prepared_raw(&raw, rpc_url, peers, network) {
        Ok(()) => {
            churn::note_broadcast(job, &wtxid, &created, height)?;
            if let Some(hop) = record.current_mut() {
                hop.broadcast = true;
            }
            record.own_ids.insert(wtxid);
            record.own_ids.insert(txid);
            record.send_after = None;
            churn::write_job(data_dir, job)?;
            churn::write_armed(data_dir, record)?;
            if !local_applied {
                if let Some(state) = state {
                    let _ = apply_pending_local(state);
                }
            }
            Ok(())
        }
        Err(e) => {
            churn::note_broadcast_error(job, e.to_string());
            churn::write_job(data_dir, job)?;
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
        if job.phase == ChurnPhase::WaitingForCover {
            churn::finish_chain(job);
            mweb_frozen::set_locked(&data_dir, &job.current_output_id, false)?;
            churn::write_job(&data_dir, job)?;
        }
        return Ok(());
    };
    let tip = state.wallet.latest_checkpoint().height();
    match churn::follow_score(job.phase, record.hops_remaining()) {
        churn::ScoreFollow::Stay => {
            if job.phase == ChurnPhase::Done {
                let _ = churn::remove_armed(&data_dir);
            }
        }
        churn::ScoreFollow::ArmNext => {
            if churn::arm_next(&mut record, churn::unix_now(), tip) {
                churn::mark_waiting_for_cover(job);
                churn::write_armed(&data_dir, &record)?;
                churn::write_job(&data_dir, job)?;
            }
        }
        churn::ScoreFollow::FinishShort => {
            churn::finish_chain(job);
            mweb_frozen::set_locked(&data_dir, &job.current_output_id, false)?;
            let _ = churn::remove_armed(&data_dir);
            churn::write_job(&data_dir, job)?;
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

    let (rpc_url, peers, network, wallet_tip) = match state.as_ref() {
        Some(loaded) => (
            loaded.litecoin_rpc_url.clone(),
            loaded.mweb_peers.clone(),
            loaded.network,
            Some(loaded.wallet.latest_checkpoint().height()),
        ),
        None => {
            let meta = meta::read_meta(data_dir)?;
            (meta.litecoin_rpc_url, meta.mweb_peers, meta.network, None)
        }
    };
    let tip = match wallet_tip {
        Some(height) => Some(height),
        None => rpc_url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
            .and_then(|url| crate::rpc::get_block_count(url).ok()),
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
    let read = match mweb::count_foreign_mweb_mempool(url, &record.own_ids) {
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
            let _ = send_armed_hop(
                state,
                data_dir,
                &mut job,
                &mut record,
                Some(url),
                &peers,
                network,
                height,
            );
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
    let _ = undo_expired_local(state);
    let _ = apply_pending_local(state);
    let Some(mut job) = churn::read_job(&state.data_dir)? else {
        return Ok(());
    };
    if matches!(
        job.phase,
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
                    if job.phase == ChurnPhase::Done {
                        mweb_frozen::set_locked(&state.data_dir, &output_id, false)?;
                    }
                    churn::write_job(&state.data_dir, &job)?;
                }
            }
            ResolvedHop::NotIncluded => {
                let phantom = output_id;
                let from_pegin = job.from_pegin;
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
                    let _ = churn::inherit_depth(&state.data_dir, &phantom, &restored, from_pegin);
                    let _ = utxo_labels::move_label(&state.data_dir, &phantom, &restored);
                    let _ = mweb_frozen::set_locked(&state.data_dir, &phantom, false);
                    let _ = mweb_frozen::set_locked(&state.data_dir, &restored, true);
                    churn::note_not_included(&mut job, &restored)?;
                    let _ = churn::remove_armed(&state.data_dir);
                    churn::write_job(&state.data_dir, &job)?;
                }
            }
            ResolvedHop::NotYet if job.phase == ChurnPhase::PausedUnscored => {
                job.phase = ChurnPhase::WaitingConfirm;
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
        records.push(TxRecord {
            txid: entry.id.clone(),
            net_sats: entry.net_sats,
            sent_sats: (-entry.net_sats).max(0) as u64,
            received_sats: entry.net_sats.max(0) as u64,
            fee_sats: entry.fee_sats,
            height,
            confirmations,
            timestamp: Some(entry.timestamp),
            kind: entry.kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }];
        merge_mweb_history(&mut records, &mweb, 100);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind, TxKind::Pegin);
        assert_eq!(records[0].fee_sats, Some(51_000));
        assert_eq!(records[0].height, Some(90));
        assert_eq!(records[0].confirmations, 11);
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
        job.phase = ChurnPhase::WaitingForCover;
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
                created_coin: None,
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
        assert_eq!(job.phase, ChurnPhase::WaitingForCover);
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

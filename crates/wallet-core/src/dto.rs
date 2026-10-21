use serde::{Deserialize, Serialize};

use crate::network::WalletNetwork;

/// Request to create a new wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletRequest {
    pub network: WalletNetwork,
    /// Optional Electrum URL; defaults from the selected network when omitted.
    #[serde(default)]
    pub electrum_url: Option<String>,
}

/// Response from wallet creation. The mnemonic is returned once for backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWalletResponse {
    pub mnemonic: String,
    pub summary: WalletSummary,
}

/// Request to restore a wallet from an existing seed: a BIP39 mnemonic, an
/// aezeed mnemonic (Nexus), or a root extended private key (xprv/zprv/Ltpv).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreWalletRequest {
    /// Seed input; the kind is auto-detected. Named `mnemonic` for backward
    /// compatibility with existing callers.
    pub mnemonic: String,
    pub network: WalletNetwork,
    #[serde(default)]
    pub electrum_url: Option<String>,
    /// MWEB key-derivation scheme to restore under.
    #[serde(default)]
    pub mweb_scheme: MwebScheme,
    /// aezeed cipher-seed passphrase, when the seed is aezeed and one was set.
    #[serde(default)]
    pub aezeed_passphrase: Option<String>,
}

/// Which BIP32 layout derives the MWEB scan/spend keys.
///
/// Litecoin Core implements scan `m/0'/100'/0'` and spend `m/0'/100'/1'`.
/// The LIP-0004 draft was written before that implementation and still says
/// `m/1/0/{100',101'}`; [`Self::Lip0004`] follows the implemented path, same
/// as [`Self::LitecoinCore`]. [`Self::Mwebd`] is the pre-migration path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MwebScheme {
    /// Litecoin Core and current LIP-0004: `m/0'/100'/{0,1}'`.
    #[default]
    LitecoinCore,
    /// LIP-0004 updated to the implemented Core path: `m/0'/100'/{0,1}'`.
    Lip0004,
    /// Legacy mwebd, and Nexus before 2026-06-01: `m/1000'/2'/0'/{0,1}'`.
    Mwebd,
}

impl MwebScheme {
    pub(crate) fn to_master_scheme(self) -> bdk_mweb::keys::MasterKeyScheme {
        match self {
            // LIP-0004's written path predates Core's LoadMWEBKeychain.
            Self::LitecoinCore | Self::Lip0004 => bdk_mweb::keys::MasterKeyScheme::LitecoinCore,
            Self::Mwebd => bdk_mweb::keys::MasterKeyScheme::Mwebd,
        }
    }
}

/// Snapshot of wallet balances and tip (amounts in litoshis).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletSummary {
    pub network: WalletNetwork,
    pub confirmed_sats: u64,
    pub trusted_pending_sats: u64,
    pub untrusted_pending_sats: u64,
    pub immature_sats: u64,
    pub total_sats: u64,
    pub tip_height: u32,
    /// Unix seconds of the tip block header, when this session has read it
    /// for [`Self::tip_height`]. Absent until the first successful header read.
    #[serde(default)]
    pub tip_time: Option<u64>,
    pub receive_address: String,
}

/// Result of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub summary: WalletSummary,
    pub new_txs: u32,
    /// Wall-clock time in the Electrum phase.
    pub electrum_ms: u64,
    /// Wall-clock time in the MWEB phase; 0 when MWEB is not active.
    pub mweb_ms: u64,
    /// Electrum server that served this sync.
    #[serde(default)]
    pub electrum_server: String,
    /// Cross-check / trust warnings the user should see (empty when all clear).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Request to send litecoin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendRequest {
    pub address: String,
    /// Ignored when [`Self::drain`] is true.
    #[serde(default)]
    pub amount_sats: u64,
    /// Fee rate in sat/vB. When omitted or zero, the wallet estimates from Electrum.
    #[serde(default)]
    pub fee_rate_sat_vb: Option<u64>,
    /// When true, send the maximum from the spendable set (wallet-wide, or
    /// [`Self::selected_outpoints`] when that is non-empty), minus fees.
    #[serde(default)]
    pub drain: bool,
    /// When non-empty, spend only these transparent outpoints (`txid:vout`).
    /// Combined with [`Self::drain`], empties the selected coins (minus fees).
    #[serde(default)]
    pub selected_outpoints: Option<Vec<String>>,
}

/// One spendable transparent UTXO for coin control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoRecord {
    /// `txid:vout`
    pub outpoint: String,
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// `external` (receive) or `internal` (change).
    pub keychain: String,
    pub confirmations: u32,
    /// Frozen coins are skipped by automatic coin selection.
    pub locked: bool,
    /// Optional local note (non-secret sidecar).
    #[serde(default)]
    pub label: String,
}

/// Freeze or unfreeze a transparent UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetUtxoLockedRequest {
    /// `txid:vout`
    pub outpoint: String,
    pub locked: bool,
}

/// Freeze or unfreeze a private (MWEB) coin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMwebUtxoLockedRequest {
    /// 32-byte output id hex.
    pub output_id: String,
    pub locked: bool,
}

/// Set or clear a local UTXO label (`txid:vout`). Empty label deletes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetUtxoLabelRequest {
    pub outpoint: String,
    pub label: String,
}

/// Result of a broadcast send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub txid: String,
    pub fee_sats: u64,
}

/// Dry-run of a send: absolute fee and recipient amount before broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreview {
    /// Amount that will arrive at the recipient (for drain: total − fee).
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: u64,
    /// True when the built transaction creates a change output (privacy merge risk).
    #[serde(default)]
    pub creates_change: bool,
}

/// Network fee-rate estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub fee_rate_sat_vb: u64,
    /// True when Electrum had no estimate and the floor rate was used.
    pub is_fallback: bool,
}

/// What a history record represents, so the UI can label it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TxKind {
    /// Plain transparent transaction.
    #[default]
    Transparent,
    Pegin,
    Pegout,
    MwebSend,
    MwebReceive,
    /// Transparent 1-in-N-out self-split.
    Split,
    /// MWEB 1-in-N-out self-split.
    MwebSplit,
    /// MWEB 1-in-1 self-spend (churn hop). The history amount is the fee.
    MwebChurn,
}

/// A wallet-relevant transaction for history UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxRecord {
    /// Transparent txid; wtxid or output id for MWEB-only records.
    pub txid: String,
    /// Net change for the wallet (received − sent); negative for outgoing.
    pub net_sats: i64,
    pub sent_sats: u64,
    pub received_sats: u64,
    /// Fee when computable (outgoing); `None` for incoming txs with foreign inputs.
    pub fee_sats: Option<u64>,
    /// Confirmation height when confirmed.
    pub height: Option<u32>,
    /// Confirmations relative to tip; `0` when unconfirmed.
    pub confirmations: u32,
    /// Confirmation timestamp (unix seconds) when known.
    pub timestamp: Option<u64>,
    /// Kind of activity (transparent, peg-in, peg-out, MWEB send/receive/split).
    #[serde(default)]
    pub kind: TxKind,
}

/// Request to unlock an encrypted wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockRequest {
    pub passphrase: String,
}

/// Request to re-reveal the stored recovery secret after passphrase confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealMnemonicRequest {
    pub passphrase: String,
}

/// Recovery material for display after a successful [`RevealMnemonicRequest`].
///
/// Storage tags (`aezeed:`, `xprv:`, …) are stripped. An aezeed cipher-seed
/// passphrase is returned separately when one was stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealMnemonicResponse {
    /// Human-readable kind (`BIP39 mnemonic`, `aezeed seed`, `extended private key`).
    pub kind: String,
    /// Words or extended private key string suitable for backup / restore.
    pub phrase: String,
    /// Present when the seed is aezeed and was stored with a non-default cipher passphrase.
    #[serde(default)]
    pub aezeed_passphrase: Option<String>,
}

/// Request to migrate a plaintext mnemonic to an encrypted store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrateEncryptRequest {
    pub passphrase: String,
}

fn default_true() -> bool {
    true
}

fn default_auto_lock_minutes() -> u32 {
    15
}

fn default_explorer_base_url() -> String {
    crate::explorer::DEFAULT_EXPLORER_BASE_URL.to_string()
}

/// Electrum / peer / explorer settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSettings {
    pub electrum_url: String,
    /// Verify TLS certificates on ssl:// Electrum servers (default true).
    #[serde(default = "default_true")]
    pub electrum_validate_domain: bool,
    /// Fall back to built-in public Electrum servers when the configured one
    /// is down (default true). Disable to keep addresses off public servers.
    #[serde(default = "default_true")]
    pub electrum_use_public_fallback: bool,
    /// Lock the wallet after this many idle minutes (0 = never).
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
    /// Server the current session last connected to (read-only, may be a fallback).
    #[serde(default)]
    pub electrum_active_url: Option<String>,
    #[serde(default)]
    pub litecoin_rpc_url: Option<String>,
    #[serde(default)]
    pub mweb_peers: Vec<String>,
    /// Active MWEB key-derivation scheme (changing it requires an MWEB resync).
    #[serde(default)]
    pub mweb_scheme: MwebScheme,
    /// Block explorer base URL (litview / self-hosted LRK).
    #[serde(default = "default_explorer_base_url")]
    pub explorer_base_url: String,
    /// Show LTC/USD under the balance hero (fetched from the explorer API).
    #[serde(default = "default_true")]
    pub show_fiat: bool,
    /// Show explorer fee-rate suggestion chips on the send form.
    #[serde(default = "default_true")]
    pub use_explorer_fee_hints: bool,
    /// Show Insights nav / Balance network pulse (litview metrics).
    #[serde(default = "default_true")]
    pub insights_enabled: bool,
}

/// Request to update wallet settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsRequest {
    pub electrum_url: String,
    /// Verify TLS certificates on ssl:// Electrum servers (default true).
    #[serde(default = "default_true")]
    pub electrum_validate_domain: bool,
    /// Fall back to built-in public Electrum servers when the configured one
    /// is down (default true).
    #[serde(default = "default_true")]
    pub electrum_use_public_fallback: bool,
    /// Lock the wallet after this many idle minutes (0 = never).
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
    #[serde(default)]
    pub litecoin_rpc_url: Option<String>,
    #[serde(default)]
    pub mweb_peers: Vec<String>,
    #[serde(default = "default_explorer_base_url")]
    pub explorer_base_url: String,
    #[serde(default = "default_true")]
    pub show_fiat: bool,
    #[serde(default = "default_true")]
    pub use_explorer_fee_hints: bool,
    #[serde(default = "default_true")]
    pub insights_enabled: bool,
}

/// Aggregate litview network snapshot for Balance pulse / Insights header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPulse {
    pub tip_height: u32,
    pub price_usd: f64,
    pub price_change_pct: Option<f64>,
    pub fastest_fee_sat_vb: u64,
    pub half_hour_fee_sat_vb: u64,
    pub mempool_tx_count: u64,
    pub mempool_vsize: u64,
    pub fetched_at_unix: u64,
}

/// One allowlisted litview time series for Insights charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSeries {
    pub id: String,
    pub title: String,
    pub unit: String,
    pub index: String,
    pub values: Vec<f64>,
    pub latest: Option<f64>,
    pub change_pct: Option<f64>,
    /// Path under the explorer base URL (e.g. `/explore`).
    pub litview_path: String,
}

/// Whether a destination matches a previously used transparent wallet address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressReuseHint {
    /// True when the address is a revealed BIP84 receive/change address that has been used.
    pub reused: bool,
}

/// Request to set or clear a local transaction label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTxLabelRequest {
    pub txid: String,
    /// Empty string clears the label.
    pub label: String,
}

/// Address-book contact kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContactKind {
    Public,
    Private,
}

/// Local address-book entry (non-secret).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactRecord {
    pub id: String,
    pub name: String,
    pub address: String,
    pub kind: ContactKind,
}

/// Create or update a contact. Empty / omitted `id` creates a new entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertContactRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub address: String,
    pub kind: ContactKind,
}

/// Delete a contact by id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteContactRequest {
    pub id: String,
}

/// One input or output from explorer tx enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIo {
    pub address: String,
    pub value_sats: u64,
    /// True when this address is one of the wallet's revealed SPKs (local match).
    pub is_wallet: bool,
}

/// Confirmation status from the explorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u32>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

/// Full transaction view from litview (`/api/tx/{txid}`), with local wallet tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxEnrichment {
    pub txid: String,
    pub fee_sats: Option<u64>,
    pub size: Option<u32>,
    pub weight: Option<u32>,
    pub status: TxStatus,
    pub inputs: Vec<TxIo>,
    pub outputs: Vec<TxIo>,
}

/// Suggested fee rates from litview (`/api/v1/fees/recommended`), sat/vB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeLadder {
    pub fastest_sat_vb: u64,
    pub half_hour_sat_vb: u64,
    pub hour_sat_vb: u64,
    pub economy_sat_vb: Option<u64>,
    pub minimum_sat_vb: Option<u64>,
}

/// Combined transparent + MWEB balances (v0.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CombinedSummary {
    pub transparent: WalletSummary,
    pub mweb_confirmed_sats: u64,
    pub mweb_unconfirmed_sats: u64,
    pub mweb_immature_sats: u64,
    pub mweb_total_sats: u64,
    pub mweb_receive_address: Option<String>,
    /// Tip height of last successful MWEB sync; `None` if never synced.
    pub mweb_synced_height: Option<u32>,
    pub mweb_stale: bool,
    pub mweb_status: String,
}

/// Coarse phase of an in-flight wallet sync (poll with MWEB progress).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SyncPhase {
    #[default]
    Idle,
    ElectrumFullScan,
    ElectrumSync,
    MwebDownload,
    Done,
}

impl SyncPhase {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ElectrumFullScan,
            2 => Self::ElectrumSync,
            3 => Self::MwebDownload,
            4 => Self::Done,
            _ => Self::Idle,
        }
    }

    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Idle => 0,
            Self::ElectrumFullScan => 1,
            Self::ElectrumSync => 2,
            Self::MwebDownload => 3,
            Self::Done => 4,
        }
    }
}

/// Progress of an in-flight sync (poll while a sync runs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MwebSyncProgress {
    /// Coarse phase of the overall wallet sync (Electrum then MWEB).
    #[serde(default)]
    pub phase: SyncPhase,
    /// True while an MWEB sync pass is running.
    pub active: bool,
    /// UTXO leaves fetched so far in the current pass.
    pub fetched: u64,
    /// Total UTXO leaves the current pass will download (0 until known).
    pub total: u64,
}

/// Redacted support bundle (no mnemonic, passphrase, or sealed blobs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagnosticsBundle {
    pub app_version: String,
    pub os: String,
    pub generated_unix: u64,
    pub network: Option<String>,
    pub electrum_url: Option<String>,
    pub electrum_validate_domain: Option<bool>,
    pub electrum_use_public_fallback: Option<bool>,
    pub active_electrum_url: Option<String>,
    pub mweb_scheme: Option<String>,
    pub mweb_peers: Option<Vec<String>>,
    pub needs_full_scan: Option<bool>,
    pub needs_mweb_scan: Option<bool>,
    pub tip_height: Option<u32>,
    pub mweb_synced_height: Option<u32>,
    pub mweb_status: Option<String>,
    pub sync_phase: SyncPhase,
    pub recent_log_lines: Vec<String>,
}

/// Default MWEB kernel fee (0.0005 LTC). Used when the request leaves fee as 0.
pub const DEFAULT_MWEB_FEE_SATS: u64 = 50_000;

/// Request to peg transparent LTC into MWEB.
///
/// `amount_sats` is the peg-in output value (HogEx). The private coin credited is
/// `amount_sats - mweb_fee_sats`. Transparent inputs also pay `transparent_fee_sats`.
/// Fee fields of `0` mean “pick automatically”.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeginRequest {
    /// Ignored when [`Self::drain`] is true.
    #[serde(default)]
    pub amount_sats: u64,
    /// MWEB kernel fee; `0` = [`DEFAULT_MWEB_FEE_SATS`].
    #[serde(default)]
    pub mweb_fee_sats: u64,
    /// Transparent miner fee; `0` = estimate from Electrum.
    #[serde(default)]
    pub transparent_fee_sats: u64,
    /// Peg in the maximum from the spendable set (wallet-wide, or
    /// [`Self::selected_outpoints`] when that is non-empty), minus transparent fee.
    #[serde(default)]
    pub drain: bool,
    /// When non-empty, fund the peg-in from only these transparent outpoints (`txid:vout`).
    /// Combined with [`Self::drain`], empties the selected coins (minus fees).
    #[serde(default)]
    pub selected_outpoints: Option<Vec<String>>,
}

/// Dry-run of a peg-in before broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeginPreview {
    /// Peg-in output value (leaves transparent).
    pub amount_sats: u64,
    /// Private coin that will be credited after the MWEB fee.
    pub private_credit_sats: u64,
    pub mweb_fee_sats: u64,
    pub transparent_fee_sats: u64,
    /// Total transparent spend: peg-in amount + transparent fee.
    pub total_from_transparent_sats: u64,
    /// True when manual coin selection likely leaves transparent change.
    #[serde(default)]
    pub creates_change: bool,
}

/// Result of probing an Electrum server (Settings “Test connection”).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectrumProbe {
    pub url: String,
    pub tip_height: u32,
    /// Round-trip time for connect + handshake + tip subscribe, milliseconds.
    pub latency_ms: u64,
}

/// Result of a peg-in broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeginResult {
    pub txid: String,
    pub fee_sats: u64,
    pub maturity_blocks: u32,
}

/// Request to send MWEB → MWEB. `fee_sats` of `0` means auto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MwebSendRequest {
    pub address: String,
    /// Ignored when [`Self::drain`] is true.
    #[serde(default)]
    pub amount_sats: u64,
    #[serde(default)]
    pub fee_sats: u64,
    /// Send all spendable private funds minus the kernel fee.
    #[serde(default)]
    pub drain: bool,
    /// When non-empty, spend only these MWEB output ids (hex). Combined with
    /// [`Self::drain`], empties the selected coins (minus the kernel fee).
    #[serde(default)]
    pub selected_output_ids: Option<Vec<String>>,
}

/// Dry-run of a private send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MwebSendPreview {
    pub amount_sats: u64,
    pub fee_sats: u64,
    /// True when selected (or auto-picked) inputs exceed amount + fee.
    #[serde(default)]
    pub creates_change: bool,
}

/// Request to peg MWEB out to a transparent address. `fee_sats` of `0` means auto.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegoutRequest {
    /// Destination for a typed-amount (single HogEx) peg-out. Ignored when
    /// [`Self::per_coin`] is true; the wallet reveals fresh receive addresses.
    #[serde(default)]
    pub address: String,
    /// Ignored when [`Self::drain`] is true or coins are selected (per-coin).
    #[serde(default)]
    pub amount_sats: u64,
    #[serde(default)]
    pub fee_sats: u64,
    /// Peg out all spendable private funds minus the kernel fee, one public
    /// output per private coin.
    #[serde(default)]
    pub drain: bool,
    /// When non-empty, spend only these MWEB output ids (hex). Combined with
    /// [`Self::drain`], empties the selected coins (minus the kernel fee).
    /// Non-empty selection is always per-coin (one HogEx output each).
    #[serde(default)]
    pub selected_output_ids: Option<Vec<String>>,
    /// Filled by the resolver: one HogEx amount per spent coin when per-coin.
    /// Clients should leave this empty.
    #[serde(default)]
    pub output_amounts: Vec<u64>,
    /// Filled on broadcast for per-coin peg-outs (fresh receive addresses).
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Filled by the resolver. When true, emit one HogEx output per coin.
    #[serde(default)]
    pub per_coin: bool,
    /// Index into [`Self::output_amounts`] that absorbed the kernel fee.
    #[serde(default)]
    pub fee_output_index: Option<u32>,
}

/// Dry-run of a peg-out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegoutPreview {
    pub amount_sats: u64,
    pub fee_sats: u64,
    /// Minimum non-dust for the destination script (litoshis).
    pub dust_sats: u64,
    /// True when selected (or auto-picked) inputs exceed amount + fee.
    #[serde(default)]
    pub creates_change: bool,
    /// Number of HogEx (public) outputs. Typed-amount path is always 1.
    #[serde(default)]
    pub output_count: u32,
    /// Public output amounts in order. Sum equals [`Self::amount_sats`].
    #[serde(default)]
    pub output_amounts: Vec<u64>,
    /// Which output is paying the kernel fee (per-coin path only).
    #[serde(default)]
    pub fee_output_index: Option<u32>,
}

/// Result of an MWEB-only broadcast (identified by wtxid).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MwebBroadcastResult {
    pub wtxid: String,
    pub fee_sats: u64,
    /// Fresh public receive addresses created for this peg-out (empty for MWEB send).
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// Public (transparent) or Private (MWEB) split.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SplitChain {
    Public,
    Private,
}

/// One spendable MWEB coin for the Coins list / split picker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MwebUtxoRecord {
    pub output_id: String,
    pub amount_sats: u64,
    pub confirmations: u32,
    /// False for unconfirmed coins and immature peg-ins.
    pub mature: bool,
    /// Blocks remaining until spendable (0 when mature).
    #[serde(default)]
    pub maturity_blocks_left: u32,
    /// Frozen coins are skipped by automatic coin selection.
    #[serde(default)]
    pub locked: bool,
    /// Optional local note (non-secret sidecar).
    #[serde(default)]
    pub label: String,
    /// This coin is the peg-in output, or a descendant tracked from one.
    #[serde(default)]
    pub from_pegin: bool,
    /// Non-solo blocks recorded for this coin. `None` means this device does not know.
    #[serde(default)]
    pub non_solo_blocks: Option<u32>,
    /// Other kernels in the last counted block.
    #[serde(default)]
    pub last_other_kernels: Option<u64>,
    /// Other outputs in the last counted block.
    #[serde(default)]
    pub last_other_outputs: Option<u64>,
    /// Counted blocks, oldest first. Empty on records saved before this list existed.
    #[serde(default)]
    pub hops: Vec<ChurnHop>,
    /// Live self-spend phase when this coin is the job's current output.
    #[serde(default)]
    pub churn_phase: Option<ChurnPhase>,
    /// Broadcast or score error for the live job, if any.
    #[serde(default)]
    pub churn_error: Option<String>,
    /// Non-solo blocks this job is waiting for. Set only while the job holds this coin.
    #[serde(default)]
    pub churn_target: Option<u32>,
    /// Non-solo blocks this job has already counted.
    #[serde(default)]
    pub churn_counted: Option<u32>,
}

/// One output in a split plan (change is flagged).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitOutput {
    pub amount_sats: u64,
    #[serde(default)]
    pub is_change: bool,
}

/// Request to preview or broadcast a 1-in-N-out self-split.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitRequest {
    pub chain: SplitChain,
    /// Public: `txid:vout`. Private: MWEB output id hex.
    pub input: String,
    /// Equal split into this many outputs (2–50). Mutually exclusive with [`Self::amounts`].
    #[serde(default)]
    pub equal_count: Option<u32>,
    /// Denomination amounts in litoshis (one entry per output, not including change).
    #[serde(default)]
    pub amounts: Vec<u64>,
    /// Public sat/vB. When omitted or zero, the wallet estimates from Electrum.
    #[serde(default)]
    pub fee_rate_sat_vb: Option<u64>,
    /// When 0, preview estimates. `split_coin` must pass the preview fee.
    #[serde(default)]
    pub fee_sats: u64,
}

/// Dry-run of a split: exact outputs and fee that [`crate::WalletApp::split_coin`] will build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitPreview {
    pub input_sats: u64,
    pub outputs: Vec<SplitOutput>,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: u64,
    pub change_sats: u64,
    #[serde(default)]
    pub creates_change: bool,
}

/// Result of a split broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitResult {
    /// Transparent txid or MWEB wtxid.
    pub txid: String,
    pub fee_sats: u64,
    pub output_count: u32,
}

/// How many non-solo blocks a self-spend will wait for. The sheet defaults to one.
pub const CHURN_MAX_TARGET: u32 = 10;

/// Confirm-sheet sentence: depth does not hide the implied amount.
pub const CHURN_AMOUNT_NOTE: &str = "This subtracts the public fee. The resulting amount is still determined by where this coin started.";

/// Confirm-sheet sentence: a quiet block pauses and does not retry.
pub const CHURN_QUIET_NOTE: &str = "A block that only contains this spend does not count, and this wallet will not try again by itself.";

/// Live self-spend job phase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ChurnPhase {
    WaitingToBroadcast,
    WaitingConfirm,
    PausedSolo,
    PausedUnscored,
    Done,
    Cancelled,
}

impl ChurnPhase {
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::WaitingToBroadcast
                | Self::WaitingConfirm
                | Self::PausedSolo
                | Self::PausedUnscored
        )
    }
}

/// Start or preview a self-spend. `target_depth` of 0 means one hop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChurnRequest {
    pub output_id: String,
    /// Non-solo blocks to count before the job stops. `0` or omitted means 1.
    #[serde(default)]
    pub target_depth: u32,
}

/// Dry-run of one self-spend hop, plus the fee if the target is more than one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChurnPreview {
    pub input_sats: u64,
    /// Fee for a single hop.
    pub hop_fee_sats: u64,
    /// Coin amount after one hop.
    pub resulting_sats: u64,
    pub target_depth: u32,
    /// `target_depth * hop_fee_sats`. A quiet block can stop the run before this is spent.
    pub total_fee_sats: u64,
    pub amount_note: String,
    pub quiet_block_note: String,
}

/// What the Coins screen needs while a job exists, including after it finishes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChurnStatus {
    pub phase: ChurnPhase,
    pub output_id: String,
    pub target_depth: u32,
    pub effective_depth: u32,
    pub fee_sats: u64,
    pub from_pegin: bool,
    #[serde(default)]
    pub last_other_kernels: Option<u64>,
    #[serde(default)]
    pub last_other_outputs: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Other kernels and outputs in one counted block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChurnHop {
    pub other_kernels: u64,
    pub other_outputs: u64,
}

/// Local record that a coin has shared some number of blocks. Exported with metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChurnDepthRecord {
    pub output_id: String,
    pub non_solo_blocks: u32,
    #[serde(default)]
    pub last_other_kernels: Option<u64>,
    #[serde(default)]
    pub last_other_outputs: Option<u64>,
    /// Counted blocks, oldest first. Missing on older files and bundles.
    #[serde(default)]
    pub hops: Vec<ChurnHop>,
    #[serde(default)]
    pub from_pegin: bool,
}

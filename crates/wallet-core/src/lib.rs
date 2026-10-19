//! Wallet-core: BDK boundary for the Litecoin Mac wallet.
//!
//! Public API exposes serde DTOs only. BDK types remain private.

mod aezeed;
mod app;
mod churn;
mod contacts;
mod descriptors;
mod discovery;
mod dto;
mod electrum;
mod error;
pub mod explorer;
mod history_export;
mod insights;
mod labels;
mod meta;
mod metadata;
mod mweb;
mod mweb_frozen;
mod mweb_history;
mod network;
mod rpc;
mod secrets;
mod seed;
mod split;
mod split_ids;
mod utxo_labels;

pub use app::{MemoryBackedApp, WalletApp};
pub use dto::{
    AddressReuseHint, ChurnDepthRecord, ChurnPhase, ChurnPreview, ChurnRequest, ChurnStatus,
    CombinedSummary, ContactKind, ContactRecord, CreateWalletRequest, CreateWalletResponse,
    DeleteContactRequest, ElectrumProbe, FeeEstimate, FeeLadder, MetricSeries,
    MigrateEncryptRequest, MwebBroadcastResult, MwebScheme, MwebSendPreview, MwebSendRequest,
    MwebSyncProgress, MwebUtxoRecord, NetworkPulse, PeginPreview, PeginRequest, PeginResult,
    PegoutPreview, PegoutRequest, RestoreWalletRequest, RevealMnemonicRequest,
    RevealMnemonicResponse, SendPreview, SendRequest, SendResult, SetMwebUtxoLockedRequest,
    SetTxLabelRequest, SetUtxoLabelRequest, SetUtxoLockedRequest, SplitChain, SplitOutput,
    SplitPreview, SplitRequest, SplitResult, SyncResult, TxEnrichment, TxIo, TxKind, TxRecord,
    TxStatus, UnlockRequest, UpdateSettingsRequest, UpsertContactRequest, UtxoRecord,
    WalletSettings, WalletSummary, CHURN_AMOUNT_NOTE, CHURN_MAX_TARGET, CHURN_QUIET_NOTE,
    DEFAULT_MWEB_FEE_SATS,
};
pub use error::{BroadcastFailureKind, WalletError};
pub use explorer::{is_chain_txid, DEFAULT_EXPLORER_BASE_URL};
pub use history_export::HistoryExportFormat;
pub use metadata::{MetadataBundle, MetadataImportResult};
pub use network::WalletNetwork;
pub use secrets::{
    EncryptedFileSecretStore, FileSecretStore, MemoryStore, SecretStore, UnlockableSecretStore,
};
pub use seed::{derive_preview, DerivePreview, MasterSecret, MwebSchemePreview};

/// Filename for the legacy plaintext mnemonic store.
pub const MNEMONIC_FILE: &str = "wallet.mnemonic";
/// Filename for the encrypted mnemonic store.
pub const MNEMONIC_ENC_FILE: &str = "wallet.mnemonic.enc";

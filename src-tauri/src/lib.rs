use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

use tauri::{AppHandle, Manager, State};
use wallet_core::{
    AddressReuseHint, CombinedSummary, ContactRecord, CreateWalletRequest, CreateWalletResponse,
    DeleteContactRequest, DiagnosticsBundle, ElectrumProbe, FeeEstimate, FeeLadder,
    HistoryExportFormat, MetadataImportResult, MetricSeries, MigrateEncryptRequest,
    MwebBroadcastResult, MwebSendPreview, MwebSendRequest, MwebSyncProgress, MwebUtxoRecord,
    NetworkPulse, PeginPreview, PeginRequest, PeginResult, PegoutPreview, PegoutRequest,
    RestoreWalletRequest, RevealMnemonicRequest, RevealMnemonicResponse, SendPreview, SendRequest,
    SendResult, SetTxLabelRequest, SetUtxoLabelRequest, SetMwebUtxoLockedRequest,
    SetUtxoLockedRequest, SplitPreview, SplitRequest, SplitResult, SyncResult, TxEnrichment,
    TxRecord, UnlockRequest, UpdateSettingsRequest, UpsertContactRequest, UtxoRecord, WalletApp,
    WalletSettings, WalletSummary, ChurnPreview, ChurnRequest, ChurnStatus,
};

mod litvm;

pub(crate) fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub(crate) fn map_err(err: wallet_core::WalletError) -> String {
    err.to_string()
}

#[tauri::command]
async fn wallet_exists(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<bool, String> {
    let dir = data_dir(&app)?;
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.exists(&dir))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_is_locked(state: State<'_, Arc<WalletApp>>) -> Result<bool, String> {
    let wallet = Arc::clone(&state);
    Ok(wallet.is_locked())
}

#[tauri::command]
async fn wallet_needs_migration(state: State<'_, Arc<WalletApp>>) -> Result<bool, String> {
    let wallet = Arc::clone(&state);
    Ok(wallet.needs_migration())
}

#[tauri::command]
async fn unlock_wallet(
    state: State<'_, Arc<WalletApp>>,
    req: UnlockRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.unlock(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn lock_wallet(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    wallet.lock();
    #[cfg(feature = "litvm")]
    litvm::drop_from_app(&app).await;
    let _ = app;
    Ok(())
}

#[tauri::command]
async fn reveal_mnemonic(
    state: State<'_, Arc<WalletApp>>,
    req: RevealMnemonicRequest,
) -> Result<RevealMnemonicResponse, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.reveal_mnemonic(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn migrate_encrypt(
    state: State<'_, Arc<WalletApp>>,
    req: MigrateEncryptRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.migrate_encrypt(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn create_wallet(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
    req: CreateWalletRequest,
    passphrase: String,
) -> Result<CreateWalletResponse, String> {
    let dir = data_dir(&app)?;
    let wallet = Arc::clone(&state);
    let result = tauri::async_runtime::spawn_blocking(move || {
        wallet.create(&dir, req, &passphrase).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())?;
    if result.is_ok() {
        #[cfg(feature = "litvm")]
        {
            let _ = litvm::attach_from_app(&app, &state).await;
        }
    }
    result
}

#[tauri::command]
async fn restore_wallet(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
    req: RestoreWalletRequest,
    passphrase: String,
) -> Result<WalletSummary, String> {
    let dir = data_dir(&app)?;
    let wallet = Arc::clone(&state);
    let result = tauri::async_runtime::spawn_blocking(move || {
        wallet.restore(&dir, req, &passphrase).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())?;
    if result.is_ok() {
        #[cfg(feature = "litvm")]
        {
            let _ = litvm::attach_from_app(&app, &state).await;
        }
    }
    result
}

#[tauri::command]
async fn load_wallet(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<WalletSummary, String> {
    let dir = data_dir(&app)?;
    let wallet = Arc::clone(&state);
    let result = tauri::async_runtime::spawn_blocking(move || wallet.load(&dir).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?;
    if result.is_ok() {
        #[cfg(feature = "litvm")]
        {
            let _ = litvm::attach_from_app(&app, &state).await;
        }
    }
    result
}

#[tauri::command]
async fn sync_wallet(state: State<'_, Arc<WalletApp>>) -> Result<SyncResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.sync().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_summary(state: State<'_, Arc<WalletApp>>) -> Result<WalletSummary, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.summary().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_combined_summary(
    state: State<'_, Arc<WalletApp>>,
) -> Result<CombinedSummary, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.combined_summary().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn address_reuse_hint(
    state: State<'_, Arc<WalletApp>>,
    address: String,
) -> Result<AddressReuseHint, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        wallet.address_reuse_hint(&address).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_tx_labels(
    state: State<'_, Arc<WalletApp>>,
) -> Result<HashMap<String, String>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.get_tx_labels().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn set_tx_label(
    state: State<'_, Arc<WalletApp>>,
    req: SetTxLabelRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.set_tx_label(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_contacts(state: State<'_, Arc<WalletApp>>) -> Result<Vec<ContactRecord>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.list_contacts().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn upsert_contact(
    state: State<'_, Arc<WalletApp>>,
    req: UpsertContactRequest,
) -> Result<ContactRecord, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.upsert_contact(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn delete_contact(
    state: State<'_, Arc<WalletApp>>,
    req: DeleteContactRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.delete_contact(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_transactions(state: State<'_, Arc<WalletApp>>) -> Result<Vec<TxRecord>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.transactions().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

/// Export history to a user-chosen file. Returns the path written, or `None` if cancelled.
#[tauri::command]
async fn export_history(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
    format: String,
) -> Result<Option<String>, String> {
    let export_format = HistoryExportFormat::parse(&format).map_err(map_err)?;
    let wallet = Arc::clone(&state);
    let body = tauri::async_runtime::spawn_blocking(move || {
        wallet.export_history(export_format).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())??;

    let default_name = export_format.default_filename().to_string();
    let ext = export_format.extension().to_string();
    let filter_name = match export_format {
        HistoryExportFormat::Csv => "CSV",
        HistoryExportFormat::Json => "JSON",
    }
    .to_string();

    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let path = rfd::FileDialog::new()
            .set_title("Export transaction history")
            .set_file_name(&default_name)
            .add_filter(&filter_name, &[&ext])
            .save_file();
        let _ = tx.send(path);
    })
    .map_err(|e| e.to_string())?;

    let Some(path) = rx.recv().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn get_receive_address(state: State<'_, Arc<WalletApp>>) -> Result<String, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.receive_address().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn get_mweb_receive_address(state: State<'_, Arc<WalletApp>>) -> Result<String, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.mweb_receive_address().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn estimate_fee(state: State<'_, Arc<WalletApp>>) -> Result<FeeEstimate, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.estimate_fee().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_unspent(state: State<'_, Arc<WalletApp>>) -> Result<Vec<UtxoRecord>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.list_unspent().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn list_mweb_unspent(
    state: State<'_, Arc<WalletApp>>,
) -> Result<Vec<MwebUtxoRecord>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.list_mweb_unspent().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_split(
    state: State<'_, Arc<WalletApp>>,
    req: SplitRequest,
) -> Result<SplitPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_split(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn split_coin(
    state: State<'_, Arc<WalletApp>>,
    req: SplitRequest,
) -> Result<SplitResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.split_coin(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_churn(
    state: State<'_, Arc<WalletApp>>,
    req: ChurnRequest,
) -> Result<ChurnPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_churn(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn start_churn(
    state: State<'_, Arc<WalletApp>>,
    req: ChurnRequest,
) -> Result<ChurnStatus, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.start_churn(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn churn_status(
    state: State<'_, Arc<WalletApp>>,
) -> Result<Option<ChurnStatus>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.churn_status().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn retry_churn(state: State<'_, Arc<WalletApp>>) -> Result<ChurnStatus, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.retry_churn().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn cancel_churn(state: State<'_, Arc<WalletApp>>) -> Result<ChurnStatus, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.cancel_churn().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn set_utxo_locked(
    state: State<'_, Arc<WalletApp>>,
    req: SetUtxoLockedRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.set_utxo_locked(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn set_mweb_utxo_locked(
    state: State<'_, Arc<WalletApp>>,
    req: SetMwebUtxoLockedRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.set_mweb_utxo_locked(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn set_utxo_label(
    state: State<'_, Arc<WalletApp>>,
    req: SetUtxoLabelRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.set_utxo_label(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn export_metadata(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<Option<String>, String> {
    let wallet = Arc::clone(&state);
    let body = tauri::async_runtime::spawn_blocking(move || {
        wallet.export_metadata_json().map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())??;

    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let path = rfd::FileDialog::new()
            .set_title("Export wallet metadata")
            .set_file_name("ltc-wallet-metadata.json")
            .add_filter("JSON", &["json"])
            .save_file();
        let _ = tx.send(path);
    })
    .map_err(|e| e.to_string())?;

    let Some(path) = rx.recv().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn import_metadata(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<Option<MetadataImportResult>, String> {
    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let path = rfd::FileDialog::new()
            .set_title("Import wallet metadata")
            .add_filter("JSON", &["json"])
            .pick_file();
        let _ = tx.send(path);
    })
    .map_err(|e| e.to_string())?;

    let Some(path) = rx.recv().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    let json = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let wallet = Arc::clone(&state);
    let result = tauri::async_runtime::spawn_blocking(move || {
        wallet.import_metadata_json(&json).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(Some(result))
}

#[tauri::command]
async fn test_electrum(
    state: State<'_, Arc<WalletApp>>,
    url: Option<String>,
) -> Result<ElectrumProbe, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.test_electrum(url).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn default_electrum_urls(state: State<'_, Arc<WalletApp>>) -> Result<Vec<String>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.default_electrum_urls().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_send(
    state: State<'_, Arc<WalletApp>>,
    req: SendRequest,
) -> Result<SendPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_send(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn send_ltc(
    state: State<'_, Arc<WalletApp>>,
    req: SendRequest,
) -> Result<SendResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.send(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_pegin(
    state: State<'_, Arc<WalletApp>>,
    req: PeginRequest,
) -> Result<PeginPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_pegin(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn pegin_ltc(
    state: State<'_, Arc<WalletApp>>,
    req: PeginRequest,
) -> Result<PeginResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.pegin(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_mweb_send(
    state: State<'_, Arc<WalletApp>>,
    req: MwebSendRequest,
) -> Result<MwebSendPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_mweb_send(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn mweb_send_ltc(
    state: State<'_, Arc<WalletApp>>,
    req: MwebSendRequest,
) -> Result<MwebBroadcastResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.mweb_send(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn preview_pegout(
    state: State<'_, Arc<WalletApp>>,
    req: PegoutRequest,
) -> Result<PegoutPreview, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.preview_pegout(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn pegout_ltc(
    state: State<'_, Arc<WalletApp>>,
    req: PegoutRequest,
) -> Result<MwebBroadcastResult, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.pegout(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn resync_mweb(state: State<'_, Arc<WalletApp>>) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.resync_mweb().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

/// Switch the MWEB derivation scheme and rescan under it (wipes local MWEB
/// state only; transparent wallet data is untouched).
#[tauri::command]
async fn set_mweb_scheme(
    state: State<'_, Arc<WalletApp>>,
    scheme: wallet_core::MwebScheme,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.set_mweb_scheme(scheme).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

/// Lock-free snapshot of MWEB download progress; pollable while a sync runs.
#[tauri::command]
async fn mweb_sync_progress(
    state: State<'_, Arc<WalletApp>>,
) -> Result<MwebSyncProgress, String> {
    Ok(state.mweb_sync_progress())
}

/// Redacted support bundle (no mnemonic / sealed secrets).
#[tauri::command]
async fn get_diagnostics(
    state: State<'_, Arc<WalletApp>>,
) -> Result<DiagnosticsBundle, String> {
    let wallet = Arc::clone(&state);
    let version = env!("CARGO_PKG_VERSION").to_string();
    Ok(tauri::async_runtime::spawn_blocking(move || wallet.diagnostics(&version))
        .await
        .map_err(|e| e.to_string())?)
}

/// Export diagnostics to a user-chosen text file. Returns the path, or `None` if cancelled.
#[tauri::command]
async fn export_diagnostics(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
) -> Result<Option<String>, String> {
    let wallet = Arc::clone(&state);
    let version = env!("CARGO_PKG_VERSION").to_string();
    let bundle = tauri::async_runtime::spawn_blocking(move || wallet.diagnostics(&version))
        .await
        .map_err(|e| e.to_string())?;
    let body = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;

    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let path = rfd::FileDialog::new()
            .set_title("Export diagnostics")
            .set_file_name("ldk-wallet-diagnostics.json")
            .add_filter("JSON", &["json"])
            .save_file();
        let _ = tx.send(path);
    })
    .map_err(|e| e.to_string())?;

    let Some(path) = rx.recv().map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

#[tauri::command]
async fn get_settings(state: State<'_, Arc<WalletApp>>) -> Result<WalletSettings, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.settings().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn update_settings(
    state: State<'_, Arc<WalletApp>>,
    req: UpdateSettingsRequest,
) -> Result<(), String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.update_settings(req).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn explorer_tx_url(
    state: State<'_, Arc<WalletApp>>,
    txid: String,
) -> Result<String, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.explorer_tx_url(&txid).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn explorer_block_url(
    state: State<'_, Arc<WalletApp>>,
    block_hash: String,
) -> Result<String, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || {
        wallet.explorer_block_url(&block_hash).map_err(map_err)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Open an http(s) URL in the system browser (never navigates the WebView).
#[tauri::command]
async fn open_explorer_url(url: String) -> Result<(), String> {
    wallet_core::explorer::validate_open_url(&url).map_err(map_err)?;
    open_url_in_browser(&url)
}

fn open_url_in_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        return Err("opening URLs is not supported on this platform".into());
    }
    Ok(())
}

#[tauri::command]
async fn fetch_tx_detail(
    state: State<'_, Arc<WalletApp>>,
    txid: String,
) -> Result<TxEnrichment, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.fetch_tx_detail(&txid).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fetch_spot_price(state: State<'_, Arc<WalletApp>>) -> Result<f64, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.fetch_spot_price().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fetch_fee_ladder(state: State<'_, Arc<WalletApp>>) -> Result<FeeLadder, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.fetch_fee_ladder().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fetch_network_pulse(state: State<'_, Arc<WalletApp>>) -> Result<NetworkPulse, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.fetch_network_pulse().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn fetch_insight_charts(
    state: State<'_, Arc<WalletApp>>,
) -> Result<Vec<MetricSeries>, String> {
    let wallet = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || wallet.fetch_insight_charts().map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

/// Phrase the user must type before a wipe is executed. Checked here at the
/// IPC boundary (not only in the UI) so a scripted or compromised webview
/// cannot destroy the wallet with a bare `invoke("wipe_wallet")`.
#[tauri::command]
fn litvm_available() -> bool {
    cfg!(feature = "litvm")
}

const WIPE_CONFIRMATION_PHRASE: &str = "DELETE WALLET";

#[tauri::command]
async fn wipe_wallet(
    app: AppHandle,
    state: State<'_, Arc<WalletApp>>,
    confirmation: String,
) -> Result<(), String> {
    if confirmation.trim() != WIPE_CONFIRMATION_PHRASE {
        return Err(format!(
            "wipe refused: type {WIPE_CONFIRMATION_PHRASE} to confirm deleting all wallet data"
        ));
    }
    let dir = data_dir(&app)?;
    let wallet = Arc::clone(&state);
    #[cfg(feature = "litvm")]
    {
        litvm::drop_from_app(&app).await;
        litvm::wipe_sidecar(&dir);
    }
    tauri::async_runtime::spawn_blocking(move || wallet.wipe(&dir).map_err(map_err))
        .await
        .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir)?;
            app.manage(Arc::new(WalletApp::new(&dir)));
            #[cfg(feature = "litvm")]
            app.manage(Arc::new(litvm::LitVmHandle::new()));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            wallet_exists,
            wallet_is_locked,
            wallet_needs_migration,
            unlock_wallet,
            lock_wallet,
            reveal_mnemonic,
            migrate_encrypt,
            create_wallet,
            restore_wallet,
            load_wallet,
            sync_wallet,
            get_summary,
            get_combined_summary,
            list_transactions,
            export_history,
            address_reuse_hint,
            get_tx_labels,
            set_tx_label,
            list_contacts,
            upsert_contact,
            delete_contact,
            get_receive_address,
            get_mweb_receive_address,
            estimate_fee,
            list_unspent,
            list_mweb_unspent,
            preview_split,
            split_coin,
            preview_churn,
            start_churn,
            churn_status,
            retry_churn,
            cancel_churn,
            set_utxo_locked,
            set_mweb_utxo_locked,
            set_utxo_label,
            export_metadata,
            import_metadata,
            test_electrum,
            default_electrum_urls,
            preview_send,
            send_ltc,
            preview_pegin,
            pegin_ltc,
            preview_mweb_send,
            mweb_send_ltc,
            preview_pegout,
            pegout_ltc,
            resync_mweb,
            set_mweb_scheme,
            mweb_sync_progress,
            get_diagnostics,
            export_diagnostics,
            get_settings,
            update_settings,
            explorer_tx_url,
            explorer_block_url,
            open_explorer_url,
            fetch_tx_detail,
            fetch_spot_price,
            fetch_fee_ladder,
            fetch_network_pulse,
            fetch_insight_charts,
            wipe_wallet,
            litvm_available,
            litvm::litvm_summary,
            litvm::test_litvm_rpc,
            litvm::preview_litvm_send,
            litvm::send_litvm,
            litvm::replace_litvm_tx,
            litvm::litvm_history,
            litvm::validate_litvm_address,
            litvm::get_litvm_settings,
            litvm::update_litvm_settings,
            litvm::litvm_explorer_tx_url,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

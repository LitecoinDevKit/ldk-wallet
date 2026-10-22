use std::path::Path;
use std::sync::{Arc, Mutex};

use tauri::{AppHandle, Manager, State};
use wallet_core::WalletApp;
use wallet_litvm::{
    parse_evm_address, wipe_settings_file, LitVmClient, LitVmHistoryPage, LitVmProbe,
    LitVmReplaceRequest, LitVmSendPreview, LitVmSendRequest, LitVmSendResult, LitVmSettings,
    LitVmSummary, UpdateLitVmSettingsRequest,
};

use crate::{data_dir, map_err};

/// Holds the LitVM client. `LitVmClient` owns a tokio runtime, so creating or
/// dropping one must happen on a blocking thread: tokio panics when a runtime
/// is dropped from inside an async context, and that panic would abort the
/// Tauri command that triggered it (the frontend `invoke` then never settles).
/// Use [`attach_from_app`] / [`drop_from_app`] (async wrappers) from commands.
pub struct LitVmHandle {
    client: Mutex<Option<LitVmClient>>,
}

impl LitVmHandle {
    pub fn new() -> Self {
        Self {
            client: Mutex::new(None),
        }
    }

    /// Lock the client slot, recovering from poisoning so one earlier panic
    /// does not permanently disable LitVM for the session.
    fn slot(&self) -> std::sync::MutexGuard<'_, Option<LitVmClient>> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Blocking: drops the client (and its runtime). Call off the async runtime.
    pub fn drop_client(&self) {
        let old = self.slot().take();
        drop(old);
    }
}

fn map_litvm(err: wallet_litvm::LitVmError) -> String {
    err.to_string()
}

/// Blocking: builds a client (and its runtime) and swaps it in. Call off the
/// async runtime; see [`LitVmHandle`].
pub fn attach(wallet: &WalletApp, handle: &LitVmHandle, data_dir: &Path) -> Result<(), String> {
    let secret = wallet.litvm_account_secret().map_err(map_err)?;
    let client = LitVmClient::open(data_dir, secret).map_err(map_litvm)?;
    let old = {
        let mut guard = handle.slot();
        guard.replace(client)
    };
    // Shut the previous runtime down outside the lock.
    drop(old);
    Ok(())
}

fn with_client<T>(
    handle: &LitVmHandle,
    f: impl FnOnce(&mut LitVmClient) -> Result<T, wallet_litvm::LitVmError>,
) -> Result<T, String> {
    let mut guard = handle.slot();
    let client = guard.as_mut().ok_or_else(|| {
        "LitVM is not ready — unlock the wallet first".to_string()
    })?;
    f(client).map_err(map_litvm)
}

#[tauri::command]
pub async fn litvm_summary(
    handle: State<'_, Arc<LitVmHandle>>,
) -> Result<LitVmSummary, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.summary()))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn test_litvm_rpc(
    handle: State<'_, Arc<LitVmHandle>>,
) -> Result<LitVmProbe, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| Ok(c.probe())))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn preview_litvm_send(
    handle: State<'_, Arc<LitVmHandle>>,
    req: LitVmSendRequest,
) -> Result<LitVmSendPreview, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.preview_send(&req)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn send_litvm(
    handle: State<'_, Arc<LitVmHandle>>,
    req: LitVmSendRequest,
) -> Result<LitVmSendResult, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.send(&req)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn replace_litvm_tx(
    handle: State<'_, Arc<LitVmHandle>>,
    req: LitVmReplaceRequest,
) -> Result<LitVmSendResult, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.replace_tx(&req)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn litvm_history(
    handle: State<'_, Arc<LitVmHandle>>,
) -> Result<LitVmHistoryPage, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.history()))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn validate_litvm_address(address: String) -> Result<String, String> {
    parse_evm_address(&address)
        .map(|addr| addr.to_checksum(None))
        .map_err(map_litvm)
}

#[tauri::command]
pub async fn get_litvm_settings(
    handle: State<'_, Arc<LitVmHandle>>,
) -> Result<LitVmSettings, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| Ok(c.settings())))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn update_litvm_settings(
    handle: State<'_, Arc<LitVmHandle>>,
    req: UpdateLitVmSettingsRequest,
) -> Result<LitVmSettings, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || with_client(&handle, |c| c.update_settings(req)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn litvm_explorer_tx_url(
    handle: State<'_, Arc<LitVmHandle>>,
    txid: String,
) -> Result<String, String> {
    let handle = Arc::clone(&handle);
    tauri::async_runtime::spawn_blocking(move || {
        with_client(&handle, |c| Ok(c.explorer_tx_url(&txid)))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn attach_from_app_blocking(app: &AppHandle, wallet: &WalletApp) -> Result<(), String> {
    let dir = data_dir(app)?;
    let handle = app.state::<Arc<LitVmHandle>>();
    attach(wallet, &handle, &dir)
}

fn drop_from_app_blocking(app: &AppHandle) {
    if let Some(handle) = app.try_state::<Arc<LitVmHandle>>() {
        handle.drop_client();
    }
}

/// Attach the LitVM client for the currently unlocked wallet. Runs on a
/// blocking thread so the client's runtime is never created or dropped inside
/// the async command context.
pub async fn attach_from_app(app: &AppHandle, wallet: &Arc<WalletApp>) -> Result<(), String> {
    let app = app.clone();
    let wallet = Arc::clone(wallet);
    tauri::async_runtime::spawn_blocking(move || attach_from_app_blocking(&app, &wallet))
        .await
        .map_err(|e| e.to_string())?
}

/// Drop the LitVM client (e.g. on lock / wipe). Runs on a blocking thread so
/// the runtime shutdown never happens inside the async command context.
pub async fn drop_from_app(app: &AppHandle) {
    let app = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || drop_from_app_blocking(&app)).await;
}

pub fn wipe_sidecar(data_dir: &Path) {
    let _ = wipe_settings_file(data_dir);
}

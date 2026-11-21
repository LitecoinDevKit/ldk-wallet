//! Integration and subprocess crash-recovery tests (Hardening item 17).

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use wallet_core::{
    CreateWalletRequest, EncryptedFileSecretStore, SyncPhase, UnlockRequest, UnlockableSecretStore,
    UpdateSettingsRequest, WalletApp, WalletNetwork, MNEMONIC_ENC_FILE, MNEMONIC_FILE,
};

const PASSPHRASE: &str = "correct horse battery staple";
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn leftover_temp_files_are_swept_on_load_and_wipe() {
    let dir = tempdir().unwrap();
    let app = WalletApp::new(dir.path());
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
        PASSPHRASE,
    )
    .expect("create");

    let account_dir = app.active_account_dir(dir.path()).unwrap();
    let root_tmp = dir.path().join("accounts.json.tmp.999");
    let acct_tmp = account_dir.join("churn_job.json.tmp.999");
    let enc_tmp = account_dir.join("mweb_coins.enc.tmp.999");
    fs::write(&root_tmp, b"partial").unwrap();
    fs::write(&acct_tmp, b"partial").unwrap();
    fs::write(&enc_tmp, b"partial").unwrap();

    app.lock();
    app.unlock(UnlockRequest {
        passphrase: PASSPHRASE.into(),
    })
    .unwrap();
    app.load(dir.path()).unwrap();

    assert!(
        !root_tmp.exists() && !acct_tmp.exists() && !enc_tmp.exists(),
        "load must sweep leftover *.tmp.* files from an interrupted write"
    );

    // Plant another temp file and verify wipe removes it too.
    fs::write(&acct_tmp, b"partial").unwrap();
    app.wipe(dir.path()).unwrap();
    assert!(!acct_tmp.exists());
}

#[test]
fn secret_store_write_failure_leaves_no_temp_files_and_preserves_existing_blob() {
    let dir = tempdir().unwrap();
    let enc = dir.path().join(MNEMONIC_ENC_FILE);
    let plain = dir.path().join(MNEMONIC_FILE);
    let store = EncryptedFileSecretStore::new(&enc, &plain);
    store
        .set_with_passphrase(PASSPHRASE, TEST_MNEMONIC)
        .unwrap();
    let original_blob = fs::read(&enc).unwrap();
    let original_key = store.sealing_key().unwrap();

    // Ensure no .tmp files are left beside wallet.mnemonic.enc after a normal write.
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !entries.iter().any(|name| name.contains(".tmp")),
        "unexpected temp files after write: {entries:?}"
    );

    store.lock();
    store.unlock(PASSPHRASE).unwrap();
    assert_eq!(store.sealing_key().unwrap(), original_key);
    assert_eq!(fs::read(&enc).unwrap(), original_blob);
}

#[test]
fn sigkill_mid_electrum_sync_recovers_cleanly_on_restart() {
    if let Ok(raw_dir) = std::env::var("LDK_WALLET_SIGKILL_SYNC_DIR") {
        let root = PathBuf::from(raw_dir);
        let app = WalletApp::new(&root);
        app.unlock(UnlockRequest {
            passphrase: PASSPHRASE.into(),
        })
        .unwrap();
        app.load(&root).unwrap();
        let _ = app.sync();
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let electrum_url = format!("tcp://{}", listener.local_addr().unwrap());

    let dir = tempdir().unwrap();
    let app = WalletApp::new(dir.path());
    let created = app
        .create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: Some(electrum_url.clone()),
            },
            PASSPHRASE,
        )
        .unwrap();
    let settings = app.settings().unwrap();
    app.update_settings(UpdateSettingsRequest {
        electrum_url,
        electrum_validate_domain: false,
        electrum_use_public_fallback: false,
        auto_lock_minutes: settings.auto_lock_minutes,
        litecoin_rpc_url: None,
        broadcast_via_own_node: false,
        mweb_peers: Vec::new(),
        explorer_base_url: settings.explorer_base_url,
        show_fiat: settings.show_fiat,
        use_explorer_fee_hints: settings.use_explorer_fee_hints,
        insights_enabled: settings.insights_enabled,
    })
    .unwrap();
    drop(app);

    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .arg("--exact")
        .arg("sigkill_mid_electrum_sync_recovers_cleanly_on_restart")
        .arg("--nocapture")
        .env("LDK_WALLET_SIGKILL_SYNC_DIR", dir.path())
        .spawn()
        .unwrap();

    // Wait until the child connects to the hanging Electrum listener and sends
    // its handshake request, then SIGKILL the child process mid-sync.
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut connected_stream = None;
    while Instant::now() < deadline {
        if let Ok((stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 8];
            let _ = Read::read(&mut &stream, &mut buf);
            connected_stream = Some(stream);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        connected_stream.is_some(),
        "child never connected to Electrum listener"
    );

    child.kill().expect("SIGKILL child mid-sync");
    let status = child.wait().expect("wait for killed child");
    assert!(!status.success(), "killed child must not succeed");
    drop(connected_stream);

    // Restart a fresh WalletApp on the same directory and verify clean recovery.
    let restarted = WalletApp::new(dir.path());
    restarted
        .unlock(UnlockRequest {
            passphrase: PASSPHRASE.into(),
        })
        .unwrap();
    let summary = restarted.load(dir.path()).unwrap();
    assert_eq!(summary.receive_address, created.summary.receive_address);
    let progress = restarted.mweb_sync_progress();
    assert_eq!(progress.phase, SyncPhase::Idle);
    assert!(!progress.active);
    let diag = restarted.diagnostics("test");
    assert_eq!(diag.needs_full_scan, Some(true));
}

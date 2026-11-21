//! Secret hygiene, zeroization, and redaction checks (Hardening item 16).

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use wallet_core::{
    CreateWalletRequest, CreateWalletResponse, EncryptedFileSecretStore, MasterSecret,
    MigrateEncryptRequest, MwebScheme, RestoreWalletRequest, RevealMnemonicRequest,
    RevealMnemonicResponse, SecretStore, UnlockRequest, UnlockableSecretStore,
    UpdateSettingsRequest, WalletApp, WalletError, WalletNetwork, WalletSettings, WalletSummary,
};
use zeroize::Zeroize;

const TEST_PASSPHRASE: &str = "correct horse battery staple";
const TEST_BIP39: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const TEST_AEZEED_WORDS: &str = "absorb century submit father path glove gloom super divert garden ice mirror wisdom grass dice kit ugly castle success suggest drink monster congress flight";
const TEST_AEZEED_PASS: &str = "!very_safe_55345_password*";
const TEST_ROOT_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const TEST_CHILD_XPRV: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
// Chain code of TEST_ROOT_XPRV (BIP32 test vector 1).
const TEST_ROOT_CHAIN_CODE_HEX: &str =
    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

fn dummy_summary() -> WalletSummary {
    WalletSummary {
        network: WalletNetwork::Testnet,
        confirmed_sats: 0,
        trusted_pending_sats: 0,
        untrusted_pending_sats: 0,
        immature_sats: 0,
        total_sats: 0,
        tip_height: 0,
        tip_time: None,
        receive_address: "tltc1qexample".into(),
    }
}

#[test]
fn debug_impls_never_leak_secrets_or_rpc_credentials() {
    let bip39_secret = MasterSecret::parse(TEST_BIP39, None).expect("parse bip39");
    let bip39_dbg = format!("{bip39_secret:?}");
    assert!(
        !bip39_dbg.contains("abandon"),
        "Bip39 Debug leaked words: {bip39_dbg}"
    );

    let aezeed_secret =
        MasterSecret::parse(TEST_AEZEED_WORDS, Some(TEST_AEZEED_PASS)).expect("parse aezeed");
    let aezeed_dbg = format!("{aezeed_secret:?}");
    assert!(
        !aezeed_dbg.contains("absorb")
            && !aezeed_dbg.contains("century")
            && !aezeed_dbg.contains(TEST_AEZEED_PASS)
            && !aezeed_dbg.contains("81b637d8")
            && !aezeed_dbg.contains("129"),
        "Aezeed Debug leaked words, passphrase, or entropy: {aezeed_dbg}"
    );

    let xprv_secret = MasterSecret::parse(TEST_ROOT_XPRV, None).expect("parse xprv");
    let xprv_dbg = format!("{xprv_secret:?}");
    assert!(
        !xprv_dbg.contains("xprv9s21") && !xprv_dbg.contains(TEST_ROOT_CHAIN_CODE_HEX),
        "Xprv Debug leaked key or chain code: {xprv_dbg}"
    );

    let create_req = CreateWalletRequest {
        network: WalletNetwork::Testnet,
        electrum_url: Some("ssl://alice:electrumpw@electrum.example:50002".into()),
    };
    assert!(
        !format!("{create_req:?}").contains("electrumpw"),
        "CreateWalletRequest Debug leaked electrum password"
    );

    let create_resp = CreateWalletResponse {
        mnemonic: TEST_BIP39.into(),
        summary: dummy_summary(),
    };
    assert!(
        !format!("{create_resp:?}").contains("abandon"),
        "CreateWalletResponse Debug leaked mnemonic"
    );

    let restore_req = RestoreWalletRequest {
        mnemonic: TEST_AEZEED_WORDS.into(),
        network: WalletNetwork::Testnet,
        electrum_url: Some("ssl://alice:electrumpw@electrum.example:50002".into()),
        mweb_scheme: MwebScheme::LitecoinCore,
        aezeed_passphrase: Some("my-cipher-passphrase".into()),
    };
    let restore_dbg = format!("{restore_req:?}");
    assert!(
        !restore_dbg.contains("absorb")
            && !restore_dbg.contains("my-cipher-passphrase")
            && !restore_dbg.contains("electrumpw"),
        "RestoreWalletRequest Debug leaked secret: {restore_dbg}"
    );

    let unlock_req = UnlockRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    assert!(
        !format!("{unlock_req:?}").contains("battery"),
        "UnlockRequest Debug leaked passphrase"
    );

    let reveal_req = RevealMnemonicRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    assert!(
        !format!("{reveal_req:?}").contains("battery"),
        "RevealMnemonicRequest Debug leaked passphrase"
    );

    let reveal_resp = RevealMnemonicResponse {
        kind: "aezeed seed".into(),
        phrase: TEST_BIP39.into(),
        aezeed_passphrase: Some("my-cipher-passphrase".into()),
    };
    let reveal_resp_dbg = format!("{reveal_resp:?}");
    assert!(
        !reveal_resp_dbg.contains("abandon") && !reveal_resp_dbg.contains("my-cipher-passphrase"),
        "RevealMnemonicResponse Debug leaked phrase/passphrase: {reveal_resp_dbg}"
    );

    let migrate_req = MigrateEncryptRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    assert!(
        !format!("{migrate_req:?}").contains("battery"),
        "MigrateEncryptRequest Debug leaked passphrase"
    );

    let settings = WalletSettings {
        electrum_url: "ssl://bob:s3cr3t@electrum.example:50002".into(),
        electrum_validate_domain: true,
        electrum_use_public_fallback: false,
        auto_lock_minutes: 15,
        electrum_active_url: Some("ssl://bob:s3cr3t@electrum.example:50002".into()),
        litecoin_rpc_url: Some("http://rpcuser:rpcs3cr3t@127.0.0.1:9332".into()),
        broadcast_via_own_node: false,
        mweb_peers: vec![],
        mweb_scheme: MwebScheme::LitecoinCore,
        explorer_base_url: "https://expuser:exps3cr3t@litview.space".into(),
        show_fiat: true,
        use_explorer_fee_hints: true,
        insights_enabled: true,
    };
    let settings_dbg = format!("{settings:?}");
    assert!(
        !settings_dbg.contains("s3cr3t")
            && !settings_dbg.contains("rpcs3cr3t")
            && !settings_dbg.contains("exps3cr3t"),
        "WalletSettings Debug leaked URL credentials: {settings_dbg}"
    );

    let update_req = UpdateSettingsRequest {
        electrum_url: "ssl://bob:s3cr3t@electrum.example:50002".into(),
        electrum_validate_domain: true,
        electrum_use_public_fallback: false,
        auto_lock_minutes: 15,
        litecoin_rpc_url: Some("http://rpcuser:rpcs3cr3t@127.0.0.1:9332".into()),
        broadcast_via_own_node: false,
        mweb_peers: vec![],
        explorer_base_url: "https://expuser:exps3cr3t@litview.space".into(),
        show_fiat: true,
        use_explorer_fee_hints: true,
        insights_enabled: true,
    };
    let update_dbg = format!("{update_req:?}");
    assert!(
        !update_dbg.contains("s3cr3t")
            && !update_dbg.contains("rpcs3cr3t")
            && !update_dbg.contains("exps3cr3t"),
        "UpdateSettingsRequest Debug leaked URL credentials: {update_dbg}"
    );
}

#[test]
fn secret_dtos_zeroize_fields_in_place() {
    let mut create_resp = CreateWalletResponse {
        mnemonic: TEST_BIP39.into(),
        summary: dummy_summary(),
    };
    create_resp.zeroize();
    assert!(create_resp.mnemonic.is_empty());

    let mut restore_req = RestoreWalletRequest {
        mnemonic: TEST_AEZEED_WORDS.into(),
        network: WalletNetwork::Testnet,
        electrum_url: None,
        mweb_scheme: MwebScheme::LitecoinCore,
        aezeed_passphrase: Some(TEST_AEZEED_PASS.into()),
    };
    restore_req.zeroize();
    assert!(restore_req.mnemonic.is_empty());
    assert!(restore_req.aezeed_passphrase.is_none());

    let mut unlock_req = UnlockRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    unlock_req.zeroize();
    assert!(unlock_req.passphrase.is_empty());

    let mut reveal_req = RevealMnemonicRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    reveal_req.zeroize();
    assert!(reveal_req.passphrase.is_empty());

    let mut reveal_resp = RevealMnemonicResponse {
        kind: "BIP39 mnemonic".into(),
        phrase: TEST_BIP39.into(),
        aezeed_passphrase: Some(TEST_AEZEED_PASS.into()),
    };
    reveal_resp.zeroize();
    assert!(reveal_resp.phrase.is_empty());
    assert!(reveal_resp.aezeed_passphrase.is_none());

    let mut migrate_req = MigrateEncryptRequest {
        passphrase: TEST_PASSPHRASE.into(),
    };
    migrate_req.zeroize();
    assert!(migrate_req.passphrase.is_empty());
}

#[test]
fn seed_and_xprv_error_strings_never_echo_secret_inputs() {
    let mut words: Vec<&str> = vec!["abandon"; 24];
    words[7] = " accidentalSecretToken99 ";
    let input = words.join(" ");
    let err = MasterSecret::parse(&input, Some("cipher-pass")).expect_err("invalid word");
    let msg = err.to_string();
    assert!(
        !msg.contains("accidentalSecretToken99") && !msg.contains("cipher-pass"),
        "seed parse error echoed secret token: {msg}"
    );
    assert!(
        msg.contains("word 8"),
        "expected 1-based word position in error, got: {msg}"
    );

    let child_err = MasterSecret::parse(TEST_CHILD_XPRV, None)
        .expect_err("child xprv must be rejected")
        .to_string();
    assert!(
        !child_err.contains("xprv9uHR") && !child_err.contains(TEST_CHILD_XPRV),
        "child xprv error echoed key: {child_err}"
    );

    let corrupt_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrXXXX";
    let bad_err = MasterSecret::parse(corrupt_xprv, None)
        .expect_err("corrupt xprv must fail")
        .to_string();
    assert!(
        !bad_err.contains("xprv9s21"),
        "base58 error echoed corrupt xprv: {bad_err}"
    );
}

#[test]
fn reveal_mnemonic_while_locked_refuses_and_stays_locked() {
    let dir = tempdir().unwrap();
    let app = WalletApp::new(dir.path());
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
        TEST_PASSPHRASE,
    )
    .expect("create");

    app.lock();
    assert!(app.is_locked());

    let res = app.reveal_mnemonic(RevealMnemonicRequest {
        passphrase: TEST_PASSPHRASE.into(),
    });
    assert!(
        matches!(res, Err(WalletError::Locked)),
        "expected Locked error when calling reveal_mnemonic while locked, got {res:?}"
    );
    assert!(
        app.is_locked(),
        "failed/refused reveal_mnemonic must not leave secrets unlocked"
    );

    // Unlocking and passing a wrong passphrase must fail without revealing or crashing,
    // while keeping the active session intact until explicit lock.
    app.unlock(UnlockRequest {
        passphrase: TEST_PASSPHRASE.into(),
    })
    .expect("unlock");
    let bad = app.reveal_mnemonic(RevealMnemonicRequest {
        passphrase: "wrong passphrase".into(),
    });
    assert!(matches!(bad, Err(WalletError::IncorrectPassphrase)));
}

#[test]
fn lock_wipe_and_error_paths_clear_secrets_and_redact_diagnostics() {
    let dir = tempdir().unwrap();
    let app = WalletApp::new(dir.path());
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: Some("ssl://eluser:elsecret@electrum.example:50002".into()),
        },
        TEST_PASSPHRASE,
    )
    .expect("create");

    assert!(app.litvm_account_secret().is_ok());

    let bundle_loaded = app.diagnostics("0.4.16");
    let bundle_json = serde_json::to_string(&bundle_loaded).unwrap();
    assert!(
        !bundle_json.contains("elsecret") && !bundle_json.contains("eluser:"),
        "diagnostics bundle leaked electrum userinfo: {bundle_json}"
    );

    // Lock clears unlocked mnemonic, sealing key, and loaded state.
    app.lock();
    assert!(app.is_locked());
    assert!(matches!(
        app.litvm_account_secret(),
        Err(WalletError::Locked)
    ));
    assert!(matches!(app.summary(), Err(WalletError::Locked)));
    assert!(matches!(
        app.export_mweb_coinswapd_secrets(),
        Err(WalletError::Locked)
    ));

    // Wrong passphrase unlock fails closed and keeps secrets cleared.
    assert!(matches!(
        app.unlock(UnlockRequest {
            passphrase: "wrong".into(),
        }),
        Err(WalletError::IncorrectPassphrase)
    ));
    assert!(app.is_locked());
    assert!(matches!(
        app.litvm_account_secret(),
        Err(WalletError::Locked)
    ));

    // Wipe deletes mnemonic files and all accounts, leaving nothing recoverable in memory.
    app.wipe(dir.path()).expect("wipe");
    assert!(!app.exists(dir.path()));
    assert!(!dir.path().join(wallet_core::MNEMONIC_ENC_FILE).exists());
    assert!(!dir.path().join(wallet_core::MNEMONIC_FILE).exists());
    assert!(matches!(
        app.litvm_account_secret(),
        Err(WalletError::MissingMnemonic) | Err(WalletError::Locked)
    ));
}

#[test]
fn encrypted_store_error_and_wipe_paths_clear_mnemonic_and_sealing_key() {
    let dir = tempdir().unwrap();
    let enc = dir.path().join("wallet.mnemonic.enc");
    let plain = dir.path().join("wallet.mnemonic");
    let store = EncryptedFileSecretStore::new(&enc, &plain);

    // Empty passphrase rejected before creating anything.
    assert!(store.set_with_passphrase("", TEST_BIP39).is_err());
    assert!(store.sealing_key().is_none());
    assert!(store.get_mnemonic().unwrap().is_none());

    // Unwritable encrypted path (directory where file should be) fails closed.
    fs::create_dir_all(&enc).unwrap();
    assert!(store
        .set_with_passphrase(TEST_PASSPHRASE, TEST_BIP39)
        .is_err());
    assert!(store.sealing_key().is_none());
    fs::remove_dir_all(&enc).unwrap();

    // Valid write -> lock -> wrong passphrase -> delete_mnemonic (wipe).
    store
        .set_with_passphrase(TEST_PASSPHRASE, TEST_BIP39)
        .unwrap();
    assert!(store.sealing_key().is_some());
    assert!(store.get_mnemonic().unwrap().is_some());

    store.lock();
    assert!(store.is_locked());
    assert!(store.sealing_key().is_none());
    assert!(store.get_mnemonic().unwrap().is_none());

    assert!(matches!(
        store.unlock("incorrect"),
        Err(WalletError::IncorrectPassphrase)
    ));
    assert!(store.sealing_key().is_none());
    assert!(store.get_mnemonic().unwrap().is_none());

    // Re-unlock then delete_mnemonic wipes in-memory buffers and on-disk files.
    store.unlock(TEST_PASSPHRASE).unwrap();
    assert!(store.sealing_key().is_some());
    store.delete_mnemonic().unwrap();
    assert!(store.sealing_key().is_none());
    assert!(store.get_mnemonic().unwrap().is_none());
    assert!(!enc.exists());
}

#[test]
fn failed_create_rolls_back_encrypted_secret_and_state() {
    let dir = tempdir().unwrap();
    // Place a regular file at `accounts` so `accounts::init_registry_account0` fails
    // *after* `set_with_passphrase` wrote `wallet.mnemonic.enc`.
    fs::write(dir.path().join("accounts"), b"blocker").unwrap();

    let app = WalletApp::new(dir.path());
    let res = app.restore(
        dir.path(),
        RestoreWalletRequest {
            mnemonic: TEST_BIP39.into(),
            network: WalletNetwork::Testnet,
            electrum_url: None,
            mweb_scheme: MwebScheme::LitecoinCore,
            aezeed_passphrase: None,
        },
        TEST_PASSPHRASE,
    );
    assert!(
        res.is_err(),
        "restore must fail when wallets path is blocked"
    );
    assert!(
        !dir.path().join(wallet_core::MNEMONIC_ENC_FILE).exists(),
        "rollback must remove wallet.mnemonic.enc on failed create/restore"
    );
    assert!(
        matches!(
            app.litvm_account_secret(),
            Err(WalletError::MissingMnemonic) | Err(WalletError::Locked)
        ),
        "rollback must clear in-memory unlocked mnemonic and sealing key"
    );
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name != "target" && !name.starts_with('.') {
                collect_rs_files(&path, out);
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn extract_item_name<'a>(line: &'a str, kw: &str) -> Option<&'a str> {
    let pos = line.find(kw)?;
    if pos > 0 {
        let prev = line[..pos].chars().next_back().unwrap();
        if is_ident_char(prev) {
            return None;
        }
    }
    let rest = line[pos + kw.len()..].trim_start();
    let end = rest.find(|c: char| !is_ident_char(c)).unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(&rest[..end])
    }
}

#[test]
fn sensitive_types_and_fields_do_not_derive_debug() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    collect_rs_files(&repo_root.join("crates"), &mut files);
    collect_rs_files(&repo_root.join("src-tauri/src"), &mut files);
    files.sort();

    const SENSITIVE_TYPES: &[&str] = &[
        "MasterSecret",
        "DecodedAezeed",
        "ZeroizingSigner",
        "CreateWalletRequest",
        "CreateWalletResponse",
        "RestoreWalletRequest",
        "UnlockRequest",
        "RevealMnemonicRequest",
        "RevealMnemonicResponse",
        "MigrateEncryptRequest",
        "WalletSettings",
        "UpdateSettingsRequest",
        "WalletMeta",
        "BroadcastRoute",
        "ArmedHop",
        "PreparedHop",
        "LitVmClient",
        "LitVmSettings",
        "LitVmSettingsFile",
        "LitVmSummary",
        "LitVmProbe",
        "UpdateLitVmSettingsRequest",
        "Cli",
        "Command",
    ];

    const SENSITIVE_FIELDS: &[&str] = &[
        "mnemonic",
        "unlocked_mnemonic",
        "passphrase",
        "aezeed_passphrase",
        "sealing_key",
        "spend_key",
        "private_key",
        "entropy",
        "raw_hex",
        "created_coin",
        "litecoin_rpc_url",
        "rpc_http_override",
    ];

    let mut violations = Vec::new();
    for file in &files {
        let content = fs::read_to_string(file).expect("read rust source");
        let lines: Vec<&str> = content.lines().collect();
        let rel = file.strip_prefix(&repo_root).unwrap_or(file);
        let mut pending_derive_debug = false;
        let mut idx = 0usize;
        while idx < lines.len() {
            let line = lines[idx].trim();
            if line.starts_with("#[") {
                if line.contains("derive(")
                    && line
                        .split(|c: char| !is_ident_char(c))
                        .any(|tok| tok == "Debug")
                {
                    pending_derive_debug = true;
                }
                idx += 1;
                continue;
            }
            if line.starts_with("///") || line.starts_with("//") || line.is_empty() {
                idx += 1;
                continue;
            }

            if pending_derive_debug {
                let item =
                    extract_item_name(line, "struct ").or_else(|| extract_item_name(line, "enum "));
                if let Some(ty) = item {
                    if SENSITIVE_TYPES.contains(&ty) {
                        violations.push(format!(
                            "{}:{}: derived Debug on sensitive type `{ty}`",
                            rel.display(),
                            idx + 1
                        ));
                    }
                    // Scan the body up to matching `}` for sensitive field identifiers.
                    if line.contains('{') {
                        let mut depth = 0i32;
                        let mut scan = idx;
                        while scan < lines.len() {
                            let body_line = lines[scan].trim();
                            for ch in body_line.chars() {
                                if ch == '{' {
                                    depth += 1;
                                } else if ch == '}' {
                                    depth -= 1;
                                }
                            }
                            if scan > idx
                                && !body_line.starts_with("//")
                                && !body_line.starts_with('#')
                            {
                                let field_part = body_line
                                    .strip_prefix("pub(crate) ")
                                    .or_else(|| body_line.strip_prefix("pub "))
                                    .unwrap_or(body_line);
                                if let Some((fname, _)) = field_part.split_once(':') {
                                    let fname = fname.trim();
                                    if SENSITIVE_FIELDS.contains(&fname) {
                                        violations.push(format!(
                                            "{}:{}: `{ty}` derives Debug while holding sensitive field `{fname}`",
                                            rel.display(),
                                            scan + 1
                                        ));
                                    }
                                }
                            }
                            if depth <= 0 {
                                break;
                            }
                            scan += 1;
                        }
                    }
                }
            }
            pending_derive_debug = false;
            idx += 1;
        }
    }

    assert!(
        violations.is_empty(),
        "sensitive types/fields must implement manual redacted fmt::Debug instead of #[derive(Debug)]:\n{}",
        violations.join("\n")
    );
}

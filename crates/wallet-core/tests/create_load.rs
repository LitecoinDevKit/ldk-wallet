use std::sync::Arc;

use tempfile::tempdir;
use wallet_core::{
    CreateWalletRequest, MemoryBackedApp, MemoryStore, RestoreWalletRequest, SecretStore,
    SendRequest, SetTxLabelRequest, SetUtxoLockedRequest, SplitChain, SplitRequest, WalletError,
    WalletNetwork,
};

fn with_secrets(secrets: Arc<dyn SecretStore>) -> MemoryBackedApp {
    wallet_core::WalletApp::with_secrets(secrets)
}

#[test]
fn create_testnet_returns_tltc_address_and_mnemonic() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));

    let resp = app
        .create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
        )
        .expect("create");

    assert_eq!(resp.mnemonic.split_whitespace().count(), 12);
    assert!(
        resp.summary.receive_address.starts_with("tltc1"),
        "got {}",
        resp.summary.receive_address
    );
    assert_eq!(resp.summary.network, WalletNetwork::Testnet);
    assert_eq!(resp.summary.total_sats, 0);
    assert!(app.exists(dir.path()));
}

#[test]
fn create_then_load_round_trip() {
    let dir = tempdir().unwrap();
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());

    let created = {
        let app = with_secrets(Arc::clone(&secrets));
        app.create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: Some("ssl://example.invalid:51002".into()),
            },
        )
        .expect("create")
    };

    let loaded = {
        let app = with_secrets(secrets);
        app.load(dir.path()).expect("load")
    };

    assert_eq!(loaded.network, WalletNetwork::Testnet);
    assert_eq!(loaded.receive_address, created.summary.receive_address);
    assert_eq!(loaded.total_sats, 0);
}

#[test]
fn second_create_fails_already_exists() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    let req = CreateWalletRequest {
        network: WalletNetwork::Testnet,
        electrum_url: None,
    };
    app.create(dir.path(), req.clone()).expect("first create");

    let err = app.create(dir.path(), req).expect_err("second create");
    assert!(matches!(err, WalletError::AlreadyExists));
}

#[test]
fn restore_known_mnemonic_is_deterministic() {
    let mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let summary_a = {
        let app = with_secrets(Arc::new(MemoryStore::new()));
        app.restore(
            dir_a.path(),
            RestoreWalletRequest {
                mnemonic: mnemonic.into(),
                network: WalletNetwork::Testnet,
                electrum_url: None,
                mweb_scheme: Default::default(),
                aezeed_passphrase: None,
            },
        )
        .expect("restore a")
    };

    let summary_b = {
        let app = with_secrets(Arc::new(MemoryStore::new()));
        app.restore(
            dir_b.path(),
            RestoreWalletRequest {
                mnemonic: mnemonic.into(),
                network: WalletNetwork::Testnet,
                electrum_url: None,
                mweb_scheme: Default::default(),
                aezeed_passphrase: None,
            },
        )
        .expect("restore b")
    };

    assert!(summary_a.receive_address.starts_with("tltc1"));
    assert_eq!(summary_a.receive_address, summary_b.receive_address);
}

#[test]
fn receive_address_advances_and_summary_keeps_it() {
    let dir = tempdir().unwrap();
    let secrets: Arc<dyn SecretStore> = Arc::new(MemoryStore::new());
    let app = with_secrets(Arc::clone(&secrets));
    let created = app
        .create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
        )
        .expect("create");

    let first = created.summary.receive_address;
    let second = app.receive_address().expect("new address");
    let third = app.receive_address().expect("another address");

    assert_ne!(first, second);
    assert_ne!(second, third);
    assert!(second.starts_with("tltc1"));
    assert_eq!(app.summary().expect("summary").receive_address, third);

    let reloaded = {
        let app = with_secrets(secrets);
        app.load(dir.path()).expect("load")
    };
    assert_eq!(reloaded.receive_address, third);
}

#[test]
fn send_rejects_invalid_address() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    let err = app
        .send(SendRequest {
            address: "not-an-address".into(),
            amount_sats: 1000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: None,
        })
        .expect_err("invalid address");
    assert!(matches!(err, WalletError::InvalidAddress(_)));
}

#[test]
fn create_after_orphaned_db_wipes_and_succeeds() {
    let dir = tempdir().unwrap();
    let secrets = Arc::new(MemoryStore::new());
    let app = with_secrets(Arc::clone(&secrets) as Arc<dyn SecretStore>);
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    secrets.delete_mnemonic().unwrap();
    assert!(app.exists(dir.path()));
    assert!(matches!(
        app.load(dir.path()).unwrap_err(),
        WalletError::MissingMnemonic
    ));
    // The first app still holds wallet.sqlite. Unix can unlink an open file;
    // Windows cannot (os error 32). Drop it before the replacement create wipes.
    drop(app);

    let app2 = with_secrets(secrets);
    let resp = app2
        .create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
        )
        .expect("create after orphan wipe");
    assert!(resp.summary.receive_address.starts_with("tltc1"));
}

#[test]
fn create_marks_needs_full_scan_in_meta() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    let meta_path = dir.path().join("wallet_meta.json");
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(meta_path).unwrap()).unwrap();
    assert_eq!(meta["needs_full_scan"], true);
}

#[test]
fn address_reuse_hint_unused_used_and_mweb() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    let created = app
        .create(
            dir.path(),
            CreateWalletRequest {
                network: WalletNetwork::Testnet,
                electrum_url: None,
            },
        )
        .expect("create");
    let addr = created.summary.receive_address;

    assert!(
        !app.address_reuse_hint(&addr).expect("hint").reused,
        "fresh unused receive address must not warn"
    );
    assert!(
        !app.address_reuse_hint("ltcmweb1qqtestreuse")
            .expect("mweb")
            .reused,
        "MWEB stealth must never warn"
    );
    assert!(
        !app.address_reuse_hint("tltc1qnotours")
            .expect("foreign")
            .reused
    );

    app.mark_external_used(0).expect("mark used");
    assert!(
        app.address_reuse_hint(&addr)
            .expect("hint after use")
            .reused,
        "marked-used receive address should warn"
    );
}

#[test]
fn tx_labels_round_trip_and_wipe() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    app.set_tx_label(SetTxLabelRequest {
        txid: "deadbeef".into(),
        label: " coffee ".into(),
    })
    .unwrap();
    let labels = app.get_tx_labels().unwrap();
    assert_eq!(labels.get("deadbeef").map(String::as_str), Some("coffee"));
    assert!(dir.path().join("tx_labels.json").is_file());

    app.wipe(dir.path()).unwrap();
    assert!(!dir.path().join("tx_labels.json").is_file());
}

#[test]
fn mweb_frozen_and_label_wipe() {
    use wallet_core::{SetMwebUtxoLockedRequest, SetUtxoLabelRequest};
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    let id = "ab".repeat(32);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: id.clone(),
        locked: true,
    })
    .unwrap();
    app.set_utxo_label(SetUtxoLabelRequest {
        outpoint: id,
        label: "savings".into(),
    })
    .unwrap();
    assert!(dir.path().join("mweb_frozen.json").is_file());
    assert!(dir.path().join("utxo_labels.json").is_file());
    app.wipe(dir.path()).unwrap();
    assert!(!dir.path().join("mweb_frozen.json").is_file());
    assert!(!dir.path().join("utxo_labels.json").is_file());
}

#[test]
fn contacts_round_trip_and_wipe() {
    use wallet_core::{ContactKind, DeleteContactRequest, UpsertContactRequest};

    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    let address = app.receive_address().unwrap();
    let contact = app
        .upsert_contact(UpsertContactRequest {
            id: None,
            name: " Alice ".into(),
            address: address.clone(),
            kind: ContactKind::Public,
        })
        .unwrap();
    assert_eq!(contact.name, "Alice");
    assert_eq!(contact.address, address);
    assert!(dir.path().join("contacts.json").is_file());

    let listed = app.list_contacts().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, contact.id);

    app.delete_contact(DeleteContactRequest {
        id: contact.id.clone(),
    })
    .unwrap();
    assert!(app.list_contacts().unwrap().is_empty());
    assert!(!dir.path().join("contacts.json").is_file());

    app.upsert_contact(UpsertContactRequest {
        id: None,
        name: "Bob".into(),
        address,
        kind: ContactKind::Public,
    })
    .unwrap();
    assert!(dir.path().join("contacts.json").is_file());
    app.wipe(dir.path()).unwrap();
    assert!(!dir.path().join("contacts.json").is_file());
}

#[test]
fn pegin_manual_selection_rejects_unknown_outpoint() {
    use wallet_core::PeginRequest;

    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    let unknown_err = app
        .preview_pegin(PeginRequest {
            amount_sats: 10_000,
            mweb_fee_sats: 0,
            transparent_fee_sats: 500,
            drain: false,
            selected_outpoints: Some(vec![
                "0000000000000000000000000000000000000000000000000000000000000000:0".into(),
            ]),
        })
        .expect_err("unknown outpoint");
    assert!(
        unknown_err.to_string().contains("not an unspent"),
        "got {unknown_err}"
    );

    // Drain + selection is allowed (100% of selected coins); unknown outpoint still fails.
    let drain_unknown = app
        .preview_pegin(PeginRequest {
            amount_sats: 0,
            mweb_fee_sats: 0,
            transparent_fee_sats: 500,
            drain: true,
            selected_outpoints: Some(vec![
                "0000000000000000000000000000000000000000000000000000000000000000:0".into(),
            ]),
        })
        .expect_err("unknown outpoint with drain");
    assert!(
        drain_unknown.to_string().contains("not an unspent"),
        "got {drain_unknown}"
    );
}

#[test]
fn list_unspent_empty_on_new_wallet() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    assert!(app.list_unspent().unwrap().is_empty());
}

#[test]
fn manual_selection_rejects_unknown_outpoint() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    let address = app.receive_address().unwrap();

    let unknown_err = app
        .send(SendRequest {
            address: address.clone(),
            amount_sats: 10_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: Some(vec![
                "0000000000000000000000000000000000000000000000000000000000000000:0".into(),
            ]),
        })
        .expect_err("unknown outpoint");
    assert!(
        unknown_err.to_string().contains("not an unspent"),
        "got {unknown_err}"
    );

    // Drain + selection is allowed (100% of selected coins); unknown outpoint still fails.
    let drain_unknown = app
        .send(SendRequest {
            address,
            amount_sats: 0,
            fee_rate_sat_vb: Some(1),
            drain: true,
            selected_outpoints: Some(vec![
                "0000000000000000000000000000000000000000000000000000000000000000:0".into(),
            ]),
        })
        .expect_err("unknown outpoint with drain");
    assert!(
        drain_unknown.to_string().contains("not an unspent"),
        "got {drain_unknown}"
    );
}

#[test]
fn coin_control_list_lock_and_manual_select() {
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, BlockHash};
    use bdk_wallet::chain::BlockId;
    use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};

    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();

    let outpoint = app
        .with_wallet_mut(|wallet, db| {
            insert_checkpoint(
                wallet,
                BlockId {
                    height: 1,
                    hash: BlockHash::all_zeros(),
                },
            );
            let op = receive_output_in_latest_block(wallet, Amount::from_sat(100_000));
            wallet
                .persist(db)
                .map_err(|e| WalletError::Persist(e.to_string()))?;
            Ok(op.to_string())
        })
        .unwrap();

    let utxos = app.list_unspent().unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].outpoint, outpoint);
    assert_eq!(utxos[0].amount_sats, 100_000);
    assert!(!utxos[0].locked);

    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outpoint.clone(),
        locked: true,
    })
    .unwrap();
    let locked = app.list_unspent().unwrap();
    assert!(locked[0].locked);

    let dest = app.receive_address().unwrap();
    let frozen_err = app
        .send(SendRequest {
            address: dest.clone(),
            amount_sats: 50_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: Some(vec![outpoint.clone()]),
        })
        .expect_err("frozen selected");
    assert!(
        frozen_err.to_string().contains("frozen"),
        "got {frozen_err}"
    );

    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outpoint.clone(),
        locked: false,
    })
    .unwrap();

    // Manual selection builds a PSBT; memory app then refuses to broadcast.
    let broadcast_err = app
        .send(SendRequest {
            address: dest,
            amount_sats: 50_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: Some(vec![outpoint]),
        })
        .expect_err("no broadcast");
    assert!(
        matches!(broadcast_err, WalletError::Electrum(_)),
        "expected build success then electrum stub, got {broadcast_err}"
    );
}

fn fund_confirmed_utxo(app: &MemoryBackedApp, amount_sats: u64) -> String {
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::{Amount, BlockHash};
    use bdk_wallet::chain::BlockId;
    use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};

    app.with_wallet_mut(|wallet, db| {
        insert_checkpoint(
            wallet,
            BlockId {
                height: 1,
                hash: BlockHash::all_zeros(),
            },
        );
        let op = receive_output_in_latest_block(wallet, Amount::from_sat(amount_sats));
        wallet
            .persist(db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        Ok(op.to_string())
    })
    .unwrap()
}

#[test]
fn public_equal_split_is_one_input() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    let outpoint = fund_confirmed_utxo(&app, 1_000_000);
    let req = SplitRequest {
        chain: SplitChain::Public,
        input: outpoint,
        equal_count: Some(3),
        amounts: vec![],
        fee_rate_sat_vb: Some(1),
        fee_sats: 0,
    };
    let preview = app.preview_split(req.clone()).unwrap();
    assert_eq!(preview.outputs.len(), 3);
    assert!(!preview.creates_change);
    let sum: u64 = preview.outputs.iter().map(|o| o.amount_sats).sum();
    assert_eq!(sum + preview.fee_sats, 1_000_000);

    let (n_in, n_out, fee) = app.public_split_io_count(req).unwrap();
    assert_eq!(n_in, 1, "split must spend exactly one coin");
    assert_eq!(n_out, 3);
    assert_eq!(fee, preview.fee_sats);
}

#[test]
fn public_split_refuses_second_wallet_coin() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    let first = fund_confirmed_utxo(&app, 1_000_000);
    let _second = fund_confirmed_utxo(&app, 800_000);
    assert_eq!(app.list_unspent().unwrap().len(), 2);
    let (n_in, _, _) = app
        .public_split_io_count(SplitRequest {
            chain: SplitChain::Public,
            input: first,
            equal_count: Some(2),
            amounts: vec![],
            fee_rate_sat_vb: Some(1),
            fee_sats: 0,
        })
        .unwrap();
    assert_eq!(n_in, 1);
}

#[test]
fn public_denom_split_change_and_frozen() {
    let dir = tempdir().unwrap();
    let app = with_secrets(Arc::new(MemoryStore::new()));
    app.create(
        dir.path(),
        CreateWalletRequest {
            network: WalletNetwork::Testnet,
            electrum_url: None,
        },
    )
    .unwrap();
    let outpoint = fund_confirmed_utxo(&app, 1_000_000);
    let preview = app
        .preview_split(SplitRequest {
            chain: SplitChain::Public,
            input: outpoint.clone(),
            equal_count: None,
            amounts: vec![100_000, 100_000],
            fee_rate_sat_vb: Some(1),
            fee_sats: 0,
        })
        .unwrap();
    assert!(preview.creates_change);
    assert!(preview.change_sats >= 2940);
    let (n_in, n_out, _) = app
        .public_split_io_count(SplitRequest {
            chain: SplitChain::Public,
            input: outpoint.clone(),
            equal_count: None,
            amounts: vec![100_000, 100_000],
            fee_rate_sat_vb: Some(1),
            fee_sats: preview.fee_sats,
        })
        .unwrap();
    assert_eq!(n_in, 1);
    assert_eq!(n_out, 3); // two denoms + change

    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outpoint.clone(),
        locked: true,
    })
    .unwrap();
    let err = app
        .preview_split(SplitRequest {
            chain: SplitChain::Public,
            input: outpoint,
            equal_count: Some(2),
            amounts: vec![],
            fee_rate_sat_vb: Some(1),
            fee_sats: 0,
        })
        .unwrap_err();
    assert!(err.to_string().contains("frozen"), "got {err}");
}

#[test]
fn file_secret_store_roundtrip() {
    use wallet_core::FileSecretStore;
    let dir = tempdir().unwrap();
    let path = dir.path().join("wallet.mnemonic");
    let store = FileSecretStore::new(&path);
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    store.set_mnemonic(phrase).expect("set");
    let got = store.get_mnemonic().expect("get");
    assert_eq!(got.as_deref(), Some(phrase));
    let store2 = FileSecretStore::new(&path);
    assert_eq!(store2.get_mnemonic().unwrap().as_deref(), Some(phrase));
    store2.delete_mnemonic().expect("delete");
    assert_eq!(store2.get_mnemonic().unwrap(), None);
}

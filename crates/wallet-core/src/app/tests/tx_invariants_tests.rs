//! Regression and property tests for transaction construction and value invariants (item 18).

use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::{Address, Amount, BlockHash, Network, ScriptBuf};
use bdk_wallet::chain::BlockId;
use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};
use bdk_wallet::KeychainKind;

use super::super::*;
use super::{app_with_private_coins, app_with_public_coins};
use crate::dto::{
    ChurnRequest, MwebSendRequest, PeginRequest, PegoutRequest, SendRequest, SetUtxoLockedRequest,
    SplitChain, SplitOutput, SplitPreview, SplitRequest, TxKind,
};
use crate::mweb_history::MwebHistoryEntry;

/// F1: Public send (`drain: true` or `drain: false`) must never accept an MWEB
/// stealth address (`script_pubkey() == ScriptBuf::new()`, anyone-can-spend!) or
/// a witness-v8/v9 MWEB bridge script.
#[test]
fn f1_public_send_rejects_mweb_stealth_and_bridge_scripts_including_drain() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _outs) = app_with_public_coins(dir.path(), &[1_000_000]);
    let mweb_addr = app.mweb_receive_address().unwrap();

    // Drain to an MWEB stealth address previously bypassed `add_recipient` and
    // built a transaction with an empty 0-byte `scriptPubKey` (anyone-can-spend).
    for drain in [true, false] {
        let res = app.preview_send(SendRequest {
            address: mweb_addr.clone(),
            amount_sats: 100_000,
            fee_rate_sat_vb: Some(1),
            drain,
            selected_outpoints: None,
        });
        assert!(
            res.is_err(),
            "public send (drain={drain}) accepted MWEB stealth address {mweb_addr}: {res:?}"
        );
    }

    // Witness v8 (HogAddr) and v9 (peg-in) bridge scripts are non-standard on
    // public sends without an MWEB kernel and would strand funds.
    for opcode in [0x58u8, 0x59u8] {
        let mut bytes = vec![opcode, 0x20];
        bytes.extend_from_slice(&[0x42u8; 32]);
        let spk = ScriptBuf::from_bytes(bytes);
        let bridge_addr = Address::from_script(&spk, Network::Testnet4)
            .expect("v8/v9 witness address")
            .to_string();
        for drain in [true, false] {
            let res = app.preview_send(SendRequest {
                address: bridge_addr.clone(),
                amount_sats: 100_000,
                fee_rate_sat_vb: Some(1),
                drain,
                selected_outpoints: None,
            });
            assert!(
                res.is_err(),
                "public send (drain={drain}) accepted {opcode:#x} bridge address {bridge_addr}: {res:?}"
            );
        }
    }
}

/// F2: `rust-litecoin` defines `DUST_RELAY_TX_FEE = 3_000` (294 litoshis for P2WPKH)
/// instead of Litecoin Core's 30 sat/vB (`2,940` litoshis for P2WPKH).
/// Public sends and peg-ins must never emit a change or drain output below `2,940` litoshis.
#[test]
fn f2_public_send_and_pegin_never_emit_sub_ltc_dust_change_or_drain() {
    // 1 P2WPKH input (68 vB) + 2 P2WPKH outputs (62 vB) + header (11 vB) = 141 vB.
    // With a 11,141-litoshi UTXO and a 10,000-litoshi send at 1 sat/vB, remaining after
    // change fee is 1,000 litoshis (>= 294 Bitcoin dust, < 2,940 Litecoin dust).
    let dir = tempfile::tempdir().unwrap();
    let (app, _outs) = app_with_public_coins(dir.path(), &[11_141]);
    let dest = app.receive_address().unwrap();
    let preview = app
        .preview_send(SendRequest {
            address: dest.clone(),
            amount_sats: 10_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: None,
        })
        .unwrap();
    assert!(
        !preview.creates_change,
        "1,000-litoshi leftover must be folded into fee, not emitted as sub-dust change: {preview:?}"
    );
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        let (_, psbt, _) = build_send_psbt(
            state,
            &SendRequest {
                address: dest.clone(),
                amount_sats: 10_000,
                fee_rate_sat_vb: Some(1),
                drain: false,
                selected_outpoints: None,
            },
        )
        .unwrap();
        for out in &psbt.unsigned_tx.output {
            let ltc_dust = bdk_mweb::policy::dust_threshold(&out.script_pubkey);
            assert!(
                out.value.to_sat() >= ltc_dust,
                "output {} is below Litecoin dust threshold {ltc_dust}",
                out.value.to_sat()
            );
        }
    }

    // Drain of a 1,500-litoshi UTXO leaves ~1,390 litoshis (< 2,940 Litecoin dust) and must fail.
    let dir_small = tempfile::tempdir().unwrap();
    let (app_small, _) = app_with_public_coins(dir_small.path(), &[1_500]);
    let dest_small = app_small.receive_address().unwrap();
    let drain_res = app_small.preview_send(SendRequest {
        address: dest_small,
        amount_sats: 0,
        fee_rate_sat_vb: Some(1),
        drain: true,
        selected_outpoints: None,
    });
    assert!(
        drain_res.is_err(),
        "draining 1,500 litoshis (< 2,940 dust) must be rejected: {drain_res:?}"
    );
}

/// F3: Peg-in must exclude user-frozen UTXOs from spendable funds, enforce v9 dust (3,300)
/// and MWEB weight minimum fee (2,100), and compute `creates_change` accurately.
#[test]
fn f3_pegin_excludes_frozen_utxos_and_checks_v9_dust_and_change() {
    let dir = tempfile::tempdir().unwrap();
    let (app, outs) = app_with_public_coins(dir.path(), &[1_000_000, 2_000_000]);
    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outs[1].to_string(),
        locked: true,
    })
    .unwrap();

    // Only 1,000,000 is unfrozen; requesting 1,500,000 must fail in preview_pegin.
    let res = app.preview_pegin(PeginRequest {
        amount_sats: 1_500_000,
        mweb_fee_sats: crate::tx_invariants::min_kernel_fee(1, std::iter::empty()),
        transparent_fee_sats: 500,
        drain: false,
        selected_outpoints: None,
    });
    assert!(
        res.is_err(),
        "preview_pegin counted frozen 2M UTXO toward spendable balance: {res:?}"
    );

    // Explicit MWEB fee below min_mweb_fee(mweb_weight(1, [])) = 2,100 must fail in preview_pegin.
    let low_mweb_fee = app.preview_pegin(PeginRequest {
        amount_sats: 100_000,
        mweb_fee_sats: 100,
        transparent_fee_sats: 500,
        drain: false,
        selected_outpoints: None,
    });
    assert!(
        low_mweb_fee.is_err(),
        "preview_pegin accepted mweb_fee_sats=100 (< 2,100 weight floor): {low_mweb_fee:?}"
    );

    // Peg-in output below v9 dust (3,300 litoshis) must fail in preview_pegin.
    let sub_v9_dust = app.preview_pegin(PeginRequest {
        amount_sats: 2_500,
        mweb_fee_sats: 2_100,
        transparent_fee_sats: 500,
        drain: false,
        selected_outpoints: None,
    });
    assert!(
        sub_v9_dust.is_err(),
        "preview_pegin accepted amount_sats=2,500 (< 3,300 v9 dust): {sub_v9_dust:?}"
    );

    // Auto-selected peg-in of 100,000 from a 1,000,000 UTXO creates change.
    let auto_preview = app
        .preview_pegin(PeginRequest {
            amount_sats: 100_000,
            mweb_fee_sats: crate::tx_invariants::min_kernel_fee(1, std::iter::empty()),
            transparent_fee_sats: 500,
            drain: false,
            selected_outpoints: None,
        })
        .unwrap();
    assert!(
        auto_preview.creates_change,
        "100k peg-in from 1M UTXO creates change, but preview reported false"
    );
}

/// F4: Duplicate manual coin IDs must be deduplicated rather than double-counted.
#[test]
fn f4_duplicate_selected_coin_ids_do_not_double_count_balance() {
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[100_000]);
    let mweb_dest = app.mweb_receive_address().unwrap();

    // Single coin is 100,000; 80,000 + 50,000 fee = 130,000 > 100,000.
    // Passing the same coin ID twice must not sum to 200,000.
    let res = app.preview_mweb_send(MwebSendRequest {
        address: mweb_dest,
        amount_sats: 80_000,
        fee_sats: 50_000,
        drain: false,
        selected_output_ids: Some(vec![ids[0].clone(), ids[0].clone()]),
    });
    assert!(
        res.is_err(),
        "duplicate selected_output_ids double-counted a 100k coin: {res:?}"
    );

    let dir_pub = tempfile::tempdir().unwrap();
    let (app_pub, outs) = app_with_public_coins(dir_pub.path(), &[100_000]);
    let res_pegin = app_pub.preview_pegin(PeginRequest {
        amount_sats: 120_000,
        mweb_fee_sats: crate::tx_invariants::min_kernel_fee(1, std::iter::empty()),
        transparent_fee_sats: 500,
        drain: false,
        selected_outpoints: Some(vec![outs[0].to_string(), outs[0].to_string()]),
    });
    assert!(
        res_pegin.is_err(),
        "duplicate selected_outpoints double-counted a 100k UTXO in preview_pegin: {res_pegin:?}"
    );
}

/// F5: `preview_mweb_send` must reject transparent addresses and `preview_pegout`
/// must reject MWEB stealth or empty addresses.
#[test]
fn f5_mweb_send_and_pegout_previews_enforce_address_kind_and_fee_floors() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    let pub_addr = app.receive_address().unwrap();
    let mweb_addr = app.mweb_receive_address().unwrap();

    let send_to_pub = app.preview_mweb_send(MwebSendRequest {
        address: pub_addr.clone(),
        amount_sats: 100_000,
        fee_sats: crate::tx_invariants::min_kernel_fee(2, std::iter::empty()),
        drain: false,
        selected_output_ids: None,
    });
    assert!(
        send_to_pub.is_err(),
        "preview_mweb_send accepted a transparent address {pub_addr}: {send_to_pub:?}"
    );

    let pegout_to_mweb = app.preview_pegout(PegoutRequest {
        address: mweb_addr.clone(),
        amount_sats: 100_000,
        fee_sats: crate::tx_invariants::min_kernel_fee(2, std::iter::empty()),
        drain: false,
        selected_output_ids: None,
        output_amounts: Vec::new(),
        addresses: Vec::new(),
        per_coin: false,
        fee_output_index: None,
    });
    assert!(
        pegout_to_mweb.is_err(),
        "preview_pegout accepted an MWEB stealth address {mweb_addr}: {pegout_to_mweb:?}"
    );

    let pegout_empty = app.preview_pegout(PegoutRequest {
        address: String::new(),
        amount_sats: 100_000,
        fee_sats: crate::tx_invariants::min_kernel_fee(2, std::iter::empty()),
        drain: false,
        selected_output_ids: None,
        output_amounts: Vec::new(),
        addresses: Vec::new(),
        per_coin: false,
        fee_output_index: None,
    });
    assert!(
        pegout_empty.is_err(),
        "preview_pegout accepted an empty destination on typed pegout: {pegout_empty:?}"
    );
}

/// F6: `merge_mweb_history` must not panic when `entry.net_sats == i64::MIN`.
#[test]
fn f6_merge_mweb_history_handles_i64_min_without_overflow_panic() {
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
        id: "extreme-neg".into(),
        kind: TxKind::MwebSend,
        net_sats: i64::MIN,
        fee_sats: Some(100),
        timestamp: 1_700_000_000,
        output_ids: Vec::new(),
        input_ids: Vec::new(),
        confirmed_height: Some(10),
    });
    let mut records = Vec::new();
    merge_mweb_history(&mut records, &mweb, 20);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sent_sats, i64::MIN.unsigned_abs());
}

/// F7: Failed splits, peg-outs, transfers, and multi-hop self-spends must not
/// advance or persist external or MWEB receive indices before building & signing succeed.
#[test]
fn f7_failed_builds_and_signs_do_not_advance_receive_indices() {
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[60_000]);
    let outpoint = {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        insert_checkpoint(
            &mut state.wallet,
            BlockId {
                height: 1,
                hash: BlockHash::all_zeros(),
            },
        );
        let op = receive_output_in_latest_block(&mut state.wallet, Amount::from_sat(100_000));
        state.wallet.persist(&mut state.db).unwrap();
        op
    };

    let mut guard = app.lock_state().unwrap();
    let state = guard.as_mut().unwrap();
    let ext_before = state.wallet.derivation_index(KeychainKind::External);
    let mweb_idx_before = state.mweb.as_ref().unwrap().receive_index;

    // 1. Public split with mismatched preview fee fails inside build_public_split_psbt.
    let bad_preview = SplitPreview {
        input_sats: 100_000,
        outputs: vec![
            SplitOutput {
                amount_sats: 40_000,
                is_change: false,
            },
            SplitOutput {
                amount_sats: 40_000,
                is_change: false,
            },
        ],
        fee_sats: 20_000,
        fee_rate_sat_vb: 1,
        change_sats: 0,
        creates_change: false,
    };
    // Force failure by passing an unknown outpoint or a fee mismatch where recipients exceed input:
    let over_preview = SplitPreview {
        input_sats: 100_000,
        outputs: vec![
            SplitOutput {
                amount_sats: 60_000,
                is_change: false,
            },
            SplitOutput {
                amount_sats: 60_000,
                is_change: false,
            },
        ],
        fee_sats: bad_preview.fee_sats,
        fee_rate_sat_vb: 1,
        change_sats: 0,
        creates_change: false,
    };
    assert!(build_public_split_psbt(state, &outpoint.to_string(), &over_preview).is_err());
    assert_eq!(
        state.wallet.derivation_index(KeychainKind::External),
        ext_before,
        "failed build_public_split_psbt burned external derivation indices"
    );

    // 2. Private split with fee below MWEB minimum fails inside sign_mweb_split.
    let data_dir = state.data_dir.clone();
    let network = state.network;
    {
        let mweb = state.mweb.as_mut().unwrap();
        let res = mweb::sign_mweb_split(
            &state.wallet,
            mweb,
            &data_dir,
            &ids[0],
            &[25_000, 25_000],
            100, // below min_mweb_fee
            network,
        );
        assert!(res.is_err());
        assert_eq!(
            mweb.receive_index, mweb_idx_before,
            "failed sign_mweb_split burned MWEB receive_index"
        );
    }

    // 3. Multi-hop self-spend where hop 1 fits (60,000 > 50,000) but hop 2 fails (10,000 <= 50,000).
    {
        let mweb = state.mweb.as_mut().unwrap();
        let coin = mweb
            .store
            .db()
            .get(&hex::decode(&ids[0]).unwrap().try_into().unwrap())
            .unwrap()
            .clone();
        let res =
            mweb::sign_self_spend_hops(&state.wallet, mweb, &data_dir, coin, 2, 50_000, network);
        assert!(res.is_err());
        assert_eq!(
            mweb.receive_index, mweb_idx_before,
            "failed sign_self_spend_hops burned MWEB receive_index"
        );
    }
    drop(guard);

    // 4. Failed per-coin sign_pegout (missing spend_key fails inside mweb::sign_pegout after
    // resolve_pegout_request succeeds) must not advance external index.
    let no_key_id = [0x91u8; 32];
    let no_key_hex = hex::encode(no_key_id);
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        super::insert_private_coin(state, no_key_id, 200_000, Some(0), false);
        let mut coin = state
            .mweb
            .as_ref()
            .unwrap()
            .store
            .db()
            .get(&no_key_id)
            .unwrap()
            .clone();
        coin.spend_key = None;
        state.mweb.as_mut().unwrap().store.db_mut().insert(coin);
    }
    let pegout_res = app.sign_pegout(PegoutRequest {
        address: String::new(),
        amount_sats: 0,
        fee_sats: crate::tx_invariants::min_kernel_fee(2, std::iter::empty()),
        drain: true,
        selected_output_ids: Some(vec![no_key_hex]),
        output_amounts: Vec::new(),
        addresses: Vec::new(),
        per_coin: true,
        fee_output_index: None,
    });
    assert!(pegout_res.is_err());
    {
        let guard = app.lock_state().unwrap();
        let state = guard.as_ref().unwrap();
        assert_eq!(
            state.wallet.derivation_index(KeychainKind::External),
            ext_before,
            "failed per-coin sign_pegout burned external derivation index"
        );
    }

    // 5. Failed transfer_coin (unknown source coin) must not advance destination account's index.
    app.create_wallet_account(
        dir.path(),
        crate::dto::CreateAccountRequest {
            name: "Dest".into(),
        },
    )
    .unwrap();
    let dest_ext_before = {
        let guard = app.lock_state().unwrap();
        guard
            .as_ref()
            .unwrap()
            .wallet
            .derivation_index(KeychainKind::External)
    };
    app.switch_wallet(dir.path(), crate::dto::SwitchWalletRequest { index: 0 })
        .unwrap();
    let transfer_res = app.transfer_coin(
        dir.path(),
        crate::dto::TransferCoinRequest {
            chain: crate::dto::SplitChain::Public,
            coin_id: format!("{}:0", "99".repeat(32)),
            to_account_index: 1,
            fee_rate_sat_vb: Some(1),
            fee_sats: 0,
        },
    );
    assert!(transfer_res.is_err());
    app.switch_wallet(dir.path(), crate::dto::SwitchWalletRequest { index: 1 })
        .unwrap();
    {
        let guard = app.lock_state().unwrap();
        assert_eq!(
            guard
                .as_ref()
                .unwrap()
                .wallet
                .derivation_index(KeychainKind::External),
            dest_ext_before,
            "failed transfer_coin burned destination account external derivation index"
        );
    }
}

/// Seeded property test over transparent `build_send_psbt` (normal + drain, manual + auto,
/// optional-UTXO top-up for sub-dust change) verifying exact value conservation and
/// Litecoin 30 sat/vB dust enforcement on every output.
#[test]
fn public_send_seeded_property_holds_conservation_and_ltc_dust() {
    use rand::{rngs::StdRng, Rng, SeedableRng};

    let dir = tempfile::tempdir().unwrap();
    let (app, outs) =
        app_with_public_coins(dir.path(), &[11_141, 25_000, 100_000, 350_000, 1_200_000]);
    let dest = app.receive_address().unwrap();
    let mut guard = app.lock_state().unwrap();
    let state = guard.as_mut().unwrap();

    for seed in 0..80u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let drain = rng.gen_bool(0.25);
        let fee_rate = rng.gen_range(1..=25u64);
        let amount_sats = if drain {
            0
        } else if rng.gen_bool(0.2) {
            rng.gen_range(0..=3_500u64)
        } else {
            rng.gen_range(2_940..=1_800_000u64)
        };
        let selected_outpoints = if rng.gen_bool(0.4) {
            let k = rng.gen_range(1..=outs.len());
            Some(outs[..k].iter().map(ToString::to_string).collect())
        } else {
            None
        };

        let req = SendRequest {
            address: dest.clone(),
            amount_sats,
            fee_rate_sat_vb: Some(fee_rate),
            drain,
            selected_outpoints,
        };
        if let Ok((resolved_rate, psbt, recip_spk)) = build_send_psbt(state, &req) {
            assert_eq!(resolved_rate, fee_rate, "seed={seed}");
            let fee_sats = crate::tx_invariants::verify_transparent_psbt(&psbt)
                .expect("transparent invariants");
            assert!(fee_sats > 0, "seed={seed}");
            let recip_out = psbt
                .unsigned_tx
                .output
                .iter()
                .find(|o| o.script_pubkey == recip_spk)
                .expect("recipient output");
            if !drain {
                assert_eq!(recip_out.value.to_sat(), amount_sats, "seed={seed}");
            }
            for out in &psbt.unsigned_tx.output {
                let ltc_dust = crate::tx_invariants::ltc_dust_threshold(&out.script_pubkey);
                assert!(
                    out.value.to_sat() >= ltc_dust,
                    "seed={seed}: output {} < Litecoin dust {ltc_dust}",
                    out.value.to_sat()
                );
            }
        }
    }
}

/// When an initial 1-input selection leaves `1,000` litoshis of sub-dust change (`< 2,940`),
/// and an optional UTXO (`50,000` litoshis, input fee `68` litoshis `< 1,000`) is available,
/// `LitecoinDustCoinSelection` pulls in the second UTXO to preserve the user's change rather
/// than burning `1,000` litoshis into the miner fee.
#[test]
fn ltc_dust_coin_selection_tops_up_optional_utxo_to_rescue_sub_dust_change() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _outs) = app_with_public_coins(dir.path(), &[11_141, 50_000]);
    let dest = app.receive_address().unwrap();
    let preview = app
        .preview_send(SendRequest {
            address: dest,
            amount_sats: 10_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: None,
        })
        .unwrap();
    assert!(
        preview.creates_change,
        "optional 50k UTXO should be added to rescue sub-dust change: {preview:?}"
    );
    assert!(
        preview.fee_sats < 500,
        "fee should be 2-in-2-out (~209 sats), not burning 1,000 sats: {preview:?}"
    );
}

fn one_output_fee() -> u64 {
    crate::tx_invariants::min_kernel_fee(1, std::iter::empty())
}

fn two_output_fee() -> u64 {
    crate::tx_invariants::min_kernel_fee(2, std::iter::empty())
}

/// A fee of 0 pays the relay minimum for the shape, not a flat kernel fee.
#[test]
fn auto_mweb_fee_follows_weight() {
    let one = one_output_fee();
    let two = two_output_fee();
    assert_eq!(one, 2_100);
    assert_eq!(two, 3_900);

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[100_000 + one, 200_000, 500_000]);
    let address = app.mweb_receive_address().unwrap();

    let exact = app
        .preview_mweb_send(MwebSendRequest {
            address: address.clone(),
            amount_sats: 100_000,
            fee_sats: 0,
            drain: false,
            selected_output_ids: Some(vec![ids[0].clone()]),
        })
        .unwrap();
    assert_eq!(exact.fee_sats, one);
    assert!(!exact.creates_change);

    let drained = app
        .preview_mweb_send(MwebSendRequest {
            address: address.clone(),
            amount_sats: 0,
            fee_sats: 0,
            drain: true,
            selected_output_ids: Some(vec![ids[1].clone()]),
        })
        .unwrap();
    assert_eq!(drained.fee_sats, one);
    assert_eq!(drained.amount_sats, 200_000 - one);
    assert!(!drained.creates_change);

    let change = app
        .preview_mweb_send(MwebSendRequest {
            address: address.clone(),
            amount_sats: 100_000,
            fee_sats: 0,
            drain: false,
            selected_output_ids: Some(vec![ids[2].clone()]),
        })
        .unwrap();
    assert_eq!(change.fee_sats, two);
    assert!(change.creates_change);

    let below = app.preview_mweb_send(MwebSendRequest {
        address: address.clone(),
        amount_sats: 100_000,
        fee_sats: 2_000,
        drain: false,
        selected_output_ids: Some(vec![ids[0].clone()]),
    });
    assert!(
        below.is_err(),
        "explicit fee under 2,100 must fail: {below:?}"
    );

    let no_change_fee_with_change = app.preview_mweb_send(MwebSendRequest {
        address: address,
        amount_sats: 100_000,
        fee_sats: one,
        drain: false,
        selected_output_ids: Some(vec![ids[2].clone()]),
    });
    assert!(
        no_change_fee_with_change.is_err(),
        "explicit 2,100 must fail when change is created: {no_change_fee_with_change:?}"
    );

    let dir_pub = tempfile::tempdir().unwrap();
    let (app_pub, _outs) = app_with_public_coins(dir_pub.path(), &[1_000_000]);
    let pegin = app_pub
        .preview_pegin(PeginRequest {
            amount_sats: 100_000,
            mweb_fee_sats: 0,
            transparent_fee_sats: 500,
            drain: false,
            selected_outpoints: None,
        })
        .unwrap();
    assert_eq!(pegin.mweb_fee_sats, one);

    let preview = app
        .preview_churn(ChurnRequest {
            output_id: ids[2].clone(),
            target_depth: 3,
            cover_min: 0,
            spread_send: false,
        })
        .unwrap();
    assert_eq!(preview.hop_fee_sats, one);
    assert_eq!(preview.total_fee_sats, one * 3);
    assert_eq!(preview.quiet_block_note, crate::dto::CHURN_QUIET_CHAIN_NOTE);
    let one_hop = app
        .preview_churn(ChurnRequest {
            output_id: ids[2].clone(),
            target_depth: 1,
            cover_min: 0,
            spread_send: false,
        })
        .unwrap();
    assert_eq!(one_hop.hop_fee_sats, one);
    assert_eq!(one_hop.total_fee_sats, one);
    assert_eq!(one_hop.quiet_block_note, crate::dto::CHURN_QUIET_NOTE);
    assert!(one_hop.quiet_block_note.contains("0.000021 LTC"));

    let split = app
        .preview_split(SplitRequest {
            chain: SplitChain::Private,
            input: ids[2].clone(),
            equal_count: Some(4),
            amounts: vec![],
            fee_rate_sat_vb: None,
            fee_sats: 0,
        })
        .unwrap();
    assert_eq!(split.fee_sats, 7_500);

    let script = crate::mweb::p2wpkh_script();
    let peg_exact = crate::tx_invariants::min_kernel_fee(0, [script.as_script()]);
    let peg_change = crate::tx_invariants::min_kernel_fee(1, [script.as_script()]);
    assert_eq!(peg_exact, 400);
    assert_eq!(peg_change, 2_200);

    let dir_peg = tempfile::tempdir().unwrap();
    let (app_peg, peg_ids) =
        app_with_private_coins(dir_peg.path(), &[100_000 + peg_exact, 500_000]);
    let ltc1 = app_peg.receive_address().unwrap();
    let exact_peg = app_peg
        .preview_pegout(PegoutRequest {
            address: ltc1.clone(),
            amount_sats: 100_000,
            fee_sats: 0,
            drain: false,
            selected_output_ids: Some(vec![peg_ids[0].clone()]),
            output_amounts: Vec::new(),
            addresses: Vec::new(),
            per_coin: false,
            fee_output_index: None,
        })
        .unwrap();
    assert_eq!(exact_peg.fee_sats, peg_exact);
    assert!(!exact_peg.creates_change);

    let change_peg = app_peg
        .preview_pegout(PegoutRequest {
            address: ltc1,
            amount_sats: 100_000,
            fee_sats: 0,
            drain: false,
            selected_output_ids: Some(vec![peg_ids[1].clone()]),
            output_amounts: Vec::new(),
            addresses: Vec::new(),
            per_coin: false,
            fee_output_index: None,
        })
        .unwrap();
    assert_eq!(change_peg.fee_sats, peg_change);
    assert!(change_peg.creates_change);

    let per_coin = app
        .preview_pegout(PegoutRequest {
            address: String::new(),
            amount_sats: 0,
            fee_sats: 0,
            drain: true,
            selected_output_ids: Some(vec![ids[1].clone(), ids[2].clone()]),
            output_amounts: Vec::new(),
            addresses: Vec::new(),
            per_coin: false,
            fee_output_index: None,
        })
        .unwrap();
    let p2wpkh = crate::mweb::p2wpkh_script();
    let two_scripts =
        crate::tx_invariants::min_kernel_fee(0, std::iter::repeat(p2wpkh.as_script()).take(2));
    assert_eq!(two_scripts, 500);
    assert_eq!(per_coin.fee_sats, two_scripts);
    assert!(!per_coin.creates_change);
}

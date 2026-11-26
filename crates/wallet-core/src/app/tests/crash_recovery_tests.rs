//! Persistence atomicity and crash-recovery tests (Hardening item 17).
//!
//! Covers restarts after simulated and real subprocess kills mid-persist,
//! mid-sync, mid-spend, and mid-churn. Asserts that holds are not orphaned,
//! phases are not stuck, and coin status + action flags match recovered files.

use std::path::{Path, PathBuf};

use super::super::*;
use super::{app_with_private_coins, insert_private_coin};
use crate::dto::{ChurnPhase, CoinStatus};

const PASSPHRASE: &str = "correct horse battery staple";

fn account_dir(app: &WalletApp) -> PathBuf {
    app.lock_state().unwrap().as_ref().unwrap().data_dir.clone()
}

fn persist_private(app: &WalletApp) {
    let mut guard = app.lock_state().unwrap();
    let state = guard.as_mut().unwrap();
    let dir = state.data_dir.clone();
    state.mweb.as_mut().unwrap().persist(&dir).unwrap();
}

fn clear_planted_job(app: &WalletApp) {
    let dir = account_dir(app);
    let _ = std::fs::remove_file(churn::job_path(&dir));
    let _ = std::fs::remove_file(churn::armed_path(&dir));
}

fn churn_req(id: &str, target_depth: u32, cover_min: u32) -> ChurnRequest {
    ChurnRequest {
        output_id: id.into(),
        target_depth,
        cover_min,
        spread_send: false,
    }
}

fn private_row(app: &WalletApp, id: &str) -> MwebUtxoRecord {
    app.list_mweb_unspent()
        .unwrap()
        .into_iter()
        .find(|coin| coin.output_id == id)
        .unwrap_or_else(|| panic!("missing private coin {id}"))
}

fn public_row(app: &WalletApp, outpoint: &OutPoint) -> UtxoRecord {
    let key = outpoint.to_string();
    app.list_unspent()
        .unwrap()
        .into_iter()
        .find(|coin| coin.outpoint == key)
        .unwrap_or_else(|| panic!("missing public coin {key}"))
}

fn restart_app(root: &Path) -> WalletApp {
    let app = WalletApp::new(root);
    app.unlock(UnlockRequest {
        passphrase: PASSPHRASE.into(),
    })
    .expect("unlock on restart");
    app.load(root).expect("load on restart");
    app
}

#[test]
fn corrupted_or_swapped_sealed_mweb_fails_load_instead_of_silently_disabling_mweb() {
    let dir = tempfile::tempdir().unwrap();
    let (app, _ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    let data_dir = account_dir(&app);
    drop(app);

    let coins_enc = meta::mweb_coins_enc_path(&data_dir);
    let history_enc = meta::mweb_history_enc_path(&data_dir);
    let valid_coins = std::fs::read(&coins_enc).unwrap();
    let valid_history = std::fs::read(&history_enc).unwrap();

    // 1. Swapping mweb_history.enc over mweb_coins.enc must make WalletApp::load fail.
    std::fs::write(&coins_enc, &valid_history).unwrap();
    let restarted = WalletApp::new(dir.path());
    restarted
        .unlock(UnlockRequest {
            passphrase: PASSPHRASE.into(),
        })
        .unwrap();
    assert!(
        restarted.load(dir.path()).is_err(),
        "load accepted history.enc swapped into coins.enc"
    );

    // 2. Truncated/corrupt mweb_coins.enc must also fail load rather than
    // silently opening with mweb = None ("MWEB unavailable").
    std::fs::write(&coins_enc, b"corrupt-sealed-blob").unwrap();
    assert!(
        restarted.load(dir.path()).is_err(),
        "load swallowed corrupt mweb_coins.enc"
    );

    // Restore valid coins blob: load succeeds again.
    std::fs::write(&coins_enc, &valid_coins).unwrap();
    restarted.load(dir.path()).unwrap();
    assert_eq!(restarted.list_mweb_unspent().unwrap().len(), 1);
}

#[test]
fn crash_mid_start_churn_after_mweb_persist_rolls_back_on_restart() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    clear_planted_job(&app);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[1].clone(),
        locked: true,
    })
    .unwrap();
    persist_private(&app);

    // Start churn on ids[0], then simulate a kill right before churn::write_job
    // committed the new job to disk (mweb_coins.enc, mweb_frozen.json, and
    // churn_armed.json were already written).
    app.start_churn(churn_req(&ids[0], 2, 1)).unwrap();
    let data_dir = account_dir(&app);
    std::fs::remove_file(churn::job_path(&data_dir)).unwrap();
    drop(app);

    let restarted = restart_app(dir.path());
    assert!(restarted.churn_status().unwrap().is_none());
    assert!(!churn::armed_path(&data_dir).exists());

    let row0 = private_row(&restarted, &ids[0]);
    assert_eq!(row0.status, CoinStatus::Ready);
    assert!(row0.actions.spend_to_self && row0.actions.select && row0.actions.freeze);
    assert!(!row0.actions.unfreeze);

    let row1 = private_row(&restarted, &ids[1]);
    assert_eq!(row1.status, CoinStatus::Frozen);
    assert!(row1.actions.unfreeze);
    assert_eq!(restarted.list_mweb_unspent().unwrap().len(), 2);
}

#[test]
fn crash_mid_retry_churn_resign_after_mweb_persist_rolls_back_to_paused_job_on_restart() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);

    // Put the job into PausedSolo as if hop 0 landed in a solo block.
    let paused_job = {
        let mut job = churn::read_job(&data_dir).unwrap().unwrap();
        job.set_phase_for_test(ChurnPhase::PausedSolo);
        churn::write_job(&data_dir, &job).unwrap();
        job
    };
    let paused_coin = paused_job.current_output_id.clone();
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        let mweb = state.mweb.as_mut().unwrap();
        assert!(mweb::set_coin_block_height(mweb, &paused_coin, 0));
        mweb.persist(&data_dir).unwrap();
    }

    // Run retry_churn (which runs resign_one_hop), then restore churn_job.json to
    // the pre-resign PausedSolo snapshot to simulate a kill after mweb.persist +
    // write_armed but before write_job committed the new current_output_id.
    app.retry_churn().unwrap();
    churn::write_job(&data_dir, &paused_job).unwrap();
    drop(app);

    let restarted = restart_app(dir.path());
    let status = restarted.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::PausedSolo);
    assert_eq!(status.output_id, paused_coin);
    assert!(status.actions.retry && status.actions.cancel);

    let row = private_row(&restarted, &paused_coin);
    assert_eq!(row.status, CoinStatus::Churning);
    assert_eq!(restarted.list_mweb_unspent().unwrap().len(), 1);

    // Retry and Cancel must both work cleanly from the recovered state.
    let retried = restarted.retry_churn().unwrap();
    assert_eq!(retried.phase, ChurnPhase::WaitingForCover);
    let cancelled = restarted.cancel_churn().unwrap();
    assert_eq!(cancelled.phase, ChurnPhase::Cancelled);
    assert_eq!(
        private_row(&restarted, &paused_coin).status,
        CoinStatus::Ready
    );
}

#[test]
fn crash_mid_send_armed_hop_converges_on_restart_for_hop0_and_hop1() {
    crate::discovery::go_offline_for_test();

    // Case 1: Hop 0 broadcast recorded in churn_armed.json, but process died before
    // churn_job.json moved to WaitingConfirm and before spent_output_id was unlocked.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);
    let created = {
        let mut record = churn::read_armed(&data_dir).unwrap().unwrap();
        let created = record.hops[0].created_output_id.clone();
        record.hops[0].broadcast = true;
        churn::write_armed(&data_dir, &record).unwrap();
        created
    };
    assert!(mweb_frozen::read_ids(&data_dir)
        .unwrap()
        .ids
        .contains(&ids[0]));
    drop(app);

    let restarted = restart_app(dir.path());
    let status = restarted.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingConfirm);
    assert_eq!(status.output_id, created);
    let frozen = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(
        !frozen.ids.contains(&ids[0]),
        "hop 0 spent coin freeze must be cleared on recovery"
    );
    assert!(frozen.ids.contains(&created));
    assert_eq!(
        private_row(&restarted, &created).status,
        CoinStatus::Churning
    );

    // Case 2: Hop 1 (of a 2-hop chain) broadcast while locked or killed after
    // write_job(WaitingConfirm) before apply_pending_local updated mweb_coins.enc.
    let dir2 = tempfile::tempdir().unwrap();
    let (app2, ids2) = app_with_private_coins(dir2.path(), &[3_000_000]);
    clear_planted_job(&app2);
    persist_private(&app2);
    app2.start_churn(churn_req(&ids2[0], 2, 1)).unwrap();
    let data_dir2 = account_dir(&app2);
    let (hop0_created, hop1_created) = {
        let mut record = churn::read_armed(&data_dir2).unwrap().unwrap();
        record.hops[0].broadcast = true;
        record.armed_index = 1;
        record.hops[1].broadcast = true;
        record.hops[1].local_applied = false;
        let h0 = record.hops[0].created_output_id.clone();
        let h1 = record.hops[1].created_output_id.clone();
        churn::write_armed(&data_dir2, &record).unwrap();

        let mut job = churn::read_job(&data_dir2).unwrap().unwrap();
        job.set_phase_for_test(ChurnPhase::WaitingForCover);
        job.current_output_id = h0.clone();
        churn::write_job(&data_dir2, &job).unwrap();
        (h0, h1)
    };
    drop(app2);

    let restarted2 = restart_app(dir2.path());
    let status2 = restarted2.churn_status().unwrap().unwrap();
    assert_eq!(status2.phase, ChurnPhase::WaitingConfirm);
    assert_eq!(status2.output_id, hop1_created);
    let frozen2 = mweb_frozen::read_ids(&data_dir2).unwrap();
    assert!(!frozen2.ids.contains(&hop0_created));
    assert!(frozen2.ids.contains(&hop1_created));
    assert_eq!(
        private_row(&restarted2, &hop1_created).status,
        CoinStatus::Churning
    );
}

#[test]
fn crash_mid_drive_churn_after_commit_score_does_not_double_count_depth() {
    let dir = tempfile::tempdir().unwrap();
    let id = "cd".repeat(32);
    let score = churn::HopScore::Mixed {
        other_kernels: 3,
        other_outputs: 5,
    };

    // First commit_score before crash.
    churn::commit_score(dir.path(), &id, true, score).unwrap();
    // Replay of the same hop's score after restart (before inherit_depth creates a new output).
    churn::commit_score(dir.path(), &id, true, score).unwrap();

    let depth = churn::depth_of(dir.path(), &id).unwrap().unwrap();
    assert_eq!(
        depth.non_solo_blocks, 1,
        "replaying commit_score on the same hop output must not double-count depth"
    );
    assert_eq!(depth.hops.len(), 1);
}

#[test]
fn crash_mid_drive_churn_before_promote_advances_next_hop_or_finishes_on_restart() {
    crate::discovery::go_offline_for_test();

    // Subcase A: 2-hop job scored hop 0 as Mixed and wrote churn_job.json
    // (WaitingForCover, effective_depth = 1), then crashed before promote_after_score
    // advanced record.armed_index from 0 to 1.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    app.start_churn(churn_req(&ids[0], 2, 1)).unwrap();
    let data_dir = account_dir(&app);
    {
        let mut record = churn::read_armed(&data_dir).unwrap().unwrap();
        record.hops[0].broadcast = true;
        churn::write_armed(&data_dir, &record).unwrap();

        let mut job = churn::read_job(&data_dir).unwrap().unwrap();
        job.set_phase_for_test(ChurnPhase::WaitingConfirm);
        churn::apply_score(
            &mut job,
            churn::HopScore::Mixed {
                other_kernels: 2,
                other_outputs: 2,
            },
        )
        .unwrap();
        assert_eq!(job.phase(), ChurnPhase::WaitingForCover);
        churn::write_job(&data_dir, &job).unwrap();
    }
    drop(app);

    let restarted = restart_app(dir.path());
    let record = churn::read_armed(&data_dir).unwrap().unwrap();
    assert_eq!(
        record.armed_index, 1,
        "restart must promote armed_index to hop 1 when hop 0 was already scored"
    );
    assert!(!record.current().unwrap().broadcast);
    assert_eq!(
        restarted.churn_status().unwrap().unwrap().phase,
        ChurnPhase::WaitingForCover
    );

    // Subcase B: FinishShort (target_depth = 2, but only 1 hop left in record after a resign)
    // scored Mixed into WaitingForCover, then crashed before promote_after_score moved to Done.
    let dir2 = tempfile::tempdir().unwrap();
    let (app2, ids2) = app_with_private_coins(dir2.path(), &[3_000_000]);
    clear_planted_job(&app2);
    persist_private(&app2);
    app2.start_churn(churn_req(&ids2[0], 1, 1)).unwrap();
    let data_dir2 = account_dir(&app2);
    let created2 = {
        let mut record = churn::read_armed(&data_dir2).unwrap().unwrap();
        record.hops[0].broadcast = true;
        let created = record.hops[0].created_output_id.clone();
        churn::write_armed(&data_dir2, &record).unwrap();
        mweb_frozen::set_locked(&data_dir2, &ids2[0], false).unwrap();
        {
            let mut guard = app2.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let mweb = state.mweb.as_mut().unwrap();
            assert!(mweb::set_coin_block_height(mweb, &created, 0));
            mweb.persist(&data_dir2).unwrap();
        }

        let mut job = churn::read_job(&data_dir2).unwrap().unwrap();
        job.target_depth = 2;
        job.set_phase_for_test(ChurnPhase::WaitingConfirm);
        churn::apply_score(
            &mut job,
            churn::HopScore::Mixed {
                other_kernels: 2,
                other_outputs: 2,
            },
        )
        .unwrap();
        assert_eq!(job.phase(), ChurnPhase::WaitingForCover);
        churn::write_job(&data_dir2, &job).unwrap();
        created
    };
    drop(app2);

    let restarted2 = restart_app(dir2.path());
    assert_eq!(
        restarted2.churn_status().unwrap().unwrap().phase,
        ChurnPhase::Done
    );
    assert!(churn::read_armed(&data_dir2).unwrap().is_none());
    assert_eq!(
        private_row(&restarted2, &created2).status,
        CoinStatus::Ready
    );
}

#[test]
fn crash_mid_cancel_or_done_finishes_cleanup_without_touching_manual_user_freezes() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    clear_planted_job(&app);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[1].clone(),
        locked: true,
    })
    .unwrap();
    persist_private(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);

    // Simulate a crash during cancel_churn right after churn_job.json was written
    // as Cancelled, before revert_unbroadcast_hop, unfreezing, and remove_armed ran.
    {
        let mut job = churn::read_job(&data_dir).unwrap().unwrap();
        churn::request_cancel(&mut job).unwrap();
        churn::write_job(&data_dir, &job).unwrap();
    }
    drop(app);

    let restarted = restart_app(dir.path());
    assert_eq!(
        restarted.churn_status().unwrap().unwrap().phase,
        ChurnPhase::Cancelled
    );
    assert!(!churn::armed_path(&data_dir).exists());

    let row0 = private_row(&restarted, &ids[0]);
    assert_eq!(row0.status, CoinStatus::Ready);
    assert!(row0.actions.freeze && row0.actions.spend_to_self);

    // Bystander manual freeze on ids[1] is untouched.
    let row1 = private_row(&restarted, &ids[1]);
    assert_eq!(row1.status, CoinStatus::Frozen);
    assert!(row1.actions.unfreeze);

    // Now manually freeze ids[0] after Cancelled, and restart again: since
    // churn_armed.json is gone, the manual freeze must survive restart.
    restarted
        .set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[0].clone(),
            locked: true,
        })
        .unwrap();
    drop(restarted);

    let restarted2 = restart_app(dir.path());
    assert_eq!(private_row(&restarted2, &ids[0]).status, CoinStatus::Frozen);
    assert_eq!(private_row(&restarted2, &ids[1]).status, CoinStatus::Frozen);
}

#[test]
fn crash_mid_reorg_sync_and_resync_mweb_and_cross_account_holds_recover_on_restart() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    let (_, pub_outs) = {
        use bdk_wallet::bitcoin::hashes::Hash;
        use bdk_wallet::bitcoin::BlockHash;
        use bdk_wallet::chain::BlockId;
        use bdk_wallet::test_utils::{insert_checkpoint, receive_output_in_latest_block};

        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        insert_checkpoint(
            &mut state.wallet,
            BlockId {
                height: 100,
                hash: BlockHash::all_zeros(),
            },
        );
        let op = receive_output_in_latest_block(&mut state.wallet, Amount::from_sat(1_000_000));
        state.wallet.persist(&mut state.db).unwrap();

        // Advance MWEB state to height 120 with a coin and confirmed history at 115,
        // simulating a crash during a later reorg after wallet.sqlite persisted at 100
        // but before mweb.disconnect_from + mweb.persist ran.
        let reorg_coin = [0x99u8; 32];
        insert_private_coin(state, reorg_coin, 500_000, Some(115), false);
        let mweb = state.mweb.as_mut().unwrap();
        mweb.sync_state.tip_height = Some(120);
        mweb.history.record(crate::mweb_history::MwebHistoryEntry {
            id: "reorg-send".into(),
            kind: TxKind::MwebSend,
            net_sats: -100_000,
            fee_sats: Some(1_000),
            timestamp: 1_700_000_000,
            output_ids: Vec::new(),
            input_ids: vec![ids[0].clone()],
            relayed: false,
            absent: false,
            confirmed_height: Some(115),
        });
        let data_dir = state.data_dir.clone();
        mweb.persist(&data_dir).unwrap();
        (reorg_coin, vec![op])
    };
    clear_planted_job(&app);
    let data_dir0 = account_dir(&app);

    // Plant stale holds from a dead session in account 0.
    mweb_frozen::reserve(&data_dir0, std::slice::from_ref(&ids[0]), "dead-session").unwrap();
    mweb_frozen::reserve_public(&data_dir0, &pub_outs, "dead-session").unwrap();

    // Create account 1 and plant a stale hold there too, then switch back to 0 or stay on 1.
    app.create_wallet_account(
        dir.path(),
        CreateAccountRequest {
            name: "Second".into(),
        },
    )
    .unwrap();
    let data_dir1 = account_dir(&app);
    mweb_frozen::reserve(&data_dir1, &["ee".repeat(32)], "dead-session").unwrap();
    drop(app);

    // Restarting loads active account (1), and must sweep stale holds across all accounts.
    let restarted = restart_app(dir.path());
    assert!(mweb_frozen::read_ids(&data_dir1)
        .unwrap()
        .reserved
        .is_empty());
    assert!(
        mweb_frozen::read_ids(&data_dir0)
            .unwrap()
            .reserved
            .is_empty(),
        "stale private hold in non-active account 0 must be cleared on startup"
    );
    assert!(
        mweb_frozen::read_ids(&data_dir0)
            .unwrap()
            .public_reserved
            .is_empty(),
        "stale public hold in non-active account 0 must be cleared on startup"
    );

    // Switch to account 0: MWEB height 120 (> wallet tip 100) must have been disconnected.
    restarted
        .switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    assert_eq!(private_row(&restarted, &ids[0]).status, CoinStatus::Ready);
    assert_eq!(
        public_row(&restarted, &pub_outs[0]).status,
        CoinStatus::Ready
    );
    {
        let guard = restarted.lock_state().unwrap();
        let state = guard.as_ref().unwrap();
        let mweb = state.mweb.as_ref().unwrap();
        assert!(
            mweb.history
                .entries
                .iter()
                .find(|e| e.id == "reorg-send")
                .unwrap()
                .confirmed_height
                .is_none(),
            "MWEB history confirmed above wallet tip must be un-confirmed on recovery"
        );
    }
}

fn spawn_crash_child(root: &Path, case: &str, crash_at: &str, extra_arg: &str) {
    let exe = std::env::current_exe().expect("current test exe");
    let status = std::process::Command::new(exe)
        .arg("--exact")
        .arg("app::tests::crash_recovery_tests::subprocess_aborts_across_all_crashpoints_recover_on_restart")
        .arg("--nocapture")
        .env("LDK_WALLET_CRASH_CHILD_CASE", case)
        .env("LDK_WALLET_CRASH_DIR", root)
        .env("LDK_WALLET_CRASH_EXTRA", extra_arg)
        .env("LDK_WALLET_CRASH_AT", crash_at)
        .status()
        .expect("spawn crash child");
    assert!(
        !status.success(),
        "expected child process for case={case} crash_at={crash_at} to abort, got {status}"
    );
}

#[test]
fn subprocess_aborts_across_all_crashpoints_recover_on_restart() {
    crate::discovery::go_offline_for_test();
    if let Ok(case) = std::env::var("LDK_WALLET_CRASH_CHILD_CASE") {
        let root = PathBuf::from(std::env::var("LDK_WALLET_CRASH_DIR").unwrap());
        let extra = std::env::var("LDK_WALLET_CRASH_EXTRA").unwrap_or_default();
        let app = restart_app(&root);
        match case.as_str() {
            "persist_coins" => {
                let _ = app.mweb_receive_address().unwrap();
            }
            "prepare_churn" => {
                let _ = app.start_churn(churn_req(&extra, 1, 1));
            }
            "resign_churn" => {
                let _ = app.retry_churn();
            }
            "cancel_churn" => {
                let _ = app.cancel_churn();
            }
            "resync_mweb" => {
                let _ = app.set_mweb_scheme(MwebScheme::Mwebd);
            }
            other => panic!("unknown crash child case: {other}"),
        }
        panic!("child case {case} returned without hitting crashpoint");
    }

    // 1. Subprocess abort at `persist_after_coins_enc` (mid-MwebRuntime::persist):
    //    `mweb_receive_index.enc` and `mweb_coins.enc` are at counter 2 while
    //    `mweb_history.enc`, `mweb_sync.enc`, and `mweb_seal_counter.txt` are at 1.
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        persist_private(&app);
        let data_dir = account_dir(&app);
        drop(app);

        spawn_crash_child(dir.path(), "persist_coins", "persist_after_coins_enc", "");

        let restarted = restart_app(dir.path());
        assert_eq!(private_row(&restarted, &ids[0]).status, CoinStatus::Ready);
        // Next persist must advance all blobs and the counter file to 3.
        let _ = restarted.mweb_receive_address().unwrap();
        let counter_str = std::fs::read_to_string(meta::mweb_seal_counter_path(&data_dir)).unwrap();
        assert_eq!(counter_str.trim(), "3");
    }

    // 2. Subprocess abort at `prepare_churn_after_mweb_persist` (mid-start_churn):
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        persist_private(&app);
        let data_dir = account_dir(&app);
        drop(app);

        spawn_crash_child(
            dir.path(),
            "prepare_churn",
            "prepare_churn_after_mweb_persist",
            &ids[0],
        );

        let restarted = restart_app(dir.path());
        assert!(restarted.churn_status().unwrap().is_none());
        assert!(!churn::armed_path(&data_dir).exists());
        let row = private_row(&restarted, &ids[0]);
        assert_eq!(row.status, CoinStatus::Ready);
        assert!(row.actions.spend_to_self && row.actions.freeze && row.actions.select);
    }

    // 3. Subprocess abort at `resign_churn_after_mweb_persist` (mid-retry_churn):
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        persist_private(&app);
        app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
        let data_dir = account_dir(&app);
        let paused_coin = {
            let mut job = churn::read_job(&data_dir).unwrap().unwrap();
            job.set_phase_for_test(ChurnPhase::PausedSolo);
            churn::write_job(&data_dir, &job).unwrap();
            job.current_output_id
        };
        {
            let mut guard = app.lock_state().unwrap();
            let state = guard.as_mut().unwrap();
            let mweb = state.mweb.as_mut().unwrap();
            assert!(mweb::set_coin_block_height(mweb, &paused_coin, 0));
            mweb.persist(&data_dir).unwrap();
        }
        drop(app);

        spawn_crash_child(
            dir.path(),
            "resign_churn",
            "resign_churn_after_mweb_persist",
            "",
        );

        let restarted = restart_app(dir.path());
        let status = restarted.churn_status().unwrap().unwrap();
        assert_eq!(status.phase, ChurnPhase::PausedSolo);
        assert_eq!(status.output_id, paused_coin);
        assert!(status.actions.retry && status.actions.cancel);
        assert_eq!(
            private_row(&restarted, &paused_coin).status,
            CoinStatus::Churning
        );
    }

    // 4. Subprocess abort at `cancel_churn_after_write_job` (mid-cancel_churn):
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        persist_private(&app);
        app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
        let data_dir = account_dir(&app);
        drop(app);

        spawn_crash_child(
            dir.path(),
            "cancel_churn",
            "cancel_churn_after_write_job",
            "",
        );

        let restarted = restart_app(dir.path());
        assert_eq!(
            restarted.churn_status().unwrap().unwrap().phase,
            ChurnPhase::Cancelled
        );
        assert!(!churn::armed_path(&data_dir).exists());
        assert_eq!(private_row(&restarted, &ids[0]).status, CoinStatus::Ready);
    }

    // 5. Subprocess abort at `resync_mweb_after_wipe` (mid-set_mweb_scheme):
    {
        let dir = tempfile::tempdir().unwrap();
        let (app, _ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        persist_private(&app);
        let data_dir = account_dir(&app);
        drop(app);

        spawn_crash_child(dir.path(), "resync_mweb", "resync_mweb_after_wipe", "");

        let restarted = restart_app(dir.path());
        assert_eq!(restarted.mweb_sync_progress().phase, SyncPhase::Idle);
        let meta = meta::read_meta(&data_dir).unwrap();
        assert!(meta.needs_mweb_scan);
        assert_eq!(meta.mweb_scheme, MwebScheme::Mwebd);
    }
}

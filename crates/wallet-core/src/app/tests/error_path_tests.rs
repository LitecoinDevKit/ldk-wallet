//! Offline error paths: lock races, persist failures, bad peers, foreign spend,
//! and commands that return before they change anything.
//!
//! Nothing here dials a public server. Dead endpoints are `127.0.0.1:9` or a
//! loopback listener this file owns, and MWEB discovery is forced empty.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::super::*;
use super::{app_with_job, app_with_private_coins, app_with_public_coins, insert_private_coin};
use crate::dto::CoinStatus;

const PASSPHRASE: &str = "correct horse battery staple";

/// Explicit fee at the two-output relay minimum. Above every one-output floor.
fn legal_mweb_fee() -> u64 {
    crate::tx_invariants::min_kernel_fee(2, std::iter::empty())
}

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

fn configure(
    app: &WalletApp,
    electrum: &str,
    rpc: Option<&str>,
    peers: &[&str],
    via_own_node: bool,
) {
    let mut guard = app.lock_state().unwrap();
    let state = guard.as_mut().unwrap();
    state.electrum_url = electrum.into();
    state.electrum_use_public_fallback = false;
    state.active_electrum_url = None;
    state.litecoin_rpc_url = rpc.map(str::to_string);
    state.broadcast_via_own_node = via_own_node;
    state.mweb_peers = peers.iter().map(|peer| (*peer).to_string()).collect();
    let meta = meta_from_state(state);
    let dir = state.data_dir.clone();
    drop(guard);
    meta::write_meta(&dir, &meta).unwrap();
}

fn block_seal_counter(data_dir: &Path) {
    let path = meta::mweb_seal_counter_path(data_dir);
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir_all(&path).unwrap();
}

fn churn_req(id: &str, target_depth: u32, cover_min: u32) -> ChurnRequest {
    ChurnRequest {
        output_id: id.into(),
        target_depth,
        cover_min,
        spread_send: false,
    }
}

fn force_cover_min_zero(app: &WalletApp) {
    let dir = account_dir(app);
    let mut job = churn::read_job(&dir).unwrap().unwrap();
    job.cover_min = 0;
    let mut record = churn::read_armed(&dir).unwrap().unwrap();
    record.cover_min = 0;
    churn::write_job(&dir, &job).unwrap();
    churn::write_armed(&dir, &record).unwrap();
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

fn unspent_ids(app: &WalletApp) -> Vec<String> {
    let mut ids: Vec<String> = app
        .list_mweb_unspent()
        .unwrap()
        .into_iter()
        .map(|coin| coin.output_id)
        .collect();
    ids.sort();
    ids
}

fn history_ids(app: &WalletApp) -> Vec<String> {
    let guard = app.lock_state().unwrap();
    let state = guard.as_ref().unwrap();
    state
        .mweb
        .as_ref()
        .unwrap()
        .history
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect()
}

fn assert_build(err: WalletError, message: &str) {
    assert_eq!(
        err.to_string(),
        format!("failed to build transaction: {message}"),
        "rejection message"
    );
}

fn assert_locked(app: &WalletApp) {
    assert!(app.is_locked());
    assert!(!app.pending_lock.load(Ordering::Acquire));
    assert!(app.state.lock().unwrap().is_none());
}

fn unlock_load(app: &WalletApp, root: &Path) {
    app.unlock(UnlockRequest {
        passphrase: PASSPHRASE.into(),
    })
    .unwrap();
    app.load(root).unwrap();
}

struct DiskSnap {
    job: Option<Vec<u8>>,
    armed: Option<Vec<u8>>,
    frozen: Option<Vec<u8>>,
    unspent: Vec<String>,
}

fn snap(app: &WalletApp) -> DiskSnap {
    let dir = account_dir(app);
    DiskSnap {
        job: std::fs::read(churn::job_path(&dir)).ok(),
        armed: std::fs::read(churn::armed_path(&dir)).ok(),
        frozen: std::fs::read(mweb_frozen::frozen_path(&dir)).ok(),
        unspent: unspent_ids(app),
    }
}

fn assert_snap(app: &WalletApp, before: &DiskSnap) {
    let after = snap(app);
    assert_eq!(after.job, before.job, "churn_job.json changed");
    assert_eq!(after.armed, before.armed, "churn_armed.json changed");
    assert_eq!(after.frozen, before.frozen, "mweb_frozen.json changed");
    assert_eq!(after.unspent, before.unspent, "unspent coins changed");
}

/// Accept until a peer sends bytes (the MWEB handshake or an Electrum request).
/// A probe connects and drops without writing; that socket is ignored.
fn take_speaking_connection(listener: &std::net::TcpListener) -> std::net::TcpStream {
    take_speaking_while(listener, || None)
}

fn take_speaking_while(
    listener: &std::net::TcpListener,
    mut finished: impl FnMut() -> Option<String>,
) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    // Signing the spend happens before the first TCP connect.
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    let mut quiet: Option<(std::net::TcpStream, std::time::Instant)> = None;
    loop {
        if let Some(err) = finished() {
            panic!("spend returned before connecting: {err}");
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for the spend connection");
        }
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                let mut buf = [0u8; 8];
                match Read::read(&mut &stream, &mut buf) {
                    Ok(0) => continue,
                    Ok(_) => return stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        quiet = Some((stream, std::time::Instant::now()));
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::ConnectionReset
                            || e.kind() == std::io::ErrorKind::ConnectionAborted =>
                    {
                        continue;
                    }
                    Err(e) => panic!("reading the spend connection: {e}"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some((stream, at)) = quiet.take() {
                    if at.elapsed() >= Duration::from_millis(400) {
                        return stream;
                    }
                    quiet = Some((stream, at));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

struct RpcStub {
    url: String,
    sends: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl RpcStub {
    fn start(fail_send: bool) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let sends = Arc::new(AtomicUsize::new(0));
        let stop_flag = Arc::clone(&stop);
        let send_count = Arc::clone(&sends);
        let join = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => serve_rpc(stream, fail_send, &send_count),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            url,
            sends,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for RpcStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn serve_rpc(stream: std::net::TcpStream, fail_send: bool, sends: &AtomicUsize) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut reader = std::io::BufReader::new(stream);
    let mut header = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        header.push_str(&line);
    }
    let len = header
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|n| n.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let method = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| value.get("method")?.as_str().map(str::to_string))
        .unwrap_or_default();
    let (status, reason, payload) = if method == "sendrawtransaction" {
        sends.fetch_add(1, Ordering::Relaxed);
        if fail_send {
            (
                500,
                "Internal Server Error",
                serde_json::json!({
                    "result": null,
                    "error": {"code": -26, "message": "rejected"},
                    "id": "ltc-wallet"
                }),
            )
        } else {
            (
                200,
                "OK",
                serde_json::json!({"result": "ok", "error": null, "id": "ltc-wallet"}),
            )
        }
    } else if method == "getblockcount" {
        (
            200,
            "OK",
            serde_json::json!({"result": 100, "error": null, "id": "ltc-wallet"}),
        )
    } else if method == "getrawmempool" {
        (
            200,
            "OK",
            serde_json::json!({"result": [], "error": null, "id": "ltc-wallet"}),
        )
    } else {
        (
            200,
            "OK",
            serde_json::json!({"result": null, "error": null, "id": "ltc-wallet"}),
        )
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    let mut stream = reader.into_inner();
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&bytes);
}

fn mweb_send_req(address: &str, id: &str, amount_sats: u64) -> MwebSendRequest {
    MwebSendRequest {
        address: address.into(),
        amount_sats,
        fee_sats: legal_mweb_fee(),
        drain: false,
        selected_output_ids: Some(vec![id.into()]),
    }
}

fn private_split_req(id: &str) -> SplitRequest {
    SplitRequest {
        chain: SplitChain::Private,
        input: id.into(),
        equal_count: Some(2),
        amounts: Vec::new(),
        fee_rate_sat_vb: None,
        fee_sats: legal_mweb_fee(),
    }
}

/// A loopback peer that stays open until the caller drops the stream.
fn bind_peer() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, format!("{}:{}", addr.ip(), addr.port()))
}

#[test]
fn lock_during_private_send_broadcast_releases_hold_and_drops_state() {
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    persist_private(&app);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[1].clone(),
        locked: true,
    })
    .unwrap();
    let data_dir = account_dir(&app);
    let (listener, peer) = bind_peer();
    configure(&app, "tcp://127.0.0.1:9", None, &[&peer], false);
    let address = app.mweb_receive_address().unwrap();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            crate::discovery::go_offline_for_test();
            let result = app.mweb_send(mweb_send_req(&address, &ids[0], 100_000));
            if let Err(err) = &result {
                let _ = done_tx.send(err.to_string());
            }
            result
        });
        let stream = take_speaking_while(&listener, || done_rx.try_recv().ok());
        assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Sending);
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .reserved
            .contains_key(&ids[0]));
        app.lock();
        drop(stream);
        let err = worker.join().unwrap().unwrap_err();
        assert!(
            err.to_string().contains("could not reach") || err.to_string().contains("broadcast"),
            "{err}"
        );
    });

    assert_locked(&app);
    let file = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(
        file.reserved.is_empty(),
        "the in-flight hold is released while locked"
    );
    assert!(file.ids.contains(&ids[1]), "a bystander freeze stays");
    unlock_load(&app, dir.path());
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Ready);
    assert_eq!(private_row(&app, &ids[1]).status, CoinStatus::Frozen);
}

#[test]
fn lock_during_public_split_broadcast_releases_hold_and_drops_state() {
    let dir = tempfile::tempdir().unwrap();
    let (app, outs) = app_with_public_coins(dir.path(), &[1_000_000, 2_000_000]);
    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outs[1].to_string(),
        locked: true,
    })
    .unwrap();
    let data_dir = account_dir(&app);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let electrum = format!("tcp://{}", listener.local_addr().unwrap());
    configure(&app, &electrum, None, &[], false);

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            app.split_coin(SplitRequest {
                chain: SplitChain::Public,
                input: outs[0].to_string(),
                equal_count: Some(2),
                amounts: Vec::new(),
                fee_rate_sat_vb: Some(1),
                fee_sats: 0,
            })
        });
        let stream = take_speaking_connection(&listener);
        assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Sending);
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .public_reserved
            .contains_key(&outs[0].to_string()));
        app.lock();
        drop(stream);
        assert!(worker.join().unwrap().is_err());
    });

    assert_locked(&app);
    let file = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(file.public_reserved.is_empty());
    unlock_load(&app, dir.path());
    assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Ready);
    assert_eq!(public_row(&app, &outs[1]).status, CoinStatus::Frozen);
    assert!(public_row(&app, &outs[1]).locked);
}

#[test]
fn lock_during_public_send_broadcast_releases_hold_and_drops_state() {
    let dir = tempfile::tempdir().unwrap();
    let (app, outs) = app_with_public_coins(dir.path(), &[1_000_000, 2_000_000]);
    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: outs[1].to_string(),
        locked: true,
    })
    .unwrap();
    let data_dir = account_dir(&app);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let electrum = format!("tcp://{}", listener.local_addr().unwrap());
    configure(&app, &electrum, None, &[], false);
    let address = app.receive_address().unwrap();

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            app.send(SendRequest {
                address: address.clone(),
                amount_sats: 10_000,
                fee_rate_sat_vb: Some(1),
                drain: false,
                selected_outpoints: Some(vec![outs[0].to_string()]),
            })
        });
        let stream = take_speaking_connection(&listener);
        assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Sending);
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .public_reserved
            .contains_key(&outs[0].to_string()));
        app.lock();
        drop(stream);
        assert!(worker.join().unwrap().is_err());
    });

    assert_locked(&app);
    let file = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(file.public_reserved.is_empty());
    unlock_load(&app, dir.path());
    assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Ready);
    assert_eq!(public_row(&app, &outs[1]).status, CoinStatus::Frozen);
    assert!(public_row(&app, &outs[1]).locked);
}

#[test]
fn lock_during_resync_aborts_at_check_lock_and_resets_sync_phase() {
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let data_dir = account_dir(&app);
    let (listener, peer) = bind_peer();
    configure(&app, "tcp://127.0.0.1:9", None, &[&peer], false);

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            crate::discovery::go_offline_for_test();
            app.set_mweb_scheme(MwebScheme::Mwebd)
        });
        let stream = take_speaking_connection(&listener);
        let progress = app.mweb_sync_progress();
        assert_eq!(progress.phase, SyncPhase::MwebDownload);
        assert!(progress.active);
        app.lock();
        drop(stream);
        let err = worker.join().unwrap().unwrap_err();
        assert!(matches!(err, WalletError::Locked), "{err}");
    });

    let progress = app.mweb_sync_progress();
    assert_eq!(progress.phase, SyncPhase::Idle);
    assert!(!progress.active);
    assert_locked(&app);
    assert!(meta::read_meta(&data_dir).unwrap().needs_mweb_scan);
}

#[test]
fn locked_pump_expiry_reconciles_on_load_and_allows_retry() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);
    let phantom = churn::read_job(&data_dir)
        .unwrap()
        .unwrap()
        .current_output_id
        .clone();
    {
        let mut record = churn::read_armed(&data_dir).unwrap().unwrap();
        record.armed_at_unix = churn::unix_now().saturating_sub(churn::ARMED_EXPIRY_SECS);
        churn::write_armed(&data_dir, &record).unwrap();
    }

    app.lock();
    app.pump_churn_broadcast(&data_dir).unwrap();
    assert!(churn::read_armed(&data_dir).unwrap().unwrap().expired);
    unlock_load(&app, dir.path());

    let listed = unspent_ids(&app);
    assert!(
        listed.contains(&ids[0]),
        "the original coin is spendable again"
    );
    assert!(!listed.contains(&phantom), "the expired output is gone");
    let status = app.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingForCover);
    assert_eq!(status.last_error.as_deref(), Some(churn::EXPIRED_SPEND));
    assert!(status.actions.retry);

    let retried = app.retry_churn().unwrap();
    assert_eq!(retried.phase, ChurnPhase::WaitingForCover);
    assert!(retried.last_error.is_none());
    assert!(!churn::read_armed(&data_dir).unwrap().unwrap().expired);
}

#[test]
fn locked_pump_multihop_broadcast_applies_on_load() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 2, 1)).unwrap();
    let data_dir = account_dir(&app);
    let stub = RpcStub::start(false);
    let (first_created, second_created) = {
        let mut record = churn::read_armed(&data_dir).unwrap().unwrap();
        record.hops[0].broadcast = true;
        assert!(churn::arm_next(&mut record, churn::unix_now(), 0));
        record.cover_min = 0;
        let first = record.hops[0].created_output_id.clone();
        let second = record.hops[1].created_output_id.clone();
        churn::write_armed(&data_dir, &record).unwrap();
        let mut job = churn::read_job(&data_dir).unwrap().unwrap();
        job.cover_min = 0;
        churn::write_job(&data_dir, &job).unwrap();
        (first, second)
    };
    configure(&app, "tcp://127.0.0.1:9", Some(&stub.url), &[], true);

    app.lock();
    app.pump_churn_broadcast(&data_dir).unwrap();
    let mid = churn::read_job(&data_dir).unwrap().unwrap();
    assert_eq!(mid.phase(), ChurnPhase::WaitingConfirm);
    assert_eq!(mid.current_output_id, second_created);
    unlock_load(&app, dir.path());

    let listed = unspent_ids(&app);
    assert!(!listed.contains(&first_created));
    assert!(listed.contains(&second_created));
    assert_eq!(
        private_row(&app, &second_created).status,
        CoinStatus::Churning
    );
    let frozen = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(!frozen.ids.contains(&first_created));
    assert!(frozen.ids.contains(&second_created));
}

#[test]
fn broadcast_hop_clears_the_spent_coin_freeze() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    force_cover_min_zero(&app);
    let data_dir = account_dir(&app);
    let stub = RpcStub::start(false);
    configure(&app, "tcp://127.0.0.1:9", Some(&stub.url), &[], true);
    let created = churn::read_job(&data_dir)
        .unwrap()
        .unwrap()
        .current_output_id
        .clone();

    app.pump_churn_broadcast(&data_dir).unwrap();

    let status = app.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingConfirm);
    let frozen = mweb_frozen::read_ids(&data_dir).unwrap();
    assert!(
        !frozen.ids.contains(&ids[0]),
        "the spent coin's freeze does not outlive the broadcast"
    );
    assert!(frozen.ids.contains(&created));
    assert!(churn::read_armed(&data_dir).unwrap().unwrap().hops[0].broadcast);
}

#[test]
fn start_churn_persist_failure_leaves_coin_ready_and_no_job() {
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    block_seal_counter(&account_dir(&app));

    assert!(app.start_churn(churn_req(&ids[0], 1, 1)).is_err());

    assert!(app.churn_status().unwrap().is_none());
    let data_dir = account_dir(&app);
    assert!(!churn::armed_path(&data_dir).exists());
    assert!(!mweb_frozen::frozen_path(&data_dir).exists());
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Ready);
}

#[test]
fn retry_churn_persist_failure_keeps_paused_job_and_coin_churning() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);
    let shown = {
        let mut job = churn::read_job(&data_dir).unwrap().unwrap();
        job.set_phase_for_test(ChurnPhase::PausedSolo);
        churn::write_job(&data_dir, &job).unwrap();
        job.current_output_id.clone()
    };
    block_seal_counter(&data_dir);

    assert!(app.retry_churn().is_err());

    let job = churn::read_job(&data_dir).unwrap().unwrap();
    assert_eq!(job.phase(), ChurnPhase::PausedSolo);
    let status = app.churn_status().unwrap().unwrap();
    assert!(status.actions.retry);
    assert_eq!(private_row(&app, &shown).status, CoinStatus::Churning);

    // An expiry written before the re-sign's persist fails keeps the phase and the retry flag.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);
    {
        let mut record = churn::read_armed(&data_dir).unwrap().unwrap();
        record.expired = true;
        churn::write_armed(&data_dir, &record).unwrap();
    }
    block_seal_counter(&data_dir);
    assert!(app.retry_churn().is_err());
    let job = churn::read_job(&data_dir).unwrap().unwrap();
    assert_eq!(job.phase(), ChurnPhase::WaitingForCover);
    assert!(app.churn_status().unwrap().unwrap().actions.retry);
    assert_eq!(
        private_row(&app, &ids[0]).status,
        CoinStatus::Churning,
        "undo put the original coin back before the persist failed"
    );
}

#[test]
fn private_split_persist_failure_takes_no_hold() {
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    let data_dir = account_dir(&app);
    block_seal_counter(&data_dir);

    assert!(app.split_coin(private_split_req(&ids[0])).is_err());

    assert!(mweb_frozen::read_ids(&data_dir)
        .unwrap()
        .reserved
        .is_empty());
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Ready);
}

#[test]
fn set_mweb_scheme_persist_failure_leaves_sync_idle_and_scan_flagged() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let data_dir = account_dir(&app);
    configure(&app, "tcp://127.0.0.1:9", None, &[], false);
    block_seal_counter(&data_dir);

    assert!(app.set_mweb_scheme(MwebScheme::Mwebd).is_err());

    let progress = app.mweb_sync_progress();
    assert_eq!(progress.phase, SyncPhase::Idle);
    assert!(!progress.active);
    assert!(meta::read_meta(&data_dir).unwrap().needs_mweb_scan);
}

#[test]
fn failed_private_spends_release_holds_and_keep_coins_ready() {
    crate::discovery::go_offline_for_test();
    let cases = [false, true];
    for via_own_node in cases {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
        app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: ids[1].clone(),
            locked: true,
        })
        .unwrap();
        let rpc = if via_own_node {
            Some("http://127.0.0.1:9")
        } else {
            None
        };
        configure(
            &app,
            "tcp://127.0.0.1:9",
            rpc,
            &["127.0.0.1:9"],
            via_own_node,
        );
        let address = app.mweb_receive_address().unwrap();
        let before_history = history_ids(&app);
        let data_dir = account_dir(&app);

        let err = app
            .mweb_send(mweb_send_req(&address, &ids[0], 100_000))
            .unwrap_err();
        assert!(!err.to_string().is_empty());
        assert!(mweb_frozen::read_ids(&data_dir)
            .unwrap()
            .reserved
            .is_empty());
        assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Ready);
        assert_eq!(private_row(&app, &ids[1]).status, CoinStatus::Frozen);
        assert_eq!(history_ids(&app), before_history);
        assert_eq!(unspent_ids(&app).len(), 2);
    }

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[1].clone(),
        locked: true,
    })
    .unwrap();
    configure(&app, "tcp://127.0.0.1:9", None, &["127.0.0.1:9"], false);
    let address = app.receive_address().unwrap();
    assert!(app
        .pegout(super::pegout_req(&address, 100_000, false, &ids[..1]))
        .is_err());
    assert!(app
        .pegout(super::pegout_req("", 0, true, &ids[..1]))
        .is_err());
    assert!(app.split_coin(private_split_req(&ids[0])).is_err());
    app.create_wallet_account(
        dir.path(),
        CreateAccountRequest {
            name: "Other".into(),
        },
    )
    .unwrap();
    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    configure(&app, "tcp://127.0.0.1:9", None, &["127.0.0.1:9"], false);
    assert!(app
        .transfer_coin(
            dir.path(),
            TransferCoinRequest {
                chain: SplitChain::Private,
                coin_id: ids[0].clone(),
                to_account_index: 1,
                fee_rate_sat_vb: None,
                fee_sats: legal_mweb_fee(),
            },
        )
        .is_err());
    let data_dir = account_dir(&app);
    assert!(mweb_frozen::read_ids(&data_dir)
        .unwrap()
        .reserved
        .is_empty());
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Ready);
    assert_eq!(private_row(&app, &ids[1]).status, CoinStatus::Frozen);
    assert_eq!(unspent_ids(&app).len(), 2);
}

#[test]
fn failed_public_spends_and_pegin_release_holds_and_unmask_locks() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, outs) = app_with_public_coins(dir.path(), &[1_000_000, 2_000_000]);
    configure(&app, "tcp://127.0.0.1:9", None, &[], false);
    let address = app.receive_address().unwrap();
    let before = app.list_unspent().unwrap().len();
    assert!(app
        .send(SendRequest {
            address: address.clone(),
            amount_sats: 10_000,
            fee_rate_sat_vb: Some(1),
            drain: false,
            selected_outpoints: Some(vec![outs[0].to_string()]),
        })
        .is_err());
    assert_eq!(app.list_unspent().unwrap().len(), before);
    assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Ready);
    assert!(mweb_frozen::read_ids(&account_dir(&app))
        .unwrap()
        .public_reserved
        .is_empty());

    app.create_wallet_account(
        dir.path(),
        CreateAccountRequest {
            name: "Other".into(),
        },
    )
    .unwrap();
    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    configure(&app, "tcp://127.0.0.1:9", None, &[], false);
    assert!(app
        .transfer_coin(
            dir.path(),
            TransferCoinRequest {
                chain: SplitChain::Public,
                coin_id: outs[0].to_string(),
                to_account_index: 1,
                fee_rate_sat_vb: Some(1),
                fee_sats: 0,
            },
        )
        .is_err());
    assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Ready);
    assert!(mweb_frozen::read_ids(&account_dir(&app))
        .unwrap()
        .public_reserved
        .is_empty());

    let _hold = CoinHold::take_public(&account_dir(&app), vec![outs[1]], &app.session).unwrap();
    configure(&app, "tcp://127.0.0.1:9", None, &["127.0.0.1:9"], false);
    let mweb_before = app.list_mweb_unspent().unwrap().len();
    assert!(app
        .pegin(PeginRequest {
            amount_sats: 100_000,
            mweb_fee_sats: legal_mweb_fee(),
            transparent_fee_sats: 10_000,
            drain: false,
            selected_outpoints: Some(vec![outs[0].to_string()]),
        })
        .is_err());
    let guard = app.lock_state().unwrap();
    let state = guard.as_ref().unwrap();
    assert!(!state.wallet.is_outpoint_locked(outs[0]));
    assert!(!state.wallet.is_outpoint_locked(outs[1]));
    drop(guard);
    assert_eq!(public_row(&app, &outs[1]).status, CoinStatus::Sending);
    assert_eq!(public_row(&app, &outs[0]).status, CoinStatus::Ready);
    assert!(mweb_frozen::read_ids(&account_dir(&app))
        .unwrap()
        .public_reserved
        .contains_key(&outs[1].to_string()));
    assert!(!mweb_frozen::read_ids(&account_dir(&app))
        .unwrap()
        .public_reserved
        .contains_key(&outs[0].to_string()));
    assert_eq!(app.list_mweb_unspent().unwrap().len(), mweb_before);
}

#[test]
fn failed_electrum_sync_leaves_phase_idle_and_state_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let data_dir = account_dir(&app);
    configure(&app, "tcp://127.0.0.1:9", None, &[], false);
    assert!(meta::read_meta(&data_dir).unwrap().needs_full_scan);

    let (cursor, _) = diag::since(u64::MAX);
    assert!(app.sync().is_err());
    let (_, lines) = diag::since(cursor);
    assert!(
        lines.iter().any(|l| l.contains("sync: failed:")),
        "missing sync failure log in {lines:#?}"
    );

    assert_eq!(app.mweb_sync_progress().phase, SyncPhase::Idle);
    assert!(meta::read_meta(&data_dir).unwrap().needs_full_scan);
}

#[test]
fn unreachable_mweb_peers_mark_resync_stale_without_failing() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    configure(&app, "tcp://127.0.0.1:9", None, &["127.0.0.1:9"], false);

    app.resync_mweb().unwrap();

    assert_eq!(app.mweb_sync_progress().phase, SyncPhase::Done);
    assert!(!app.mweb_sync_progress().active);
    assert!(app.combined_summary().unwrap().mweb_stale);
}

#[test]
fn churn_broadcast_failure_pauses_job_until_retry() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    force_cover_min_zero(&app);
    let data_dir = account_dir(&app);
    let stub = RpcStub::start(true);
    configure(&app, "tcp://127.0.0.1:9", Some(&stub.url), &[], false);

    app.pump_churn_broadcast(&data_dir).unwrap();
    let status = app.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingToBroadcast);
    assert!(status.actions.retry && status.actions.cancel);
    assert!(!churn::read_armed(&data_dir).unwrap().unwrap().hops[0].broadcast);
    let sends = stub.sends.load(Ordering::Relaxed);
    assert!(sends >= 1);

    app.pump_churn_broadcast(&data_dir).unwrap();
    assert_eq!(
        stub.sends.load(Ordering::Relaxed),
        sends,
        "a paused broadcast is not sent again"
    );
    assert_eq!(
        app.churn_status().unwrap().unwrap().phase,
        ChurnPhase::WaitingToBroadcast
    );
}

#[test]
fn churn_unread_headers_and_not_included_grace_transitions() {
    crate::discovery::go_offline_for_test();

    // Headers cannot be read: the hop stays where it is.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    configure(&app, "tcp://127.0.0.1:9", None, &[], false);
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        raise_tip(state, 20);
        let mut job = churn::read_job(&state.data_dir).unwrap().unwrap();
        let wtxid = churn::read_armed(&state.data_dir).unwrap().unwrap().hops[0]
            .wtxid
            .clone();
        job.set_phase_for_test(ChurnPhase::WaitingConfirm);
        job.broadcast_height = Some(1);
        job.pending_wtxid = Some(wtxid);
        churn::write_job(&state.data_dir, &job).unwrap();
        drive_churn(state, None).unwrap();
    }
    assert_eq!(
        app.churn_status().unwrap().unwrap().phase,
        ChurnPhase::WaitingConfirm
    );

    // Still inside the grace window, a paused unscored hop goes back to waiting.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        raise_tip(state, 20);
        state.mweb.as_mut().unwrap().sync_state.leafset = vec![0x80];
        let mut job = churn::read_job(&state.data_dir).unwrap().unwrap();
        let wtxid = churn::read_armed(&state.data_dir).unwrap().unwrap().hops[0]
            .wtxid
            .clone();
        job.set_phase_for_test(ChurnPhase::PausedUnscored);
        job.broadcast_height = Some(18);
        job.pending_wtxid = Some(wtxid);
        churn::write_job(&state.data_dir, &job).unwrap();
        drive_churn(state, None).unwrap();
    }
    assert_eq!(
        app.churn_status().unwrap().unwrap().phase,
        ChurnPhase::WaitingConfirm
    );

    // Past the grace window, an input that is still unspent restores the original coin.
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        raise_tip(state, 20);
        state.mweb.as_mut().unwrap().sync_state.leafset = vec![0x80];
        let mut job = churn::read_job(&state.data_dir).unwrap().unwrap();
        let wtxid = churn::read_armed(&state.data_dir).unwrap().unwrap().hops[0]
            .wtxid
            .clone();
        job.set_phase_for_test(ChurnPhase::WaitingConfirm);
        job.broadcast_height = Some(0);
        job.pending_wtxid = Some(wtxid);
        churn::write_job(&state.data_dir, &job).unwrap();
        drive_churn(state, None).unwrap();
    }
    let status = app.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingToBroadcast);
    assert!(status.actions.retry);
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Churning);
    assert!(
        churn::read_job(&account_dir(&app))
            .unwrap()
            .unwrap()
            .needs_resign
    );
    assert!(churn::read_armed(&account_dir(&app)).unwrap().is_none());
}

fn raise_tip(state: &mut WalletState, height: u32) {
    use bdk_wallet::bitcoin::hashes::Hash;
    use bdk_wallet::bitcoin::BlockHash;
    use bdk_wallet::chain::BlockId;
    use bdk_wallet::test_utils::insert_checkpoint;
    insert_checkpoint(
        &mut state.wallet,
        BlockId {
            height,
            hash: BlockHash::all_zeros(),
        },
    );
}

#[test]
fn foreign_spend_detected_on_pass_drops_phantom_and_cleans_freezes_on_cancel() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let phantom = churn::read_job(&account_dir(&app))
        .unwrap()
        .unwrap()
        .current_output_id
        .clone();
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        // Leaf 0, the spent input, is absent. Leaf 8 keeps the set non-empty.
        state.mweb.as_mut().unwrap().sync_state.leafset = vec![0x00, 0x80];
        drive_churn(state, None).unwrap();
    }

    let status = app.churn_status().unwrap().unwrap();
    assert_eq!(status.phase, ChurnPhase::WaitingForCover);
    assert_eq!(status.last_error.as_deref(), Some(churn::FOREIGN_SPEND));
    assert!(!status.actions.retry && status.actions.cancel);
    assert!(churn::read_armed(&account_dir(&app)).unwrap().is_none());
    let listed = unspent_ids(&app);
    assert!(!listed.contains(&phantom));
    assert!(!listed.contains(&ids[0]));
    assert_eq!(private_row(&app, &ids[1]).status, CoinStatus::Ready);
    assert_build(
        app.retry_churn().unwrap_err(),
        &format!("{} Cancel this self-spend.", churn::FOREIGN_SPEND),
    );

    let cancelled = app.cancel_churn().unwrap();
    assert_eq!(cancelled.phase, ChurnPhase::Cancelled);
    assert!(!mweb_frozen::frozen_path(&account_dir(&app)).exists());
}

#[test]
fn rejected_churn_commands_leave_files_and_coins_untouched() {
    crate::discovery::go_offline_for_test();
    let reject_retry = "There is no paused self-spend to try again.";
    let reject_cancel = "There is no self-spend to cancel.";
    let reject_confirm = "This self-spend is already on the network. Wait for the next block.";

    for phase in ChurnPhase::ALL {
        let dir = tempfile::tempdir().unwrap();
        let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
        clear_planted_job(&app);
        app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
        {
            let dir = account_dir(&app);
            let mut job = churn::read_job(&dir).unwrap().unwrap();
            job.set_phase_for_test(phase);
            churn::write_job(&dir, &job).unwrap();
        }
        let before = snap(&app);
        let retry_rejected = !matches!(
            phase,
            ChurnPhase::WaitingToBroadcast
                | ChurnPhase::WaitingForCover
                | ChurnPhase::PausedSolo
                | ChurnPhase::PausedUnscored
        );
        let cancel_rejected = !matches!(
            phase,
            ChurnPhase::WaitingToBroadcast
                | ChurnPhase::WaitingForCover
                | ChurnPhase::PausedSolo
                | ChurnPhase::PausedUnscored
        );
        if retry_rejected {
            let expected = reject_retry;
            assert_build(app.retry_churn().unwrap_err(), expected);
            assert_snap(&app, &before);
        }
        if cancel_rejected {
            let expected = if phase == ChurnPhase::WaitingConfirm {
                reject_confirm
            } else {
                reject_cancel
            };
            assert_build(app.cancel_churn().unwrap_err(), expected);
            assert_snap(&app, &before);
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let data_dir = account_dir(&app);
    std::fs::remove_file(churn::job_path(&data_dir)).unwrap();
    let before = snap(&app);
    assert_build(
        app.retry_churn().unwrap_err(),
        "There is no self-spend to try again.",
    );
    assert_build(
        app.cancel_churn().unwrap_err(),
        "There is no self-spend to cancel.",
    );
    assert_snap(&app, &before);
}

#[test]
fn early_return_validations_leave_phases_holds_and_coins_untouched() {
    crate::discovery::go_offline_for_test();

    // An active job refuses a second one.
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::WaitingForCover, false);
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        insert_private_coin(state, [0x41; 32], 3_000_000, Some(0), false);
    }
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&hex::encode([0x41; 32]), 1, 1))
            .unwrap_err(),
        "A self-spend is already in progress.",
    );
    assert_snap(&app, &before);

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[0].clone(),
        locked: true,
    })
    .unwrap();
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&ids[0], 1, 1)).unwrap_err(),
        "Unfreeze this coin before spending it to yourself.",
    );
    assert_snap(&app, &before);

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    let _hold = CoinHold::take(&account_dir(&app), vec![ids[0].clone()], &app.session).unwrap();
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&ids[0], 1, 1)).unwrap_err(),
        "Unfreeze this coin before spending it to yourself.",
    );
    assert_snap(&app, &before);
    assert_eq!(private_row(&app, &ids[0]).status, CoinStatus::Sending);

    let dir = tempfile::tempdir().unwrap();
    let (app, _) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    let pending = [0x71; 32];
    {
        let mut guard = app.lock_state().unwrap();
        insert_private_coin(guard.as_mut().unwrap(), pending, 3_000_000, None, false);
    }
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&hex::encode(pending), 1, 1))
            .unwrap_err(),
        "This coin is not spendable yet.",
    );
    assert_snap(&app, &before);

    let maturing = [0x72; 32];
    {
        let mut guard = app.lock_state().unwrap();
        insert_private_coin(guard.as_mut().unwrap(), maturing, 3_000_000, Some(0), true);
    }
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&hex::encode(maturing), 1, 1))
            .unwrap_err(),
        "This coin is not spendable yet.",
    );
    assert_snap(&app, &before);

    let dir = tempfile::tempdir().unwrap();
    // Exactly two one-output hop fees: `amount <= fee * target` is rejected.
    let two_hops = crate::tx_invariants::min_kernel_fee(1, std::iter::empty()).saturating_mul(2);
    let (app, ids) = app_with_private_coins(dir.path(), &[two_hops]);
    clear_planted_job(&app);
    let before = snap(&app);
    assert_build(
        app.start_churn(churn_req(&ids[0], 2, 1)).unwrap_err(),
        "This coin is too small to pay the fee.",
    );
    assert_build(
        app.start_churn(churn_req(&ids[0], 11, 1)).unwrap_err(),
        "Choose between 1 and 10 blocks.",
    );
    assert_build(
        app.start_churn(churn_req(&ids[0], 1, 11)).unwrap_err(),
        "Choose between 1 and 10 other private transactions.",
    );
    assert_snap(&app, &before);

    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000, 2_000_000]);
    clear_planted_job(&app);
    let address = app.receive_address().unwrap();
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: ids[0].clone(),
        locked: true,
    })
    .unwrap();
    let before = snap(&app);
    for err in [
        app.mweb_send(mweb_send_req(&address, &ids[0], 100_000))
            .unwrap_err(),
        app.pegout(super::pegout_req(&address, 100_000, false, &ids[..1]))
            .unwrap_err(),
        app.split_coin(private_split_req(&ids[0])).unwrap_err(),
    ] {
        assert!(err.to_string().contains("frozen"), "{err}");
    }
    assert_snap(&app, &before);

    let _hold = CoinHold::take(&account_dir(&app), vec![ids[1].clone()], &app.session).unwrap();
    let before = snap(&app);
    let err = app
        .mweb_send(mweb_send_req(&address, &ids[1], 100_000))
        .unwrap_err();
    assert!(err.to_string().contains("frozen"), "{err}");
    assert_snap(&app, &before);
    assert_eq!(private_row(&app, &ids[1]).status, CoinStatus::Sending);

    let immature = [0x73; 32];
    {
        let mut guard = app.lock_state().unwrap();
        insert_private_coin(guard.as_mut().unwrap(), immature, 3_000_000, None, false);
    }
    let before = snap(&app);
    let err = app
        .mweb_send(mweb_send_req(&address, &hex::encode(immature), 100_000))
        .unwrap_err();
    assert!(err.to_string().contains("not yet spendable"), "{err}");
    assert_snap(&app, &before);

    let before = snap(&app);
    assert_eq!(
        app.transfer_coin(
            dir.path(),
            TransferCoinRequest {
                chain: SplitChain::Private,
                coin_id: ids[1].clone(),
                to_account_index: 0,
                fee_rate_sat_vb: None,
                fee_sats: legal_mweb_fee(),
            },
        )
        .unwrap_err()
        .to_string(),
        "metadata error: cannot transfer a coin to the active wallet"
    );
    assert_snap(&app, &before);
}

#[test]
fn phase_changes_holds_and_rejections_appear_in_diagnostic_log_and_bundle() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, pub_outs) = app_with_public_coins(dir.path(), &[2_000_000]);
    let priv_id = "f1".repeat(32);
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        insert_private_coin(state, [0xf1; 32], 3_000_000, Some(0), false);
    }
    persist_private(&app);
    clear_planted_job(&app);

    let (cursor, _) = diag::since(u64::MAX);

    // 1. SyncPass transitions: early drop resets to Idle; finish reaches Done.
    {
        let pass = app.sync_pass();
        pass.electrum(true);
        pass.mweb();
        drop(pass);
    }
    {
        let pass = app.sync_pass();
        pass.electrum(false);
        pass.finish();
    }

    // 2. Lock lifecycle: Loaded -> LockPending -> Locked (CheckLock and ReleaseGuard),
    // rejected Unlock, UnlockedEmpty -> Loaded, and rejected command while Locked.
    {
        let mut guard = app.lock_state().unwrap();
        app.lock();
        assert!(guard.check_lock().is_err());
    }
    assert!(app.summary().is_err());
    assert!(app
        .unlock(UnlockRequest {
            passphrase: "wrong passphrase".into(),
        })
        .is_err());
    unlock_load(&app, dir.path());
    {
        let guard = app.lock_state().unwrap();
        app.lock();
        drop(guard);
    }
    unlock_load(&app, dir.path());

    // 3. Holds and freeze/unfreeze commands + rejections (private and public).
    let data_dir = account_dir(&app);
    let priv_hold = CoinHold::take(&data_dir, vec![priv_id.clone()], &app.session).unwrap();
    let pub_hold = CoinHold::take_public(&data_dir, vec![pub_outs[0]], &app.session).unwrap();

    // Freeze while held must be rejected and logged.
    assert!(app
        .set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: priv_id.clone(),
            locked: true,
        })
        .is_err());
    assert!(app
        .set_utxo_locked(SetUtxoLockedRequest {
            outpoint: pub_outs[0].to_string(),
            locked: true,
        })
        .is_err());
    drop(priv_hold);
    drop(pub_hold);

    // User freeze -> repeat freeze rejected -> unfreeze (private and public).
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: priv_id.clone(),
        locked: true,
    })
    .unwrap();
    assert!(app
        .set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
            output_id: priv_id.clone(),
            locked: true,
        })
        .is_err());
    app.set_mweb_utxo_locked(SetMwebUtxoLockedRequest {
        output_id: priv_id.clone(),
        locked: false,
    })
    .unwrap();

    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: pub_outs[0].to_string(),
        locked: true,
    })
    .unwrap();
    assert!(app
        .set_utxo_locked(SetUtxoLockedRequest {
            outpoint: pub_outs[0].to_string(),
            locked: true,
        })
        .is_err());
    app.set_utxo_locked(SetUtxoLockedRequest {
        outpoint: pub_outs[0].to_string(),
        locked: false,
    })
    .unwrap();

    // 4. Churn command rejections (no job on disk, invalid target) + start & cancel transitions.
    assert!(app.retry_churn().is_err());
    assert!(app.cancel_churn().is_err());
    assert!(app.start_churn(churn_req(&priv_id, 99, 1)).is_err());
    app.start_churn(churn_req(&priv_id, 1, 1)).unwrap();
    app.cancel_churn().unwrap();

    let (_, lines) = diag::since(cursor);
    let bundle = app.diagnostics("0.4.16");
    let has = |needle: &str| {
        lines.iter().any(|l| l.contains(needle))
            && bundle.recent_log_lines.iter().any(|l| l.contains(needle))
    };

    // SyncPass assertions.
    assert!(
        has("sync-phase: Idle -> ElectrumFullScan reason=electrum full_scan"),
        "missing ElectrumFullScan log in {lines:#?}"
    );
    assert!(
        has("sync-phase: ElectrumFullScan -> MwebDownload reason=mweb download"),
        "missing MwebDownload log in {lines:#?}"
    );
    assert!(
        has("sync-phase: MwebDownload -> Idle reason=pass exited before finish"),
        "missing SyncPass early-exit Idle log in {lines:#?}"
    );
    assert!(
        has("sync-phase: Idle -> ElectrumSync reason=electrum sync")
            && has("sync-phase: ElectrumSync -> Done reason=pass finished"),
        "missing SyncPass finish log in {lines:#?}"
    );

    // Lock lifecycle assertions.
    assert!(
        has("lock-state: Loaded -> LockPending event=LockWhileHeld reason=state mutex held"),
        "missing LockWhileHeld log in {lines:#?}"
    );
    assert!(
        has("lock-state: LockPending -> Locked event=CheckLock reason=holder aborted on pending lock"),
        "missing CheckLock log in {lines:#?}"
    );
    assert!(
        has("lock-state: LockPending -> Locked event=ReleaseGuard reason=holder released state mutex"),
        "missing ReleaseGuard log in {lines:#?}"
    );
    assert!(
        has("lock-state: rejected command from=Locked reason=wallet is locked"),
        "missing rejected command while Locked log in {lines:#?}"
    );
    assert!(
        has("lock-state: rejected Unlock from=Locked reason=incorrect passphrase"),
        "missing rejected Unlock log in {lines:#?}"
    );
    assert!(
        has("lock-state: Locked -> UnlockedEmpty event=Unlock reason=passphrase verified")
            && has(
                "lock-state: UnlockedEmpty -> Loaded event=Load account=0 reason=account loaded"
            ),
        "missing Unlock/Load logs in {lines:#?}"
    );

    // CoinHold & freeze assertions.
    assert!(
        has(&format!(
            "coin-hold: take kind=private coin={priv_id} session={} from=unheld to=reserved reason=in-flight spend",
            app.session
        )) && has(&format!(
            "coin-hold: release kind=private coin={priv_id} from=reserved to=unheld reason=spend settled"
        )),
        "missing private CoinHold logs in {lines:#?}"
    );
    assert!(
        has(&format!(
            "coin-hold: take kind=public coin={} session={} from=unheld to=public_reserved reason=in-flight spend",
            pub_outs[0], app.session
        )) && has(&format!(
            "coin-hold: release kind=public coin={} from=public_reserved to=unheld reason=spend settled",
            pub_outs[0]
        )),
        "missing public CoinHold logs in {lines:#?}"
    );
    assert!(
        has(&format!(
            "coin-freeze: rejected kind=private coin={priv_id} from=unfrozen to=frozen"
        )) && has(&format!(
            "coin-freeze: phase unfrozen -> frozen kind=private coin={priv_id} reason=user freeze command"
        )) && has(&format!(
            "coin-freeze: phase frozen -> unfrozen kind=private coin={priv_id} reason=user freeze command"
        )),
        "missing private freeze logs in {lines:#?}"
    );
    assert!(
        has(&format!(
            "coin-freeze: rejected kind=public coin={} from=unfrozen to=frozen",
            pub_outs[0]
        )) && has(&format!(
            "coin-freeze: phase unfrozen -> frozen kind=public coin={} reason=user freeze command",
            pub_outs[0]
        )) && has(&format!(
            "coin-freeze: phase frozen -> unfrozen kind=public coin={} reason=user freeze command",
            pub_outs[0]
        )),
        "missing public freeze logs in {lines:#?}"
    );

    // Self-spend command rejections & transitions.
    assert!(
        has("self-spend: rejected Retry job=none from=None reason=There is no self-spend to try again.")
            && has("self-spend: rejected Cancel job=none from=None reason=There is no self-spend to cancel.")
            && has(&format!(
                "self-spend: rejected Start coin={priv_id} from=None"
            )),
        "missing self-spend command rejection logs in {lines:#?}"
    );
    assert!(
        has(&format!(
            "self-spend: phase WaitingToBroadcast -> WaitingForCover job={priv_id}"
        )) && has(&format!(
            "self-spend: phase WaitingForCover -> Cancelled job={priv_id}"
        )),
        "missing self-spend phase transition logs in {lines:#?}"
    );
}

#[test]
fn audit_f3_post_broadcast_commit_succeeds_during_detached_mweb_sync_and_after_lock() {
    crate::discovery::go_offline_for_test();

    // Helper: local RPC listener that pauses inside `sendrawtransaction` at `entered`,
    // waits for `release`, and then returns HTTP 200 `{"result":"ok"}` (broadcast succeeded!).
    let spawn_gated_rpc = |entered: Arc<std::sync::Barrier>, release: Arc<std::sync::Barrier>| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(stream);
            let mut content_len: usize = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some((name, val)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_len = val.trim().parse().unwrap_or(0);
                    }
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
            }
            // Drain the HTTP POST body before replying/closing; on Windows,
            // closing a socket with unread data in the receive buffer triggers
            // a TCP RST (WSAECONNRESET / os error 10054) on the client.
            if content_len > 0 {
                let mut body = vec![0u8; content_len];
                let _ = reader.read_exact(&mut body);
            }
            entered.wait();
            release.wait();
            let payload = br#"{"result":"ok","error":null,"id":"ltc-wallet"}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let mut stream = reader.into_inner();
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(payload);
            let _ = stream.flush();
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut drain = [0u8; 64];
            let _ = stream.read(&mut drain);
        });
        (url, handle)
    };

    // Subcase A: `sync()` parks `state.mweb` (`park_mweb`) while `mweb_send` is broadcasting,
    // and the network accepts the transaction (`200 OK`).
    let dir_a = tempfile::tempdir().unwrap();
    let (app_a, ids_a) = app_with_private_coins(dir_a.path(), &[3_000_000, 2_000_000]);
    persist_private(&app_a);
    let dest_a = app_a.mweb_receive_address().unwrap();
    let entered_a = Arc::new(std::sync::Barrier::new(2));
    let release_a = Arc::new(std::sync::Barrier::new(2));
    let (rpc_url_a, rpc_join_a) = spawn_gated_rpc(Arc::clone(&entered_a), Arc::clone(&release_a));
    configure(&app_a, "tcp://127.0.0.1:9", Some(&rpc_url_a), &[], true);

    let send_res_a = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            crate::discovery::go_offline_for_test();
            app_a.mweb_send(mweb_send_req(&dest_a, &ids_a[0], 100_000))
        });
        entered_a.wait();
        let mut guard = app_a.lock_state().unwrap();
        let _parked = app_a.park_mweb(&mut guard).unwrap().expect("mweb parked");
        drop(guard);
        release_a.wait();
        worker.join().unwrap()
    });
    rpc_join_a.join().unwrap();

    // Subcase B: `app.lock()` (e.g. auto-lock) fires while `mweb_send` is broadcasting,
    // and the network accepts the transaction (`200 OK`).
    let dir_b = tempfile::tempdir().unwrap();
    let (app_b, ids_b) = app_with_private_coins(dir_b.path(), &[3_000_000]);
    persist_private(&app_b);
    let dest_b = app_b.mweb_receive_address().unwrap();
    let entered_b = Arc::new(std::sync::Barrier::new(2));
    let release_b = Arc::new(std::sync::Barrier::new(2));
    let (rpc_url_b, rpc_join_b) = spawn_gated_rpc(Arc::clone(&entered_b), Arc::clone(&release_b));
    configure(&app_b, "tcp://127.0.0.1:9", Some(&rpc_url_b), &[], true);

    let send_res_b = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            crate::discovery::go_offline_for_test();
            app_b.mweb_send(mweb_send_req(&dest_b, &ids_b[0], 100_000))
        });
        entered_b.wait();
        app_b.lock();
        release_b.wait();
        worker.join().unwrap()
    });
    rpc_join_b.join().unwrap();

    assert!(
        send_res_a.is_ok(),
        "broadcast MWEB send failed to commit during detached MWEB sync (releases CoinHold and enables double-send): {send_res_a:?}"
    );
    assert!(
        !matches!(send_res_b, Err(WalletError::MissingMnemonic)),
        "broadcast MWEB send after lock falsely reported MissingMnemonic and dropped local spend record: {send_res_b:?}"
    );
}

#[test]
fn audit_f4_lock_and_switch_wallet_during_detached_mweb_sync_preserve_invariants() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    app.create_wallet_account(
        dir.path(),
        CreateAccountRequest {
            name: "Second".into(),
        },
    )
    .unwrap();
    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    let acc0_dir = account_dir(&app);

    // 1. Switch to Account 1 while Account 0's MWEB runtime is detached: switching back to
    // Account 0 after detached sync finishes must NOT leave Account 0 with `state.mweb == None`.
    let mut guard = app.lock_state().unwrap();
    let detached_rt = app.park_mweb(&mut guard).unwrap().expect("park acc0 mweb");
    drop(guard);

    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 1 })
        .unwrap();
    let _ = app.restore_parked_mweb(&acc0_dir, detached_rt);
    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    let acc0_coins_after_switch = app.list_mweb_unspent();

    // 2. Reload cleanly, detach MWEB, call `lock()`, then unlock + load + advance state:
    // `lock()` must clear `detached_mweb_view`, keep cancellation signaled for the detached
    // worker, and reject stale pre-lock `restore_parked_mweb` instead of clobbering new state.
    app.lock();
    unlock_load(&app, dir.path());
    let mut guard = app.lock_state().unwrap();
    let pre_lock_rt = app.park_mweb(&mut guard).unwrap().expect("park acc0 mweb");
    drop(guard);

    app.lock();
    let leaked_detached_view_while_locked = app.detached_mweb_view().is_some();
    unlock_load(&app, dir.path());
    app.start_churn(churn_req(&ids[0], 1, 1)).unwrap();
    let churned_id = app.churn_status().unwrap().unwrap().output_id;

    let stale_reattach = app.restore_parked_mweb(&acc0_dir, pre_lock_rt);
    let post_reattach_ids = unspent_ids(&app);

    assert!(
        acc0_coins_after_switch.is_ok(),
        "switching accounts during detached MWEB sync left Account 0 in AccountPark with mweb=None: {acc0_coins_after_switch:?}"
    );
    assert!(
        !leaked_detached_view_while_locked,
        "lock() left plaintext DetachedMwebView balances and stealth address in memory while locked"
    );
    assert!(
        stale_reattach.is_err() && post_reattach_ids.contains(&churned_id),
        "stale pre-lock MwebRuntime reattached into post-unlock session and clobbered new churn output: reattach={stale_reattach:?}, coins={post_reattach_ids:?}"
    );
}

#[test]
fn audit_f5_churn_armed_file_must_not_store_cleartext_mweb_spend_key_on_disk() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);
    let data_dir = account_dir(&app);

    app.start_churn(churn_req(&ids[0], 2, 1)).unwrap();
    app.lock();

    let raw_armed_json = std::fs::read_to_string(churn::armed_path(&data_dir)).unwrap();
    assert!(
        !raw_armed_json.contains("\"spend_key\"")
            && !raw_armed_json.contains("\"blind\"")
            && !raw_armed_json.contains("\"shared_secret\""),
        "churn_armed.json persisted cleartext MWEB spend_key/blind/shared_secret on disk while wallet is locked"
    );
}

#[test]
fn audit_f7_cross_account_private_transfer_uses_destination_mweb_scheme() {
    crate::discovery::go_offline_for_test();
    let dir = tempfile::tempdir().unwrap();
    let (app, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app);
    persist_private(&app);

    // Create Account 1 and configure it to use the legacy `Mwebd` derivation scheme.
    app.create_wallet_account(
        dir.path(),
        CreateAccountRequest {
            name: "MwebdAccount".into(),
        },
    )
    .unwrap();
    app.set_mweb_scheme(MwebScheme::Mwebd).unwrap();
    let expected_acc1_addr = app.mweb_receive_address().unwrap();

    // Switch back to Account 0 (`LitecoinCore` scheme) and lock/unlock so Account 1 is cold on disk.
    app.switch_wallet(dir.path(), SwitchWalletRequest { index: 0 })
        .unwrap();
    app.lock();
    unlock_load(&app, dir.path());

    let preview = app
        .preview_transfer_coin(
            dir.path(),
            TransferCoinRequest {
                chain: SplitChain::Private,
                coin_id: ids[0].clone(),
                to_account_index: 1,
                fee_rate_sat_vb: None,
                fee_sats: 0,
            },
        )
        .unwrap();

    assert_eq!(
        preview.address, expected_acc1_addr,
        "private transfer to cold Account 1 derived destination under Account 0's LitecoinCore scheme instead of Account 1's Mwebd scheme"
    );
}

#[test]
fn audit_f9b_second_process_load_must_not_clobber_live_coin_hold() {
    let dir = tempfile::tempdir().unwrap();
    let (app1, ids) = app_with_private_coins(dir.path(), &[3_000_000]);
    clear_planted_job(&app1);
    persist_private(&app1);
    let data_dir = account_dir(&app1);

    // Process 1 holds a live in-flight reservation while broadcasting a spend.
    let _live_hold = CoinHold::take(&data_dir, vec![ids[0].clone()], &app1.session).unwrap();
    assert_eq!(private_row(&app1, &ids[0]).status, CoinStatus::Sending);

    // Process 2 (e.g. wallet-cli or a second GUI instance) opens the same data_dir.
    let app2 = WalletApp::new(dir.path());
    app2.unlock(UnlockRequest {
        passphrase: PASSPHRASE.into(),
    })
    .unwrap();
    if app2.load(dir.path()).is_ok() {
        assert!(
            mweb_frozen::read_ids(&data_dir)
                .unwrap()
                .reserved
                .contains_key(&ids[0]),
            "second WalletApp::load wiped Process 1's live in-flight CoinHold reservation"
        );
    }
}

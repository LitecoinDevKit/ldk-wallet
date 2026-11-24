//! End-to-end offline mock-Electrum SPV acceptance tests (item 25).
//!
//! Spins up an in-process loopback JSON-RPC Electrum 1.4 server and drives
//! `WalletApp::sync`, `WalletApp::prefetch_transparent`, and `WalletApp::update_settings`
//! against honest and adversarial server responses.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk_wallet::bitcoin::absolute::LockTime;
use bdk_wallet::bitcoin::block::{Header, Version as BlockVersion};
use bdk_wallet::bitcoin::consensus::encode::serialize;
use bdk_wallet::bitcoin::constants::genesis_block;
use bdk_wallet::bitcoin::hashes::{sha256, sha256d, Hash, HashEngine};
use bdk_wallet::bitcoin::pow::{CompactTarget, Target};
use bdk_wallet::bitcoin::transaction::Version as TxVersion;
use bdk_wallet::bitcoin::{
    Address, Amount, Network, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use serde_json::{json, Value};

use super::super::*;
use super::app_with_job;
use crate::discovery;
use crate::dto::{ChurnPhase, CoinStatus, TxKind, UpdateSettingsRequest};
use crate::mweb_history::MwebHistoryEntry;

#[derive(Clone, Debug)]
struct MockHistoryEntry {
    tx_hash: String,
    height: i32,
}

#[derive(Clone, Debug)]
struct MockMerkleProof {
    block_height: usize,
    pos: usize,
    /// Display-hex (big-endian, matching Electrum JSON-RPC wire format) sibling hashes.
    merkle: Vec<String>,
}

#[derive(Clone, Default)]
struct MockChainState {
    headers: BTreeMap<u32, Header>,
    tip_height: u32,
    histories: HashMap<String, Vec<MockHistoryEntry>>,
    txs: HashMap<String, Vec<u8>>,
    proofs: HashMap<(String, usize), Result<MockMerkleProof, String>>,
    broadcast_txs: Vec<Transaction>,
    /// Heights passed to `blockchain.block.header` (one entry per call).
    header_calls: Vec<u32>,
    /// Number of round-trips containing `blockchain.block.header`.
    header_batches: usize,
    /// Number of `blockchain.block.headers` batch calls.
    headers_batch_calls: usize,
    /// Number of `blockchain.scripthash.get_history` calls.
    script_history_calls: usize,
    /// Number of `blockchain.transaction.get` calls.
    tx_get_calls: usize,
    /// Number of round-trips containing `blockchain.transaction.get`.
    tx_get_batches: usize,
    /// Number of `blockchain.transaction.get_merkle` calls.
    merkle_calls: usize,
    /// Number of round-trips containing `blockchain.transaction.get_merkle`.
    merkle_batches: usize,
}

struct MockElectrumServer {
    url: String,
    state: Arc<Mutex<MockChainState>>,
}

impl MockElectrumServer {
    fn start(initial: MockChainState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock electrum");
        let addr = listener.local_addr().unwrap();
        let url = format!("tcp://{addr}");
        let state = Arc::new(Mutex::new(initial));
        let state_clone = Arc::clone(&state);

        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let st = Arc::clone(&state_clone);
                std::thread::spawn(move || {
                    let mut reader =
                        BufReader::with_capacity(64 * 1024, stream.try_clone().unwrap());
                    let mut writer = stream;
                    let mut line = String::new();
                    while reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false) {
                        let mut batch_reqs = Vec::new();
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            if let Ok(req) = serde_json::from_str::<Value>(trimmed) {
                                batch_reqs.push(req);
                            }
                        }
                        line.clear();

                        // Drain any additional pipelined requests already queued on the
                        // socket (from `RawClient::batch_call`, which writes the whole
                        // batch in one `write_all` before waiting for responses).
                        // Use non-blocking mode on `reader.get_ref()` rather than a
                        // cloned socket's `SO_RCVTIMEO` (which does not propagate to
                        // duplicated handles on Windows and leaves timed-out Winsock
                        // TCP sockets indeterminate).
                        let _ = reader.get_ref().set_nonblocking(true);
                        loop {
                            let has_newline = match reader.fill_buf() {
                                Ok(buf) if !buf.is_empty() => buf.contains(&b'\n'),
                                _ => break,
                            };
                            if !has_newline {
                                // A partial line without `\n` means the sender's current
                                // batch spilled past the buffer boundary; block until the
                                // line completes, then keep draining non-blocking.
                                let _ = reader.get_ref().set_nonblocking(false);
                            }
                            let got = reader.read_line(&mut line).map(|n| n > 0).unwrap_or(false);
                            if !has_newline {
                                let _ = reader.get_ref().set_nonblocking(true);
                            }
                            if !got {
                                break;
                            }
                            let t = line.trim();
                            if !t.is_empty() {
                                if let Ok(req) = serde_json::from_str::<Value>(t) {
                                    batch_reqs.push(req);
                                }
                            }
                            line.clear();
                        }
                        let _ = reader.get_ref().set_nonblocking(false);

                        if batch_reqs.is_empty() {
                            continue;
                        }
                        note_round_trip(&st, &batch_reqs);
                        let mut encoded = Vec::new();
                        for req in &batch_reqs {
                            let resp = handle_rpc(&st, req);
                            encoded.extend_from_slice(&serde_json::to_vec(&resp).unwrap());
                            encoded.push(b'\n');
                        }
                        if writer.write_all(&encoded).is_err() || writer.flush().is_err() {
                            break;
                        }
                    }
                });
            }
        });

        Self { url, state }
    }

    fn update<F: FnOnce(&mut MockChainState)>(&self, f: F) {
        let mut guard = self.state.lock().unwrap();
        f(&mut guard);
    }
}

fn note_round_trip(state: &Arc<Mutex<MockChainState>>, batch_reqs: &[Value]) {
    let mut has_header = false;
    let mut has_tx_get = false;
    let mut has_merkle = false;
    for req in batch_reqs {
        let items: Vec<&Value> = match req.as_array() {
            Some(arr) => arr.iter().collect(),
            None => vec![req],
        };
        for item in items {
            match item.get("method").and_then(Value::as_str).unwrap_or("") {
                "blockchain.block.header" => has_header = true,
                "blockchain.transaction.get" => has_tx_get = true,
                "blockchain.transaction.get_merkle" => has_merkle = true,
                _ => {}
            }
        }
    }
    let mut st = state.lock().unwrap();
    if has_header {
        st.header_batches += 1;
    }
    if has_tx_get {
        st.tx_get_batches += 1;
    }
    if has_merkle {
        st.merkle_batches += 1;
    }
}

fn handle_rpc(state: &Arc<Mutex<MockChainState>>, req: &Value) -> Value {
    if let Some(arr) = req.as_array() {
        let responses: Vec<Value> = arr
            .iter()
            .map(|item| handle_single_rpc(state, item))
            .collect();
        return Value::Array(responses);
    }
    handle_single_rpc(state, req)
}

fn handle_single_rpc(state: &Arc<Mutex<MockChainState>>, req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req
        .get("params")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut st = state.lock().unwrap();
    match method {
        "server.version" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": ["ElectrumX 1.16.0", "1.4"]
        }),
        "server.ping" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": null
        }),
        "blockchain.headers.subscribe" => {
            let tip_h = st.tip_height;
            let hdr = st
                .headers
                .get(&tip_h)
                .copied()
                .unwrap_or_else(|| genesis_block(Network::Testnet4).header);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "height": tip_h,
                    "hex": hex::encode(serialize(&hdr)),
                }
            })
        }
        "blockchain.block.header" => {
            let h = params.first().and_then(Value::as_u64).unwrap_or(0) as u32;
            st.header_calls.push(h);
            match st.headers.get(&h) {
                Some(hdr) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": hex::encode(serialize(hdr)),
                }),
                None => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": 1, "message": format!("header {h} not found")}
                }),
            }
        }
        "blockchain.block.headers" => {
            st.headers_batch_calls += 1;
            let start = params.first().and_then(Value::as_u64).unwrap_or(0) as u32;
            let count = params.get(1).and_then(Value::as_u64).unwrap_or(0) as u32;
            let mut raw = Vec::new();
            let mut n = 0usize;
            for h in start..start.saturating_add(count) {
                if let Some(hdr) = st.headers.get(&h) {
                    raw.extend_from_slice(&serialize(hdr));
                    n += 1;
                } else {
                    break;
                }
            }
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "count": n,
                    "hex": hex::encode(raw),
                    "max": 2016
                }
            })
        }
        "blockchain.scripthash.get_history" => {
            st.script_history_calls += 1;
            let sh = params.first().and_then(Value::as_str).unwrap_or("");
            let entries: Vec<Value> = st
                .histories
                .get(sh)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|e| json!({"tx_hash": e.tx_hash, "height": e.height}))
                .collect();
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": entries
            })
        }
        "blockchain.transaction.get" => {
            st.tx_get_calls += 1;
            let txid = params.first().and_then(Value::as_str).unwrap_or("");
            match st.txs.get(txid) {
                Some(raw) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": hex::encode(raw)
                }),
                None => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": 2, "message": format!("tx {txid} not found")}
                }),
            }
        }
        "blockchain.transaction.get_merkle" => {
            st.merkle_calls += 1;
            let txid = params
                .first()
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let height = params.get(1).and_then(Value::as_u64).unwrap_or(0) as usize;
            match st.proofs.get(&(txid.clone(), height)) {
                Some(Ok(proof)) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "block_height": proof.block_height,
                        "pos": proof.pos,
                        "merkle": proof.merkle,
                    }
                }),
                Some(Err(msg)) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": 1, "message": msg}
                }),
                None => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": 1, "message": format!("no merkle proof for {txid} at {height}")}
                }),
            }
        }
        "blockchain.transaction.broadcast" => {
            let raw_hex = params.first().and_then(Value::as_str).unwrap_or("");
            let bytes = hex::decode(raw_hex).unwrap_or_default();
            let tx: Transaction =
                bdk_wallet::bitcoin::consensus::encode::deserialize(&bytes).unwrap();
            let txid = tx.compute_txid().to_string();
            st.txs.insert(txid.clone(), bytes);
            st.broadcast_txs.push(tx);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": txid
            })
        }
        "blockchain.estimatefee" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": 0.0001
        }),
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("unsupported method {other}")}
        }),
    }
}

fn electrum_scripthash_hex(script: &Script) -> String {
    let mut hash = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    hash.reverse();
    hex::encode(hash)
}

fn sha256d_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut eng = sha256d::Hash::engine();
    eng.input(left);
    eng.input(right);
    sha256d::Hash::from_engine(eng).to_byte_array()
}

fn display_hex_from_internal(internal_bytes: [u8; 32]) -> String {
    let mut rev = internal_bytes;
    rev.reverse();
    hex::encode(rev)
}

/// Regtest bits, valid under [`crate::spv::easy_pow_for_test`] for a block more
/// than 300s after its parent. Real Litecoin bits take ~a million scrypt hashes.
fn easy_bits() -> CompactTarget {
    CompactTarget::from_consensus(0x207f_ffff)
}

fn mine_testnet_header(mut header: Header) -> Header {
    let target = Target::from_compact(header.bits);
    for nonce in header.nonce..=u32::MAX {
        header.nonce = nonce;
        let bytes = serialize(&header);
        let mut pow = [0u8; 32];
        let params = scrypt::Params::new(10, 1, 1).unwrap();
        scrypt::scrypt(&bytes, &bytes, &params, &mut pow).unwrap();
        let pow_hash = bdk_wallet::bitcoin::BlockHash::from_byte_array(pow);
        if target.is_met_by(pow_hash) {
            return header;
        }
    }
    panic!("no scrypt nonce found");
}

fn make_coinbase_tx(height: u32) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x04, (height & 0xff) as u8, 0x01, 0x02, 0x03]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![
                0x00, 0x14, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            ]),
        }],
        mw_tx: None,
        is_hog_ex: false,
    }
}

fn make_funding_tx(recipient_spk: ScriptBuf, sats: u64, tag: u8) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([tag; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::from_bytes(vec![0x01, tag]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: recipient_spk,
        }],
        mw_tx: None,
        is_hog_ex: false,
    }
}

fn configure_electrum(app: &WalletApp, electrum_url: &str, use_fallback: bool) {
    let mut guard = app.lock_state().unwrap();
    let state = guard.as_mut().unwrap();
    state.electrum_url = electrum_url.to_string();
    state.electrum_validate_domain = false;
    state.electrum_use_public_fallback = use_fallback;
    state.active_electrum_url = None;
    state.mweb_peers.clear();
    let meta = meta_from_state(state);
    let dir = state.data_dir.clone();
    drop(guard);
    meta::write_meta(&dir, &meta).unwrap();
    app.forget_electrum();
}

/// Build a base chain `[0, 1]` on Testnet4 where block 1 confirms `tx` at `pos = 1` alongside a
/// coinbase tx at `pos = 0`.
fn build_single_block_chain_with_tx(tx: &Transaction) -> (MockChainState, Txid, [u8; 32]) {
    let gen = genesis_block(Network::Testnet4).header;
    let cb = make_coinbase_tx(1);
    let cb_id = cb.compute_txid().to_byte_array();
    let tx_id = tx.compute_txid();
    let tx_bytes = tx_id.to_byte_array();
    let root = sha256d_pair(&cb_id, &tx_bytes);

    let b1 = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array(root),
        time: gen.time + 600,
        bits: easy_bits(),
        nonce: 0,
    });

    let mut st = MockChainState::default();
    st.headers.insert(0, gen);
    st.headers.insert(1, b1);
    st.tip_height = 1;

    let sh = electrum_scripthash_hex(&tx.output[0].script_pubkey);
    st.histories.insert(
        sh,
        vec![MockHistoryEntry {
            tx_hash: tx_id.to_string(),
            height: 1,
        }],
    );
    st.txs.insert(tx_id.to_string(), serialize(tx));
    st.proofs.insert(
        (tx_id.to_string(), 1),
        Ok(MockMerkleProof {
            block_height: 1,
            pos: 1,
            merkle: vec![display_hex_from_internal(cb_id)],
        }),
    );

    (st, tx_id, cb_id)
}

#[test]
fn sync_rejects_forged_merkle_proofs_and_bad_headers_before_confirming_coin() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 250_000, 0x21);
    let (honest_state, txid, _cb_id) = build_single_block_chain_with_tx(&tx);

    // 1. Server serving CVE-2012-2459 left-sibling duplicate proof:
    // Header merkle_root is sha256d(txid || txid), and server claims pos = 1 (left sibling == txid).
    let gen = genesis_block(Network::Testnet4).header;
    let dup_root = sha256d_pair(&txid.to_byte_array(), &txid.to_byte_array());
    let b1_dup = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array(dup_root),
        time: gen.time + 600,
        bits: easy_bits(),
        nonce: 0,
    });
    let mut cve_2012_2459_state = honest_state.clone();
    cve_2012_2459_state.headers.insert(1, b1_dup);
    cve_2012_2459_state.proofs.insert(
        (txid.to_string(), 1),
        Ok(MockMerkleProof {
            block_height: 1,
            pos: 1,
            merkle: vec![display_hex_from_internal(txid.to_byte_array())],
        }),
    );
    let server = MockElectrumServer::start(cve_2012_2459_state);
    configure_electrum(&app, &server.url, false);

    let err = app
        .sync()
        .expect_err("CVE-2012-2459 forged merkle proof must fail sync");
    assert!(
        err.to_string().contains("CVE-2012-2459"),
        "expected CVE-2012-2459 error, got: {err}"
    );
    assert!(
        app.list_unspent().unwrap().is_empty(),
        "forged merkle proof must not confirm or credit coin"
    );
    assert!(
        app.remembered_electrum().is_none(),
        "lying server must not stay remembered after SPV failure"
    );

    // 2. Server serving a header that fails Litecoin scrypt PoW:
    let mut bad_pow_state = honest_state.clone();
    let mut bad_b1 = *bad_pow_state.headers.get(&1).unwrap();
    bad_b1.bits = CompactTarget::from_consensus(0x1b00ffff);
    bad_b1.nonce = 0;
    bad_pow_state.headers.insert(1, bad_b1);
    server.update(|st| *st = bad_pow_state);

    let err = app
        .sync()
        .expect_err("header failing scrypt PoW must fail sync");
    assert!(
        err.to_string().contains("proof-of-work") || err.to_string().contains("target"),
        "expected PoW/target error, got: {err}"
    );
    assert!(app.list_unspent().unwrap().is_empty());

    // 3. Honest server state succeeds and confirms the coin:
    server.update(|st| *st = honest_state);
    app.sync()
        .expect("honest SPV proof and header must succeed");
    let utxos = app.list_unspent().unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].confirmations, 1);
    assert_eq!(utxos[0].status, CoinStatus::Ready);
}

#[test]
fn sync_rejects_lagging_server_and_weaker_fork_but_accepts_heavier_fork() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 400_000, 0x31);
    let (mut state_h2, _txid, _cb_id) = build_single_block_chain_with_tx(&tx);

    // Extend honest chain to height 2
    let gen = *state_h2.headers.get(&0).unwrap();
    let b1 = *state_h2.headers.get(&1).unwrap();
    let b2 = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: b1.block_hash(),
        merkle_root: gen.merkle_root,
        time: b1.time + 600,
        bits: easy_bits(),
        nonce: 0,
    });
    state_h2.headers.insert(2, b2);
    state_h2.tip_height = 2;

    let server = MockElectrumServer::start(state_h2.clone());
    configure_electrum(&app, &server.url, false);
    app.sync().expect("sync to height 2");
    assert_eq!(app.summary().unwrap().tip_height, 2);

    // 1. Server lags at height 1 -> rejected
    server.update(|st| {
        st.headers.remove(&2);
        st.tip_height = 1;
    });
    let lag_err = app.sync().expect_err("lagging server must be rejected");
    assert!(
        lag_err.to_string().contains("lagging"),
        "expected lagging server error, got: {lag_err}"
    );
    assert_eq!(app.summary().unwrap().tip_height, 2);

    // 2. Server presents a competing fork at height 2 with equal cumulative work -> rejected
    let b2_weaker_fork = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: b1.block_hash(),
        merkle_root: gen.merkle_root,
        time: b1.time + 700,
        bits: easy_bits(),
        nonce: 0,
    });
    server.update(|st| {
        st.headers.insert(2, b2_weaker_fork);
        st.tip_height = 2;
    });
    let fork_err = app
        .sync()
        .expect_err("competing fork with <= cumulative work must be rejected");
    assert!(
        fork_err.to_string().contains("fork") || fork_err.to_string().contains("work"),
        "expected fork work error, got: {fork_err}"
    );

    // 3. Server extends the fork to height 3 with strictly more cumulative work -> accepted
    let b3_fork = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: b2_weaker_fork.block_hash(),
        merkle_root: gen.merkle_root,
        time: b2_weaker_fork.time + 600,
        bits: easy_bits(),
        nonce: 0,
    });
    server.update(|st| {
        st.headers.insert(3, b3_fork);
        st.tip_height = 3;
    });
    app.sync().expect("strictly heavier fork must be accepted");
    assert_eq!(app.summary().unwrap().tip_height, 3);
}

#[test]
fn transaction_claimed_mined_waits_unconfirmed_until_merkle_proof_passes() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 350_000, 0x41);
    let (honest_state, txid, _cb_id) = build_single_block_chain_with_tx(&tx);

    // Server claims `tx` is mined at height 1, but `get_merkle` returns a protocol error
    // (e.g., server has not finished indexing the block's merkle branch yet).
    let mut unverified_state = honest_state.clone();
    unverified_state.proofs.insert(
        (txid.to_string(), 1),
        Err("merkle branch not indexed yet".into()),
    );
    let server = MockElectrumServer::start(unverified_state);
    configure_electrum(&app, &server.url, false);

    app.sync().expect("sync succeeds with tx kept unconfirmed");
    let utxos = app.list_unspent().unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(
        utxos[0].confirmations, 0,
        "tx claimed mined without a passing merkle proof must remain at 0 confirmations"
    );
    assert_eq!(utxos[0].status, CoinStatus::Pending);

    // Next sync provides the valid merkle proof -> coin becomes confirmed (1 conf, Ready).
    server.update(|st| *st = honest_state);
    app.sync().expect("sync with valid proof");
    let utxos_after = app.list_unspent().unwrap();
    assert_eq!(utxos_after.len(), 1);
    assert_eq!(utxos_after[0].confirmations, 1);
    assert_eq!(utxos_after[0].status, CoinStatus::Ready);
}

#[test]
fn switching_servers_drops_cached_server_unconfirmed_state_but_preserves_local_and_pegin_spends() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();

    // Confirmed UTXO (`tx_conf`, 1,000,000 sats) + unconfirmed incoming phantom (`tx_phantom`, 500,000 sats)
    // served only by Server A.
    let tx_conf = make_funding_tx(recv_addr.script_pubkey(), 1_000_000, 0x51);
    let tx_phantom = make_funding_tx(recv_addr.script_pubkey(), 500_000, 0x52);
    let (mut state_a, conf_txid, _cb_id) = build_single_block_chain_with_tx(&tx_conf);
    let sh = electrum_scripthash_hex(&recv_addr.script_pubkey());
    let phantom_txid = tx_phantom.compute_txid().to_string();
    state_a
        .histories
        .get_mut(&sh)
        .unwrap()
        .push(MockHistoryEntry {
            tx_hash: phantom_txid.clone(),
            height: 0,
        });
    state_a
        .txs
        .insert(phantom_txid.clone(), serialize(&tx_phantom));

    // Server B has the same confirmed chain `[0, 1]` and `tx_conf`, but never heard of `tx_phantom`.
    let (state_b, _, _) = build_single_block_chain_with_tx(&tx_conf);

    let server_a = MockElectrumServer::start(state_a);
    let server_b = MockElectrumServer::start(state_b);
    configure_electrum(&app, &server_a.url, false);

    app.sync().expect("sync against server A");
    let utxos_a = app.list_unspent().unwrap();
    assert_eq!(
        utxos_a.len(),
        2,
        "both confirmed coin and unconfirmed server A coin are visible initially"
    );

    // Simulate a local unconfirmed peg-in spend of `tx_conf` (or local broadcast) recorded via
    // `apply_unconfirmed_txs` + MWEB history `TxKind::Pegin`.
    let local_pegin_spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: conf_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(990_000),
            script_pubkey: ScriptBuf::from_bytes({
                let mut v = vec![0x59, 0x20];
                v.extend_from_slice(&[0x77; 32]);
                v
            }),
        }],
        mw_tx: None,
        is_hog_ex: false,
    };
    let pegin_txid = local_pegin_spend.compute_txid().to_string();
    {
        let mut guard = app.lock_state().unwrap();
        let state = guard.as_mut().unwrap();
        state
            .wallet
            .apply_unconfirmed_txs([(local_pegin_spend, crate::mweb_history::now_ts())]);
        state.wallet.persist(&mut state.db).unwrap();
        let mweb = state.mweb.as_mut().unwrap();
        mweb.history.record(MwebHistoryEntry {
            id: pegin_txid.clone(),
            kind: TxKind::Pegin,
            net_sats: -1_000_000,
            fee_sats: Some(10_000),
            timestamp: crate::mweb_history::now_ts(),
            output_ids: Vec::new(),
            input_ids: Vec::new(),
            confirmed_height: None,
        });
        let data_dir = state.data_dir.clone();
        mweb.persist(&data_dir).unwrap();
    }

    // Switch to Server B via `update_settings`:
    let settings = app.settings().unwrap();
    app.update_settings(UpdateSettingsRequest {
        electrum_url: server_b.url.clone(),
        electrum_validate_domain: false,
        electrum_use_public_fallback: false,
        auto_lock_minutes: settings.auto_lock_minutes,
        litecoin_rpc_url: settings.litecoin_rpc_url,
        broadcast_via_own_node: settings.broadcast_via_own_node,
        mweb_peers: settings.mweb_peers,
        explorer_base_url: settings.explorer_base_url,
        show_fiat: settings.show_fiat,
        use_explorer_fee_hints: settings.use_explorer_fee_hints,
        insights_enabled: settings.insights_enabled,
    })
    .unwrap();

    // Immediately after switching servers (and after syncing with Server B),
    // Server A's phantom unconfirmed UTXO must be gone, while our local peg-in spend
    // still keeps `conf_txid:0` spent!
    let utxos_after_switch = app.list_unspent().unwrap();
    assert!(
        !utxos_after_switch
            .iter()
            .any(|u| u.outpoint.starts_with(&phantom_txid)),
        "unconfirmed coin cached from previous server A must be dropped on server switch"
    );
    assert!(
        !utxos_after_switch
            .iter()
            .any(|u| u.outpoint.starts_with(&conf_txid.to_string())),
        "local peg-in spend must stay applied across server switch"
    );

    app.sync().expect("sync against server B");
    let utxos_after_b = app.list_unspent().unwrap();
    assert!(
        !utxos_after_b
            .iter()
            .any(|u| u.outpoint.starts_with(&phantom_txid)),
        "phantom coin from server A must remain absent after syncing server B"
    );
    assert!(
        !utxos_after_b
            .iter()
            .any(|u| u.outpoint.starts_with(&conf_txid.to_string())),
        "local peg-in spend must remain applied after syncing server B"
    );
}

#[test]
fn repair_missing_pegin_spends_rejects_mismatched_txid_and_invalid_tx() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();

    let tx_conf = make_funding_tx(recv_addr.script_pubkey(), 1_000_000, 0x61);
    let (mut state, conf_txid, _cb_id) = build_single_block_chain_with_tx(&tx_conf);

    // Record a peg-in entry in MWEB history whose transparent tx (`expected_pegin_txid`) is missing
    // from `state.wallet`, so `repair_missing_pegin_spends` runs during `sync` and asks Electrum
    // for `expected_pegin_txid`.
    let valid_pegin_tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: conf_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(990_000),
            script_pubkey: ScriptBuf::from_bytes({
                let mut v = vec![0x59, 0x20];
                v.extend_from_slice(&[0x88; 32]);
                v
            }),
        }],
        mw_tx: None,
        is_hog_ex: false,
    };
    let expected_pegin_txid = valid_pegin_tx.compute_txid().to_string();

    // Dishonest server returns a DIFFERENT transaction under `expected_pegin_txid` that spends
    // `conf_txid:0` (or creates a fake > MAX_MONEY output):
    let forged_tx = make_funding_tx(recv_addr.script_pubkey(), 999_000, 0x62);
    assert_ne!(forged_tx.compute_txid().to_string(), expected_pegin_txid);
    state
        .txs
        .insert(expected_pegin_txid.clone(), serialize(&forged_tx));

    {
        let mut guard = app.lock_state().unwrap();
        let st = guard.as_mut().unwrap();
        let mweb = st.mweb.as_mut().unwrap();
        mweb.history.record(MwebHistoryEntry {
            id: expected_pegin_txid.clone(),
            kind: TxKind::Pegin,
            net_sats: -1_000_000,
            fee_sats: Some(10_000),
            timestamp: crate::mweb_history::now_ts(),
            output_ids: Vec::new(),
            input_ids: Vec::new(),
            confirmed_height: None,
        });
        let data_dir = st.data_dir.clone();
        mweb.persist(&data_dir).unwrap();
    }

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);

    let res = app.sync().expect("sync completes with repair warning");
    assert!(
        res.warnings
            .iter()
            .any(|w| w.contains("Could not repair 1 peg-in spend")),
        "mismatched raw tx in pegin repair must be rejected and surface warning: {:?}",
        res.warnings
    );
    assert!(
        app.transactions()
            .unwrap()
            .iter()
            .all(|t| t.txid != forged_tx.compute_txid().to_string()),
        "forged transaction with mismatched txid must never be inserted into BDK graph"
    );

    // Once the server returns the authentic `valid_pegin_tx` bytes, repair succeeds.
    server.update(|st| {
        st.txs
            .insert(expected_pegin_txid.clone(), serialize(&valid_pegin_tx));
    });
    let res2 = app.sync().expect("sync repairs valid pegin tx");
    assert!(
        res2.warnings
            .iter()
            .any(|w| w.contains("Repaired 1 peg-in spend")),
        "expected repair confirmation, got: {:?}",
        res2.warnings
    );
}

#[test]
fn cross_check_tip_remains_a_warning_and_does_not_fail_sync() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 300_000, 0x71);
    let (state_sync, _txid, _cb_id) = build_single_block_chain_with_tx(&tx);

    // Sync server is at height 1 with valid SPV proof.
    let server_sync = MockElectrumServer::start(state_sync);
    configure_electrum(&app, &server_sync.url, false);

    let res = app.sync().expect("sync succeeds");
    assert_eq!(res.summary.tip_height, 1);

    // Direct `electrum::cross_check_tip` against a second server with a different block at height 1
    // returns `Ok(Some(warning))` (stays a warning, not an error).
    let gen = genesis_block(Network::Testnet4).header;
    let b1_alt = mine_testnet_header(Header {
        version: BlockVersion::TWO,
        prev_blockhash: gen.block_hash(),
        merkle_root: gen.merkle_root,
        time: gen.time + 700,
        bits: easy_bits(),
        nonce: 0,
    });
    let mut alt_state = MockChainState::default();
    alt_state.headers.insert(0, gen);
    alt_state.headers.insert(1, b1_alt);
    alt_state.tip_height = 1;
    let server_alt = MockElectrumServer::start(alt_state);

    let local_b1_hash = server_sync
        .state
        .lock()
        .unwrap()
        .headers
        .get(&1)
        .unwrap()
        .block_hash();
    let warning = crate::electrum::cross_check_tip(&server_alt.url, false, 1, &|h| match h {
        1 => Some(local_b1_hash),
        _ => None,
    })
    .expect("cross_check_tip returns Ok")
    .expect("disagreement produces warning");
    assert!(
        warning.contains("WARNING: Electrum servers disagree at height 1"),
        "unexpected warning: {warning}"
    );
}

fn extend_chain(st: &mut MockChainState, target: u32) {
    while st.tip_height < target {
        let prev = *st.headers.get(&st.tip_height).expect("tip header");
        let height = st.tip_height + 1;
        let next = mine_testnet_header(Header {
            version: BlockVersion::TWO,
            prev_blockhash: prev.block_hash(),
            merkle_root: prev.merkle_root,
            time: prev.time.saturating_add(600),
            bits: easy_bits(),
            nonce: 0,
        });
        st.headers.insert(height, next);
        st.tip_height = height;
    }
}

#[test]
fn second_sync_does_not_refetch_a_header_for_an_anchored_tx_below_the_window() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let _window = crate::spv::narrow_header_window_for_test(4);
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 250_000, 0x41);
    let (mut state, _txid, _cb) = build_single_block_chain_with_tx(&tx);
    extend_chain(&mut state, 5);

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);
    app.sync().expect("first sync anchors the coin");
    assert_eq!(app.summary().unwrap().tip_height, 5);
    assert_eq!(app.list_unspent().unwrap().len(), 1);

    // The stored header would also avoid a fetch. Remove it so the skip has to
    // come from the anchor already in the wallet.
    let account_dir = app.lock_state().unwrap().as_ref().unwrap().data_dir.clone();
    let mut spv = crate::spv::load_spv_state(&account_dir);
    assert!(
        spv.verified_headers.remove(&1).is_some(),
        "first sync should have stored the anchor header"
    );
    crate::spv::save_spv_state(&account_dir, &spv).unwrap();

    server.update(|st| {
        extend_chain(st, 20);
        st.header_calls.clear();
    });
    app.sync().expect("second sync");
    let calls = server.state.lock().unwrap().header_calls.clone();
    assert!(
        !calls.contains(&1),
        "anchored tx below the window must not refetch its header, calls={calls:?}"
    );
    assert_eq!(app.list_unspent().unwrap().len(), 1);
    assert_eq!(app.summary().unwrap().tip_height, 20);
}

#[test]
fn pegin_repair_backs_off_after_a_dead_fallback() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 250_000, 0x51);
    let (state, _txid, _cb) = build_single_block_chain_with_tx(&tx);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc_url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        // Accept and never answer. Reading the request and then dropping the
        // socket makes the client fail at once, so the repair timeout never runs.
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 1024];
                loop {
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    let missing_id = "ab".repeat(32);
    {
        let mut guard = app.lock_state().unwrap();
        let st = guard.as_mut().unwrap();
        st.litecoin_rpc_url = Some(rpc_url);
        st.mweb.as_mut().unwrap().history.record(MwebHistoryEntry {
            id: missing_id,
            kind: TxKind::Pegin,
            net_sats: -1_000_000,
            fee_sats: Some(10_000),
            timestamp: crate::mweb_history::now_ts(),
            output_ids: Vec::new(),
            input_ids: Vec::new(),
            confirmed_height: None,
        });
        let data_dir = st.data_dir.clone();
        st.mweb.as_mut().unwrap().persist(&data_dir).unwrap();
    }

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);

    let started = std::time::Instant::now();
    let first = app.sync().expect("sync warns instead of failing repair");
    let first_ms = started.elapsed().as_millis();
    assert!(first
        .warnings
        .iter()
        .any(|w| w.contains("Could not repair")));
    assert!(
        (1500..10_000).contains(&first_ms),
        "dead fallback should stop at the short timeout, got {first_ms} ms"
    );

    let started = std::time::Instant::now();
    let second = app.sync().expect("second sync");
    let second_ms = started.elapsed().as_millis();
    assert!(second
        .warnings
        .iter()
        .any(|w| w.contains("Could not repair")));
    assert!(
        second_ms < 1_500,
        "a peg-in that just failed its fallbacks must not stall the next sync, got {second_ms} ms"
    );
}

#[test]
fn absorbed_mweb_pegin_output_id_is_not_treated_as_missing_transparent_pegin() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 250_000, 0x71);
    let (state, _txid, _cb) = build_single_block_chain_with_tx(&tx);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rpc_url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0u8; 1024];
                loop {
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    // Simulate a peg-in coin absorbed by `absorb_received_coins` (where `id` is the MWEB
    // output_id and `output_ids` contains `id`, with positive `net_sats` and no `fee_sats`).
    let absorbed_output_id = "cd".repeat(32);
    {
        let mut guard = app.lock_state().unwrap();
        let st = guard.as_mut().unwrap();
        st.litecoin_rpc_url = Some(rpc_url);
        st.mweb.as_mut().unwrap().history.record(MwebHistoryEntry {
            id: absorbed_output_id.clone(),
            kind: TxKind::Pegin,
            net_sats: 500_000,
            fee_sats: None,
            timestamp: crate::mweb_history::now_ts(),
            output_ids: vec![absorbed_output_id],
            input_ids: Vec::new(),
            confirmed_height: Some(1),
        });
        let data_dir = st.data_dir.clone();
        st.mweb.as_mut().unwrap().persist(&data_dir).unwrap();
    }

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);

    let started = std::time::Instant::now();
    let res = app.sync().expect("sync succeeds");
    let elapsed_ms = started.elapsed().as_millis();
    assert!(
        res.warnings.is_empty(),
        "absorbed MWEB peg-in coin must not trigger missing transparent peg-in warning: {:?}",
        res.warnings
    );
    assert!(
        elapsed_ms < 1_000,
        "absorbed MWEB peg-in coin must not stall sync on RPC fallback, took {elapsed_ms} ms"
    );
}

#[test]
fn unchanged_tip_skips_redundant_header_window_fetch_and_fresh_prefetch_skips_duplicate_scan() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_addr = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap();
    let tx = make_funding_tx(recv_addr.script_pubkey(), 250_000, 0x72);
    let (mut state, _txid, _cb) = build_single_block_chain_with_tx(&tx);
    extend_chain(&mut state, 5);

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);

    app.sync().expect("first sync at tip 5");
    assert_eq!(app.summary().unwrap().tip_height, 5);

    // Second sync at the same tip height/hash should not re-fetch the header window.
    server.update(|st| {
        st.header_calls.clear();
        st.headers_batch_calls = 0;
    });
    app.sync().expect("second sync at unchanged tip 5");
    {
        let st = server.state.lock().unwrap();
        assert!(
            st.header_calls.is_empty() && st.headers_batch_calls == 0,
            "unchanged tip must not re-fetch headers: header_calls={:?}, batch_calls={}",
            st.header_calls,
            st.headers_batch_calls
        );
    }

    // Lock the wallet, advance the chain to 8, run prefetch_transparent, then unlock + load + sync.
    app.lock();
    server.update(|st| {
        extend_chain(st, 8);
    });
    assert!(
        app.prefetch_transparent(dir.path()).expect("prefetch"),
        "locked prefetch should advance chain to 8"
    );
    app.unlock(crate::dto::UnlockRequest {
        passphrase: "correct horse battery staple".into(),
    })
    .expect("unlock");
    let summary = app.load(dir.path()).expect("load");
    assert_eq!(summary.tip_height, 8);

    server.update(|st| {
        st.header_calls.clear();
        st.headers_batch_calls = 0;
        st.script_history_calls = 0;
    });
    let res = app.sync().expect("sync right after prefetch");
    assert_eq!(res.summary.tip_height, 8);
    {
        let st = server.state.lock().unwrap();
        assert_eq!(
            st.script_history_calls, 0,
            "sync right after fresh prefetch must reuse the prefetched script scan"
        );
        assert_eq!(
            st.headers_batch_calls, 0,
            "sync right after fresh prefetch must not re-download headers"
        );
    }
}

#[test]
fn cold_restore_batches_raw_txs_headers_and_merkle_proofs_with_partial_missing_merkle_fallback() {
    discovery::go_offline_for_test();
    let _pow = crate::spv::easy_pow_for_test();
    let _window = crate::spv::narrow_header_window_for_test(4);
    let dir = tempfile::tempdir().unwrap();
    let app = app_with_job(dir.path(), ChurnPhase::Cancelled, false);
    let recv_spk = Address::from_str(&app.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap()
        .script_pubkey();
    let sh = electrum_scripthash_hex(&recv_spk);

    let dir2 = tempfile::tempdir().unwrap();
    let app2 = app_with_job(dir2.path(), ChurnPhase::Cancelled, false);
    let recv_spk2 = Address::from_str(&app2.receive_address().unwrap())
        .unwrap()
        .require_network(Network::Testnet4)
        .unwrap()
        .script_pubkey();
    let sh2 = electrum_scripthash_hex(&recv_spk2);

    let gen = genesis_block(Network::Testnet4).header;
    let mut state = MockChainState::default();
    state.headers.insert(0, gen);

    let mut prev = gen;
    let mut history = Vec::new();
    let mut missing_merkle_txid = String::new();
    for height in 1..=60u32 {
        let cb = make_coinbase_tx(height);
        let cb_id = cb.compute_txid().to_byte_array();
        let mut tx = make_funding_tx(recv_spk.clone(), 100_000 + u64::from(height), height as u8);
        tx.output.push(TxOut {
            value: Amount::from_sat(100_000 + u64::from(height)),
            script_pubkey: recv_spk2.clone(),
        });
        let txid = tx.compute_txid();
        let root = sha256d_pair(&cb_id, &txid.to_byte_array());
        let hdr = mine_testnet_header(Header {
            version: BlockVersion::TWO,
            prev_blockhash: prev.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array(root),
            time: prev.time + 600,
            bits: easy_bits(),
            nonce: 0,
        });
        prev = hdr;
        state.headers.insert(height, hdr);
        state.tip_height = height;
        history.push(MockHistoryEntry {
            tx_hash: txid.to_string(),
            height: height as i32,
        });
        state.txs.insert(txid.to_string(), serialize(&tx));
        if height == 30 {
            missing_merkle_txid = txid.to_string();
            state.proofs.insert(
                (txid.to_string(), height as usize),
                Err("merkle branch not indexed yet".into()),
            );
        } else {
            state.proofs.insert(
                (txid.to_string(), height as usize),
                Ok(MockMerkleProof {
                    block_height: height as usize,
                    pos: 1,
                    merkle: vec![display_hex_from_internal(cb_id)],
                }),
            );
        }
    }
    state.histories.insert(sh, history.clone());
    state.histories.insert(sh2, history);
    // Extend to 65 so heights 1..=60 sit below the 4-block tip window (62..=65).
    extend_chain(&mut state, 65);

    let server = MockElectrumServer::start(state);
    configure_electrum(&app, &server.url, false);

    let expected_tx_batches = 60usize.div_ceil(crate::spv::RAW_TX_BATCH_SIZE);
    let expected_merkle_batches = 60usize.div_ceil(crate::spv::MERKLE_BATCH_SIZE);
    let max_header_batches = 1 + 60usize.div_ceil(crate::spv::HEADER_BATCH_SIZE);

    app.sync()
        .expect("cold restore sync with 1 missing merkle proof succeeds");
    {
        let st = server.state.lock().unwrap();
        assert_eq!(st.tx_get_calls, 60);
        assert_eq!(
            st.tx_get_batches, expected_tx_batches,
            "60 raw txs must be fetched in {expected_tx_batches} chunk(s) of {}, got {} round-trips",
            crate::spv::RAW_TX_BATCH_SIZE,
            st.tx_get_batches
        );
        assert!(
            st.header_calls.len() >= 60,
            "expected >= 60 isolated header fetches below window, got {}",
            st.header_calls.len()
        );
        assert!(
            st.header_batches <= max_header_batches,
            "isolated headers must be batched in <= {max_header_batches} round-trips, got {}",
            st.header_batches
        );
    }

    let utxos = app.list_unspent().unwrap();
    assert_eq!(utxos.len(), 60);
    let confirmed_count = utxos.iter().filter(|u| u.confirmations > 0).count();
    let pending: Vec<_> = utxos.iter().filter(|u| u.confirmations == 0).collect();
    assert_eq!(
        confirmed_count, 59,
        "59 valid proofs must confirm despite 1 protocol error in the same batch"
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].txid, missing_merkle_txid);
    assert_eq!(pending[0].status, CoinStatus::Pending);

    // Now test a clean cold sync where all 60 merkle proofs are available:
    // merkle proofs must take ceil(60 / MERKLE_BATCH_SIZE) batch round-trip(s), not 60.
    let cb30_id = make_coinbase_tx(30).compute_txid().to_byte_array();
    server.update(|st| {
        st.tx_get_calls = 0;
        st.tx_get_batches = 0;
        st.header_calls.clear();
        st.header_batches = 0;
        st.merkle_calls = 0;
        st.merkle_batches = 0;
        st.proofs.insert(
            (missing_merkle_txid.clone(), 30),
            Ok(MockMerkleProof {
                block_height: 30,
                pos: 1,
                merkle: vec![display_hex_from_internal(cb30_id)],
            }),
        );
    });
    configure_electrum(&app2, &server.url, false);
    app2.sync().expect("clean cold sync");
    {
        let st = server.state.lock().unwrap();
        assert_eq!(st.tx_get_calls, 60);
        assert_eq!(st.tx_get_batches, expected_tx_batches);
        assert!(st.header_batches <= max_header_batches);
        assert_eq!(st.merkle_calls, 60);
        assert_eq!(
            st.merkle_batches, expected_merkle_batches,
            "60 merkle proofs must be fetched in {expected_merkle_batches} batch round-trip(s), got {}",
            st.merkle_batches
        );
    }
    let utxos2 = app2.list_unspent().unwrap();
    assert_eq!(utxos2.len(), 60);
    assert!(utxos2
        .iter()
        .all(|u| u.confirmations > 0 && u.status == CoinStatus::Ready));
}

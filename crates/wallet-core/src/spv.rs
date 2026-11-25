//! SPV verification of Electrum headers, merkle proofs, and transactions (item 25).
//!
//! Ensures an Electrum server cannot confirm a coin with a forged merkle proof
//! (CVE-2017-12842, CVE-2012-2459) or a header that fails Litecoin scrypt proof-of-work,
//! target/retarget rules, `prev_blockhash` continuity, or fork cumulative-work resolution.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bdk_electrum::electrum_client::{ElectrumApi, Error as ElectrumError, GetMerkleRes};
use bdk_wallet::bitcoin::block::Header;
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bdk_wallet::bitcoin::constants::genesis_block;
use bdk_wallet::bitcoin::hashes::{sha256d, Hash};
use bdk_wallet::bitcoin::pow::{CompactTarget, Target, Work};
use bdk_wallet::bitcoin::{BlockHash, Transaction, TxMerkleNode, Txid};
use bdk_wallet::chain::spk_client::{
    FullScanRequest, FullScanResponse, SpkWithExpectedTxids, SyncRequest, SyncResponse,
};
use bdk_wallet::chain::{BlockId, ChainPosition, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet, Wallet};
use serde::{Deserialize, Serialize};

use crate::diag;
use crate::electrum::{BATCH_SIZE, STOP_GAP};
use crate::error::WalletError;
use crate::network::WalletNetwork;

/// On-disk SPV state per account (`electrum_spv.json`).
pub const ELECTRUM_SPV_FILE: &str = "electrum_spv.json";

/// Persistent SPV state stored beside `wallet.sqlite`.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectrumSpvState {
    /// Redacted (`user:pass@` stripped) URL of the server that produced the current
    /// unconfirmed server state.
    #[serde(default)]
    pub last_server_url: Option<String>,
    /// Unconfirmed transaction IDs reported only by `last_server_url` (not locally broadcast).
    #[serde(default)]
    pub server_unconfirmed_txids: BTreeSet<String>,
    /// Peg-in txids from MWEB history, never evicted. Kept here because the
    /// sealed history cannot be read by the locked prefetch.
    #[serde(default)]
    pub protected_txids: BTreeSet<String>,
    /// Verified block headers (height -> 80-byte raw hex) for fork work and retarget checks.
    #[serde(default)]
    pub verified_headers: BTreeMap<u32, String>,
    /// Monotonic timestamp counter used for `start_sync_with_revealed_spks_at` / `start_full_scan_at`
    /// and `apply_evicted_txs`.
    #[serde(default)]
    pub last_sync_ts: u64,
}

impl std::fmt::Debug for ElectrumSpvState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumSpvState")
            .field(
                "last_server_url",
                &crate::redact::redact_opt_url(&self.last_server_url),
            )
            .field(
                "server_unconfirmed_txids",
                &self.server_unconfirmed_txids.len(),
            )
            .field("protected_txids", &self.protected_txids.len())
            .field("verified_headers", &self.verified_headers.len())
            .field("last_sync_ts", &self.last_sync_ts)
            .finish()
    }
}

/// Specific reason an SPV check rejected Electrum data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpvError {
    /// 64-byte inner merkle node deserializes as a valid stripped transaction (CVE-2017-12842).
    InnerNodeIsValidTx { height: u32, level: usize },
    /// Left sibling in merkle path equals the current hash (CVE-2012-2459).
    LeftSiblingDuplicate { height: u32, level: usize },
    /// Right sibling duplicate at an odd leaf was followed by a distinct right sibling higher up.
    RightDuplicateNotRightmost { height: u32, level: usize },
    /// Merkle proof height or position does not match the requested block / tree depth.
    InvalidMerklePosition {
        expected_height: u32,
        proof_height: usize,
        pos: usize,
        depth: usize,
    },
    /// Computed merkle root does not match the verified block header's `merkle_root`.
    MerkleRootMismatch {
        height: u32,
        expected: TxMerkleNode,
        computed: TxMerkleNode,
    },
    /// Header at height 0 does not match the Litecoin genesis block for `network`.
    GenesisMismatch { expected: BlockHash, got: BlockHash },
    /// Header's `bits` is negative, zero, overflowed, or exceeds Litecoin `powLimit`.
    InvalidCompactTarget { height: u32, bits: u32 },
    /// Header's `scrypt(1024, 1, 1)` hash exceeds its target (`bits`).
    InsufficientProofOfWork {
        height: u32,
        pow_hash: BlockHash,
        bits: u32,
    },
    /// Header's `prev_blockhash` does not match the preceding block's hash.
    PrevHashMismatch {
        height: u32,
        expected_prev: BlockHash,
        got_prev: BlockHash,
    },
    /// Header's `bits` does not match the expected Litecoin difficulty target at `height`.
    TargetMismatch {
        height: u32,
        expected_bits: u32,
        got_bits: u32,
    },
    /// Server's reported tip is behind our local verified chain tip.
    ServerLagging { local_tip: u32, server_tip: u32 },
    /// Server is on a competing fork with less or equal cumulative work from the fork point,
    /// or no common ancestor could be verified.
    InsufficientForkWork {
        fork_height: u32,
        local_tip: u32,
        server_tip: u32,
    },
    /// Server returned an invalid or mismatched raw transaction.
    InvalidTransaction { txid: Txid, reason: String },
    /// Underlying Electrum transport / protocol failure.
    Transport(String),
}

impl std::fmt::Display for SpvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InnerNodeIsValidTx { height, level } => write!(
                f,
                "SPV merkle proof at height {height} level {level} has a 64-byte transaction as an inner node (CVE-2017-12842)"
            ),
            Self::LeftSiblingDuplicate { height, level } => write!(
                f,
                "SPV merkle proof at height {height} level {level} has a duplicated left sibling (CVE-2012-2459)"
            ),
            Self::RightDuplicateNotRightmost { height, level } => write!(
                f,
                "SPV merkle proof at height {height} level {level} has a non-rightmost duplicate sibling (CVE-2012-2459)"
            ),
            Self::InvalidMerklePosition {
                expected_height,
                proof_height,
                pos,
                depth,
            } => write!(
                f,
                "SPV merkle proof position/height invalid (expected height {expected_height}, got {proof_height}, pos {pos}, depth {depth})"
            ),
            Self::MerkleRootMismatch {
                height,
                expected,
                computed,
            } => write!(
                f,
                "SPV merkle root mismatch at height {height}: header has {expected}, proof computed {computed}"
            ),
            Self::GenesisMismatch { expected, got } => write!(
                f,
                "SPV genesis header mismatch: expected {expected}, server returned {got}"
            ),
            Self::InvalidCompactTarget { height, bits } => write!(
                f,
                "SPV header at height {height} has invalid compact target {bits:#010x}"
            ),
            Self::InsufficientProofOfWork {
                height,
                pow_hash,
                bits,
            } => write!(
                f,
                "SPV header at height {height} fails Litecoin scrypt proof-of-work (pow_hash {pow_hash}, bits {bits:#010x})"
            ),
            Self::PrevHashMismatch {
                height,
                expected_prev,
                got_prev,
            } => write!(
                f,
                "SPV header at height {height} prev_blockhash mismatch: expected {expected_prev}, got {got_prev}"
            ),
            Self::TargetMismatch {
                height,
                expected_bits,
                got_bits,
            } => write!(
                f,
                "SPV header at height {height} target mismatch: expected bits {expected_bits:#010x}, got {got_bits:#010x}"
            ),
            Self::ServerLagging {
                local_tip,
                server_tip,
            } => write!(
                f,
                "SPV rejected lagging Electrum server: server tip {server_tip} is behind local tip {local_tip}"
            ),
            Self::InsufficientForkWork {
                fork_height,
                local_tip,
                server_tip,
            } => write!(
                f,
                "SPV rejected competing fork at height {fork_height} (local tip {local_tip}, server tip {server_tip}): insufficient cumulative proof-of-work"
            ),
            Self::InvalidTransaction { txid, reason } => write!(
                f,
                "SPV rejected invalid transaction {txid}: {reason}"
            ),
            Self::Transport(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for SpvError {}

impl From<SpvError> for WalletError {
    fn from(e: SpvError) -> Self {
        WalletError::Electrum(e.to_string())
    }
}

/// Staged SPV state update to persist alongside `wallet.persist(&mut db)`.
pub struct SpvSyncOutcome {
    pub tip_height: u32,
    pub tip_time: u64,
    account_dir: PathBuf,
    state: ElectrumSpvState,
}

impl SpvSyncOutcome {
    pub fn persist_state(&self) -> Result<(), WalletError> {
        save_spv_state(&self.account_dir, &self.state)
    }
}

pub fn spv_path(account_dir: &Path) -> PathBuf {
    account_dir.join(ELECTRUM_SPV_FILE)
}

pub fn load_spv_state(account_dir: &Path) -> ElectrumSpvState {
    let path = spv_path(account_dir);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_spv_state(account_dir: &Path, state: &ElectrumSpvState) -> Result<(), WalletError> {
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| WalletError::Persist(format!("serialize electrum_spv.json: {e}")))?;
    crate::fs_atomic::write_atomic(&spv_path(account_dir), &json)
        .map_err(|e| WalletError::Persist(format!("write electrum_spv.json: {e}")))
}

const RETARGET_INTERVAL: u32 = 2016;
const TARGET_SPACING_SECS: u64 = 150;
const TARGET_TIMESPAN_SECS: u64 = 302_400;
/// Headers re-read below the lower of the local and server tips, so a short
/// reorg falls inside the verified window.
const REORG_SUFFIX: u32 = 8;
/// Most headers verified in one pass when the wallet is far behind the server.
const MAX_HEADER_WINDOW: u32 = 2016;
/// Deepest competing fork resolved by cumulative work; deeper ones are refused.
const MAX_FORK_DEPTH: u32 = 2160;
/// Verified headers kept in `electrum_spv.json`.
const KEEP_VERIFIED_HEADERS: usize = 2200;
/// Raw transactions requested per `blockchain.transaction.get` batch.
pub(crate) const RAW_TX_BATCH_SIZE: usize = 200;
/// Block headers requested per `blockchain.block.header` batch.
pub(crate) const HEADER_BATCH_SIZE: usize = 100;
/// Merkle branches requested per `blockchain.transaction.get_merkle` batch.
pub(crate) const MERKLE_BATCH_SIZE: usize = 100;

/// Lock-free progress counters updated during an Electrum SPV pass.
#[derive(Default)]
pub struct ElectrumProgress {
    pub scripts_scanned: AtomicU32,
    /// Scripts whose history was non-empty. Gap-limit scanning has no total,
    /// so the UI shows this beside `scripts_scanned` instead of a percentage.
    pub scripts_active: AtomicU32,
    pub txs_fetched: AtomicU32,
    pub txs_total: AtomicU32,
    pub anchors_verified: AtomicU32,
    pub anchors_total: AtomicU32,
}

impl ElectrumProgress {
    pub fn reset(&self) {
        self.scripts_scanned.store(0, Ordering::Relaxed);
        self.scripts_active.store(0, Ordering::Relaxed);
        self.txs_fetched.store(0, Ordering::Relaxed);
        self.txs_total.store(0, Ordering::Relaxed);
        self.anchors_verified.store(0, Ordering::Relaxed);
        self.anchors_total.store(0, Ordering::Relaxed);
    }
}

/// Litecoin `powLimit` on mainnet and testnet (`0x00000fff…ff`, compact `0x1e0fffff`).
const POW_LIMIT_BE: [u8; 32] = [
    0x00, 0x00, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

#[derive(Clone, Copy)]
struct PowParams {
    limit: Target,
    allow_min_difficulty: bool,
    no_retargeting: bool,
}

#[cfg(test)]
thread_local! {
    static EASY_POW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static HEADER_WINDOW: std::cell::Cell<u32> = const { std::cell::Cell::new(MAX_HEADER_WINDOW) };
}

/// Regtest-style proof of work on this thread until dropped: limit `0x207fffff`,
/// min-difficulty blocks allowed, no retargeting. Lets tests mine a header in a
/// hash or two while keeping the real genesis blocks.
#[cfg(test)]
pub(crate) struct EasyPowGuard(());

#[cfg(test)]
impl Drop for EasyPowGuard {
    fn drop(&mut self) {
        EASY_POW.with(|c| c.set(false));
    }
}

#[cfg(test)]
pub(crate) fn easy_pow_for_test() -> EasyPowGuard {
    EASY_POW.with(|c| c.set(true));
    EasyPowGuard(())
}

/// How many headers one pass reads from the server. Tests shrink this so an
/// anchor can sit below the window without mining two thousand blocks.
fn header_window() -> u32 {
    #[cfg(test)]
    {
        HEADER_WINDOW.with(|cell| cell.get())
    }
    #[cfg(not(test))]
    {
        MAX_HEADER_WINDOW
    }
}

/// Shrink [`header_window`] on this thread until dropped.
#[cfg(test)]
pub(crate) struct HeaderWindowGuard(u32);

#[cfg(test)]
impl Drop for HeaderWindowGuard {
    fn drop(&mut self) {
        HEADER_WINDOW.with(|cell| cell.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn narrow_header_window_for_test(window: u32) -> HeaderWindowGuard {
    let prev = HEADER_WINDOW.with(|cell| cell.replace(window.max(1)));
    HeaderWindowGuard(prev)
}

fn pow_params(network: WalletNetwork) -> PowParams {
    #[cfg(test)]
    if EASY_POW.with(|c| c.get()) {
        return PowParams {
            limit: Target::from_compact(CompactTarget::from_consensus(0x207f_ffff)),
            allow_min_difficulty: true,
            no_retargeting: true,
        };
    }
    PowParams {
        limit: Target::from_be_bytes(POW_LIMIT_BE),
        allow_min_difficulty: matches!(network, WalletNetwork::Testnet),
        no_retargeting: false,
    }
}

/// 256-bit unsigned integer for the retarget arithmetic, most significant limb first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct U256([u64; 4]);

impl U256 {
    fn from_target(target: Target) -> Self {
        let bytes = target.to_be_bytes();
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            *limb = u64::from_be_bytes(word);
        }
        U256(limbs)
    }

    fn to_target(self) -> Target {
        let mut bytes = [0u8; 32];
        for (chunk, limb) in bytes.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        Target::from_be_bytes(bytes)
    }

    fn bits(self) -> u32 {
        let mut remaining = 256u32;
        for limb in self.0 {
            if limb != 0 {
                return remaining - limb.leading_zeros();
            }
            remaining -= 64;
        }
        0
    }

    fn shr1(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (o, limb) in out.iter_mut().zip(self.0) {
            *o = (limb >> 1) | carry;
            carry = limb << 63;
        }
        U256(out)
    }

    fn shl1(self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u64;
        for (o, limb) in out.iter_mut().zip(self.0).rev() {
            *o = (limb << 1) | carry;
            carry = limb >> 63;
        }
        U256(out)
    }

    /// Wraps on overflow, like Core's `arith_uint256`.
    fn mul_u64(self, m: u64) -> Self {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for (o, limb) in out.iter_mut().zip(self.0).rev() {
            let product = u128::from(limb) * u128::from(m) + carry;
            *o = product as u64;
            carry = product >> 64;
        }
        U256(out)
    }

    fn div_u64(self, d: u64) -> Self {
        let mut out = [0u64; 4];
        let mut rem = 0u128;
        for (o, limb) in out.iter_mut().zip(self.0) {
            let cur = (rem << 64) | u128::from(limb);
            *o = (cur / u128::from(d)) as u64;
            rem = cur % u128::from(d);
        }
        U256(out)
    }
}

/// Litecoin's proof-of-work hash: `scrypt(N=1024, r=1, p=1)` of the 80-byte
/// header, salted with itself, read little-endian like a block hash.
pub fn scrypt_pow_hash(header: &Header) -> BlockHash {
    let bytes = serialize(header);
    let params = scrypt::Params::new(10, 1, 1).expect("scrypt(1024, 1, 1) params are valid");
    let mut out = [0u8; 32];
    scrypt::scrypt(&bytes, &bytes, &params, &mut out).expect("32-byte scrypt output is valid");
    BlockHash::from_byte_array(out)
}

/// Decode `bits` the way Core's `SetCompact` does, refusing negative,
/// overflowing, and zero targets.
pub fn decode_compact_target(bits: CompactTarget) -> Option<Target> {
    let raw = bits.to_consensus();
    let size = raw >> 24;
    let word = raw & 0x007f_ffff;
    if word != 0 && raw & 0x0080_0000 != 0 {
        return None;
    }
    if word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)) {
        return None;
    }
    let target = Target::from_compact(bits);
    (target != Target::ZERO).then_some(target)
}

pub fn header_work(header: &Header) -> Option<Work> {
    decode_compact_target(header.bits).map(Target::to_work)
}

/// Check a header's own proof of work: the genesis hash at height 0, a valid
/// compact target no easier than `powLimit`, and a scrypt hash under it.
/// Returns the header's block hash.
pub fn verify_header_pow(
    header: &Header,
    height: u32,
    network: WalletNetwork,
) -> Result<BlockHash, SpvError> {
    let hash = header.block_hash();
    if height == 0 {
        let expected = genesis_block(network.to_bitcoin_network()).block_hash();
        if hash != expected {
            return Err(SpvError::GenesisMismatch {
                expected,
                got: hash,
            });
        }
    }
    let params = pow_params(network);
    let bits = header.bits.to_consensus();
    let target = decode_compact_target(header.bits)
        .filter(|target| *target <= params.limit)
        .ok_or(SpvError::InvalidCompactTarget { height, bits })?;
    let pow_hash = scrypt_pow_hash(header);
    if !target.is_met_by(pow_hash) {
        return Err(SpvError::InsufficientProofOfWork {
            height,
            pow_hash,
            bits,
        });
    }
    Ok(hash)
}

/// Litecoin's `CalculateNextWorkRequired`, including the one-bit shift that
/// keeps a target near `powLimit` from overflowing 256 bits.
pub fn calculate_next_work_required(
    last_header: &Header,
    first_block_time: u32,
    network: WalletNetwork,
) -> CompactTarget {
    let params = pow_params(network);
    if params.no_retargeting {
        return last_header.bits;
    }
    let min = (TARGET_TIMESPAN_SECS / 4) as i64;
    let max = (TARGET_TIMESPAN_SECS * 4) as i64;
    let actual = (i64::from(last_header.time) - i64::from(first_block_time)).clamp(min, max) as u64;
    let limit = U256::from_target(params.limit);
    let mut target = U256::from_target(Target::from_compact(last_header.bits));
    let shift = target.bits() > limit.bits() - 1;
    if shift {
        target = target.shr1();
    }
    target = target.mul_u64(actual).div_u64(TARGET_TIMESPAN_SECS);
    if shift {
        target = target.shl1();
    }
    if target > limit {
        target = limit;
    }
    target.to_target().to_compact_lossy()
}

/// The `bits` Litecoin consensus requires for the header at `height`.
/// `get_header` returns an ancestor on the same chain.
#[cfg(test)]
pub fn expected_header_bits<F>(
    height: u32,
    header: &Header,
    network: WalletNetwork,
    mut get_header: F,
) -> Result<CompactTarget, SpvError>
where
    F: FnMut(u32) -> Result<Header, SpvError>,
{
    expected_bits_with(height, header, network, |h| get_header(h).map(Some))?
        .ok_or_else(|| SpvError::Transport(format!("missing ancestor header for height {height}")))
}

/// The `bits` Litecoin consensus requires at `height`, or `Ok(None)` when an
/// ancestor it needs is unknown.
fn expected_bits_with<F>(
    height: u32,
    header: &Header,
    network: WalletNetwork,
    mut get_header: F,
) -> Result<Option<CompactTarget>, SpvError>
where
    F: FnMut(u32) -> Result<Option<Header>, SpvError>,
{
    if height == 0 {
        return Ok(Some(header.bits));
    }
    let params = pow_params(network);
    let limit_bits = params.limit.to_compact_lossy();
    let Some(last) = get_header(height - 1)? else {
        return Ok(None);
    };
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        if !params.allow_min_difficulty {
            return Ok(Some(last.bits));
        }
        if u64::from(header.time) > u64::from(last.time) + 2 * TARGET_SPACING_SECS {
            return Ok(Some(limit_bits));
        }
        let mut at = height - 1;
        let mut cur = last;
        while at > 0 && !at.is_multiple_of(RETARGET_INTERVAL) && cur.bits == limit_bits {
            at -= 1;
            let Some(prev) = get_header(at)? else {
                return Ok(None);
            };
            cur = prev;
        }
        return Ok(Some(cur.bits));
    }
    // Litecoin looks back a full interval except at the first retarget.
    let lookback = if height == RETARGET_INTERVAL {
        RETARGET_INTERVAL - 1
    } else {
        RETARGET_INTERVAL
    };
    let Some(first) = get_header(height - 1 - lookback)? else {
        return Ok(None);
    };
    Ok(Some(calculate_next_work_required(
        &last, first.time, network,
    )))
}

/// Check `server_headers` against the local chain: proof of work, links,
/// targets, and, when the server is on another branch, strictly more
/// cumulative work than the local branch from the fork point.
#[cfg(test)]
pub fn verify_header_chain(
    local_headers: &BTreeMap<u32, Header>,
    local_tip_height: u32,
    server_headers: &BTreeMap<u32, Header>,
    server_tip_height: u32,
    network: WalletNetwork,
) -> Result<(), SpvError> {
    let local_hashes = local_headers
        .iter()
        .map(|(h, header)| (*h, header.block_hash()))
        .collect();
    resolve_chain(
        &local_hashes,
        local_headers,
        local_tip_height,
        server_headers,
        server_tip_height,
        network,
    )
    .map(|_| ())
}

/// Check server headers against the local chain (proof of work, links,
/// targets, fork work) and return the height where the two meet. Ancestors a target check needs but neither side has are
/// skipped; the driver fetches the ones it can.
fn resolve_chain(
    local_hashes: &BTreeMap<u32, BlockHash>,
    local_headers: &BTreeMap<u32, Header>,
    local_tip: u32,
    server: &BTreeMap<u32, Header>,
    server_tip: u32,
    network: WalletNetwork,
) -> Result<u32, SpvError> {
    if server_tip < local_tip {
        return Err(SpvError::ServerLagging {
            local_tip,
            server_tip,
        });
    }
    let no_fork = SpvError::InsufficientForkWork {
        fork_height: 0,
        local_tip,
        server_tip,
    };
    let mut hashes = BTreeMap::new();
    for (&height, header) in server.range(..=server_tip) {
        let hash = verify_header_pow(header, height, network)?;
        if let Some(&prev) = height.checked_sub(1).and_then(|p| hashes.get(&p)) {
            if header.prev_blockhash != prev {
                return Err(SpvError::PrevHashMismatch {
                    height,
                    expected_prev: prev,
                    got_prev: header.prev_blockhash,
                });
            }
        }
        hashes.insert(height, hash);
    }
    if !hashes.contains_key(&server_tip) {
        return Err(SpvError::Transport(format!(
            "Electrum server did not return its tip header at height {server_tip}"
        )));
    }

    let agreement = local_hashes
        .range(..=local_tip)
        .rev()
        .find(|(h, hash)| hashes.get(*h) == Some(*hash))
        .map(|(h, _)| *h)
        .ok_or(no_fork)?;

    let lookup = |h: u32| -> Result<Option<Header>, SpvError> {
        Ok(server.get(&h).copied().or_else(|| {
            (h <= agreement)
                .then(|| local_headers.get(&h).copied())
                .flatten()
        }))
    };
    for (&height, header) in server.range(..=server_tip).filter(|(h, _)| **h > 0) {
        if let Some(expected) = expected_bits_with(height, header, network, lookup)? {
            if expected != header.bits {
                return Err(SpvError::TargetMismatch {
                    height,
                    expected_bits: expected.to_consensus(),
                    got_bits: header.bits.to_consensus(),
                });
            }
        }
    }

    if agreement < local_tip {
        let weaker = SpvError::InsufficientForkWork {
            fork_height: agreement,
            local_tip,
            server_tip,
        };
        let zero = Work::from_be_bytes([0u8; 32]);
        let mut server_work = zero;
        let mut first_branch_work = None;
        for h in agreement + 1..=server_tip {
            let work = server
                .get(&h)
                .and_then(header_work)
                .ok_or_else(|| weaker.clone())?;
            first_branch_work.get_or_insert(work);
            server_work = server_work + work;
        }
        let estimate = first_branch_work.ok_or_else(|| weaker.clone())?;
        let mut local_work = zero;
        for h in agreement + 1..=local_tip {
            local_work = local_work
                + local_headers
                    .get(&h)
                    .and_then(header_work)
                    .unwrap_or(estimate);
        }
        if server_work <= local_work {
            return Err(weaker);
        }
    }
    Ok(agreement)
}

/// Verify an Electrum merkle branch for `txid` against a verified header,
/// refusing the forgeries `electrum_client::utils::validate_merkle_proof`
/// accepts: a 64-byte inner node that parses as a transaction
/// (CVE-2017-12842), a duplicated left sibling or a duplicate off the right
/// edge (CVE-2012-2459), and a position outside the tree.
pub fn verify_merkle_proof(
    txid: &Txid,
    header: &Header,
    expected_height: u32,
    proof: &GetMerkleRes,
) -> Result<(), SpvError> {
    let depth = proof.merkle.len();
    let pos = proof.pos;
    if proof.block_height != expected_height as usize || depth > 32 || pos >> depth != 0 {
        return Err(SpvError::InvalidMerklePosition {
            expected_height,
            proof_height: proof.block_height,
            pos,
            depth,
        });
    }
    let height = expected_height;
    let mut cur = txid.to_byte_array();
    let mut index = pos;
    let mut seen_duplicate = false;
    for (level, display) in proof.merkle.iter().enumerate() {
        let mut sibling = *display;
        sibling.reverse();
        let (left, right) = if index & 1 == 1 {
            if sibling == cur {
                return Err(SpvError::LeftSiblingDuplicate { height, level });
            }
            (sibling, cur)
        } else {
            if sibling == cur {
                seen_duplicate = true;
            } else if seen_duplicate {
                return Err(SpvError::RightDuplicateNotRightmost { height, level });
            }
            (cur, sibling)
        };
        let mut node = [0u8; 64];
        node[..32].copy_from_slice(&left);
        node[32..].copy_from_slice(&right);
        if deserialize::<Transaction>(&node).is_ok() {
            return Err(SpvError::InnerNodeIsValidTx { height, level });
        }
        cur = sha256d::Hash::hash(&node).to_byte_array();
        index >>= 1;
    }
    let computed = TxMerkleNode::from_byte_array(cur);
    if computed != header.merkle_root {
        return Err(SpvError::MerkleRootMismatch {
            height,
            expected: header.merkle_root,
            computed,
        });
    }
    Ok(())
}

/// Parse raw transaction bytes from Electrum and check they are the
/// transaction asked for and pass the context-free consensus checks.
pub fn verify_transaction(
    raw_bytes: &[u8],
    expected_txid: &Txid,
) -> Result<Arc<Transaction>, SpvError> {
    let invalid = |reason: String| SpvError::InvalidTransaction {
        txid: *expected_txid,
        reason,
    };
    let tx: Transaction =
        deserialize(raw_bytes).map_err(|e| invalid(format!("malformed bytes: {e}")))?;
    let txid = tx.compute_txid();
    if txid != *expected_txid {
        return Err(invalid(format!("server returned transaction {txid}")));
    }
    if tx.base_size() == 64 {
        return Err(invalid(
            "64-byte transaction could pass as a merkle node (CVE-2017-12842)".into(),
        ));
    }
    let mut prevouts = HashSet::with_capacity(tx.input.len());
    if !tx
        .input
        .iter()
        .all(|input| prevouts.insert(input.previous_output))
    {
        return Err(invalid("duplicate input (CVE-2018-17144)".into()));
    }
    let mut total = 0u64;
    for output in &tx.output {
        let value = output.value.to_sat();
        total = total
            .checked_add(value)
            .filter(|sum| {
                value <= crate::tx_invariants::MAX_MONEY && *sum <= crate::tx_invariants::MAX_MONEY
            })
            .ok_or_else(|| invalid("output value above MAX_MONEY".into()))?;
    }
    Ok(Arc::new(tx))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_header(hex_str: &str) -> Option<Header> {
    hex::decode(hex_str).ok().and_then(|b| deserialize(&b).ok())
}

fn decode_headers(stored: &BTreeMap<u32, String>) -> BTreeMap<u32, Header> {
    stored
        .iter()
        .filter_map(|(h, hex_str)| decode_header(hex_str).map(|header| (*h, header)))
        .collect()
}

/// `passed` plus the peg-ins an earlier sync stored, recorded back on `state`.
fn merge_protected(state: &mut ElectrumSpvState, passed: &HashSet<Txid>) -> HashSet<Txid> {
    let mut all: HashSet<Txid> = state
        .protected_txids
        .iter()
        .filter_map(|s| Txid::from_str(s).ok())
        .collect();
    all.extend(passed.iter().copied());
    state.protected_txids = all.iter().map(Txid::to_string).collect();
    all
}

fn transport(e: ElectrumError) -> SpvError {
    SpvError::Transport(e.to_string())
}

fn electrum_err(e: ElectrumError) -> WalletError {
    WalletError::Electrum(e.to_string())
}

fn is_unconfirmed(wallet: &Wallet, txid: Txid) -> bool {
    wallet
        .get_tx(txid)
        .is_some_and(|tx| matches!(tx.pos, ChainPosition::Unconfirmed { .. }))
}

/// True when `txid` spends one of this wallet's outputs, so it came from
/// someone holding our keys rather than only from the server.
fn spends_own_output(wallet: &Wallet, txid: Txid) -> bool {
    let graph = wallet.tx_graph();
    graph.get_tx(txid).is_some_and(|tx| {
        tx.input.iter().any(|input| {
            graph
                .get_txout(input.previous_output)
                .is_some_and(|out| wallet.is_mine(out.script_pubkey.clone()))
        })
    })
}

/// Evict the unconfirmed transactions only the previous Electrum server
/// reported, when the user switches to `new_server_url`. Transactions
/// spending our own coins and `protected` ones (peg-ins) stay. Persists the
/// wallet, then the SPV state. Returns how many were evicted.
pub fn evict_unconfirmed_on_server_switch(
    wallet: &mut PersistedWallet<Connection>,
    db: &mut Connection,
    account_dir: &Path,
    new_server_url: &str,
    protected: &HashSet<Txid>,
) -> Result<usize, WalletError> {
    let mut state = load_spv_state(account_dir);
    let new_server = crate::redact::redact_userinfo(new_server_url);
    if state.last_server_url.as_deref() == Some(new_server.as_str()) {
        return Ok(0);
    }
    let protected = merge_protected(&mut state, protected);
    let ts = unix_now().max(state.last_sync_ts.saturating_add(1));
    let evict: Vec<Txid> = state
        .server_unconfirmed_txids
        .iter()
        .filter_map(|s| Txid::from_str(s).ok())
        .filter(|txid| {
            !protected.contains(txid)
                && is_unconfirmed(wallet, *txid)
                && !spends_own_output(wallet, *txid)
        })
        .collect();
    if !evict.is_empty() {
        wallet.apply_evicted_txs(evict.iter().map(|txid| (*txid, ts)));
        wallet
            .persist(db)
            .map_err(|e| WalletError::Persist(e.to_string()))?;
        diag::log(format!(
            "electrum: server changed; dropped {} unconfirmed tx(s) only the previous server reported",
            evict.len()
        ));
    }
    state.last_server_url = None;
    state.server_unconfirmed_txids.clear();
    state.last_sync_ts = ts;
    save_spv_state(account_dir, &state)?;
    Ok(evict.len())
}

/// A header this account verified in an earlier sync.
pub fn verified_header_at(account_dir: &Path, height: u32) -> Option<Header> {
    load_spv_state(account_dir)
        .verified_headers
        .get(&height)
        .and_then(|hex_str| decode_header(hex_str))
}

/// Server headers this pass verified, and where they meet the local chain.
struct VerifiedChain {
    tip_height: u32,
    agreement: u32,
    /// Headers checked against the server on this pass.
    headers: BTreeMap<u32, Header>,
    local_hashes: BTreeMap<u32, BlockHash>,
    /// Headers verified on an earlier pass (`electrum_spv.json`). Not run
    /// through proof-of-work again. An anchor below this pass's window uses
    /// these instead of another `blockchain.block.header` round-trip.
    cached_headers: BTreeMap<u32, Header>,
    sub_ms: u64,
    range_ms: u64,
    walk_ms: u64,
    ancestors_ms: u64,
    pow_ms: u64,
}

impl VerifiedChain {
    fn verify_and_store_header(
        &mut self,
        height: u32,
        header: Header,
        network: WalletNetwork,
    ) -> Result<Header, SpvError> {
        let hash = verify_header_pow(&header, height, network)?;
        if let Some(&local) = self.local_hashes.get(&height) {
            if local != hash {
                return Err(SpvError::Transport(format!(
                    "Electrum header at height {height} conflicts with the verified chain"
                )));
            }
        }
        self.headers.insert(height, header);
        Ok(header)
    }

    fn prefetch_headers_at<E: ElectrumApi>(
        &mut self,
        api: &E,
        heights: &[u32],
        network: WalletNetwork,
    ) -> Result<(), SpvError> {
        let missing: Vec<u32> = heights
            .iter()
            .copied()
            .filter(|h| !self.headers.contains_key(h) && !self.cached_headers.contains_key(h))
            .collect::<BTreeSet<u32>>()
            .into_iter()
            .collect();
        for chunk in missing.chunks(HEADER_BATCH_SIZE) {
            let fetched = api.batch_block_header(chunk).map_err(transport)?;
            if fetched.len() != chunk.len() {
                return Err(SpvError::Transport(format!(
                    "Electrum server returned {} headers for {} heights",
                    fetched.len(),
                    chunk.len()
                )));
            }
            for (&height, header) in chunk.iter().zip(fetched) {
                self.verify_and_store_header(height, header, network)?;
            }
        }
        Ok(())
    }

    /// The verified header at `height`, reading and checking an isolated one
    /// below the window when needed.
    fn header_at<E: ElectrumApi>(
        &mut self,
        api: &E,
        height: u32,
        network: WalletNetwork,
    ) -> Result<Header, SpvError> {
        if let Some(header) = self.headers.get(&height) {
            return Ok(*header);
        }
        if let Some(header) = self.cached_headers.get(&height) {
            return Ok(*header);
        }
        let header = api.block_header(height as usize).map_err(transport)?;
        self.verify_and_store_header(height, header, network)
    }
}

fn fetch_headers<E: ElectrumApi>(
    api: &E,
    start: u32,
    end: u32,
    out: &mut BTreeMap<u32, Header>,
) -> Result<(), SpvError> {
    let mut height = start;
    while height <= end {
        let count = (end - height + 1).min(header_window());
        let res = api
            .block_headers(height as usize, count as usize)
            .map_err(transport)?;
        if res.headers.is_empty() {
            return Err(SpvError::Transport(format!(
                "Electrum server returned no headers from height {height}"
            )));
        }
        for header in res.headers.into_iter().take(count as usize) {
            out.insert(height, header);
            height += 1;
        }
    }
    Ok(())
}

fn fetch_header<E: ElectrumApi>(api: &E, height: u32) -> Result<Header, SpvError> {
    api.block_header(height as usize).map_err(transport)
}

fn fetch_headers_at<E: ElectrumApi>(
    api: &E,
    heights: &[u32],
    out: &mut BTreeMap<u32, Header>,
) -> Result<(), SpvError> {
    let missing: Vec<u32> = heights
        .iter()
        .copied()
        .filter(|h| !out.contains_key(h))
        .collect::<BTreeSet<u32>>()
        .into_iter()
        .collect();
    for chunk in missing.chunks(HEADER_BATCH_SIZE) {
        let fetched = api.batch_block_header(chunk).map_err(transport)?;
        if fetched.len() != chunk.len() {
            return Err(SpvError::Transport(format!(
                "Electrum server returned {} headers for {} heights",
                fetched.len(),
                chunk.len()
            )));
        }
        for (&height, header) in chunk.iter().zip(fetched) {
            out.insert(height, header);
        }
    }
    Ok(())
}

/// Ancestors the target checks need: the window's parent and the first
/// block of each retarget epoch that ends inside the window.
fn needed_ancestors(start: u32, server_tip: u32) -> Vec<u32> {
    let mut ancestors = Vec::new();
    if start > 1 && server_tip > 0 {
        ancestors.push(start - 1);
    }
    for height in (start..=server_tip).filter(|h| h.is_multiple_of(RETARGET_INTERVAL) && *h > 0) {
        let lookback = if height == RETARGET_INTERVAL {
            RETARGET_INTERVAL - 1
        } else {
            RETARGET_INTERVAL
        };
        ancestors.push(height - 1 - lookback);
    }
    ancestors
}

/// Read the server's recent headers and verify them against the local chain.
fn verify_server_chain<E: ElectrumApi>(
    wallet: &Wallet,
    api: &E,
    network: WalletNetwork,
    local_headers: &BTreeMap<u32, Header>,
) -> Result<VerifiedChain, SpvError> {
    let local_cp = wallet.latest_checkpoint();
    let local_tip = local_cp.height();
    let local_hashes: BTreeMap<u32, BlockHash> =
        local_cp.iter().map(|cp| (cp.height(), cp.hash())).collect();
    let sub_started = std::time::Instant::now();
    let notification = api.block_headers_subscribe().map_err(transport)?;
    let sub_ms = sub_started.elapsed().as_millis() as u64;
    let server_tip = u32::try_from(notification.height).map_err(|_| {
        SpvError::Transport(format!(
            "Electrum tip height {} overflows u32",
            notification.height
        ))
    })?;
    if server_tip < local_tip {
        return Err(SpvError::ServerLagging {
            local_tip,
            server_tip,
        });
    }
    if server_tip == local_tip
        && notification.header.block_hash() == local_cp.hash()
        && local_headers.get(&local_tip) == Some(&notification.header)
    {
        return Ok(VerifiedChain {
            tip_height: server_tip,
            agreement: local_tip,
            headers: BTreeMap::from([(local_tip, notification.header)]),
            local_hashes,
            cached_headers: local_headers.clone(),
            sub_ms,
            range_ms: 0,
            walk_ms: 0,
            ancestors_ms: 0,
            pow_ms: 0,
        });
    }

    let mut server = BTreeMap::new();
    let mut start = local_tip
        .min(server_tip)
        .saturating_sub(REORG_SUFFIX)
        .max(server_tip.saturating_sub(header_window().saturating_sub(1)))
        .max(1);
    // On an incremental sync where `start - 1` is not cached locally and fits
    // within `header_window()`, include `start - 1` in the contiguous range fetch
    // so `needed_ancestors` does not pay a separate `batch_block_header` round-trip.
    if local_tip > 0
        && start > 1
        && !local_headers.contains_key(&(start - 1))
        && server_tip - (start - 1) < header_window()
    {
        start -= 1;
    }
    let range_started = std::time::Instant::now();
    if server_tip > 0 {
        fetch_headers(api, start, server_tip, &mut server)?;
    }
    let range_ms = range_started.elapsed().as_millis() as u64;

    let mut ancestors_ms = 0u64;
    // On a cold wallet (local_tip == 0), no fork below local_tip is possible,
    // so genesis and the window's ancestor headers can be fetched in one batch.
    if local_tip == 0 {
        let anc_started = std::time::Instant::now();
        let mut initial = needed_ancestors(start, server_tip);
        initial.push(0);
        fetch_headers_at(api, &initial, &mut server)?;
        ancestors_ms += anc_started.elapsed().as_millis() as u64;
    }

    let walk_started = std::time::Instant::now();
    let mut agreement = None;
    for (&height, &hash) in local_hashes.range(..=local_tip).rev() {
        if let std::collections::btree_map::Entry::Vacant(slot) = server.entry(height) {
            slot.insert(fetch_header(api, height)?);
        }
        if server[&height].block_hash() == hash {
            agreement = Some(height);
            break;
        }
    }
    if let Some(fork) = agreement.filter(|a| *a < local_tip && a + 1 < start) {
        if server_tip - fork > MAX_FORK_DEPTH {
            return Err(SpvError::InsufficientForkWork {
                fork_height: fork,
                local_tip,
                server_tip,
            });
        }
        fetch_headers(api, fork + 1, start - 1, &mut server)?;
        start = fork + 1;
    }
    let walk_ms = walk_started.elapsed().as_millis() as u64;

    // Only skip ancestors at or below `agreement` that are already in our
    // verified `local_headers` cache (`electrum_spv.json`).
    let anc_started = std::time::Instant::now();
    let ancestors: Vec<u32> = needed_ancestors(start, server_tip)
        .into_iter()
        .filter(|h| !(agreement.is_some_and(|ag| *h <= ag) && local_headers.contains_key(h)))
        .collect();
    fetch_headers_at(api, &ancestors, &mut server)?;
    ancestors_ms += anc_started.elapsed().as_millis() as u64;

    let pow_started = std::time::Instant::now();
    let agreement = resolve_chain(
        &local_hashes,
        local_headers,
        local_tip,
        &server,
        server_tip,
        network,
    )?;
    let pow_ms = pow_started.elapsed().as_millis() as u64;
    Ok(VerifiedChain {
        tip_height: server_tip,
        agreement,
        headers: server,
        local_hashes,
        cached_headers: local_headers.clone(),
        sub_ms,
        range_ms,
        walk_ms,
        ancestors_ms,
        pow_ms,
    })
}

/// `Some(agree)` when this pass or a previously verified header is at `height`.
/// `None` when that height is below the window and not stored.
fn header_agrees(chain: &VerifiedChain, height: u32, hash: BlockHash) -> Option<bool> {
    let header = chain
        .headers
        .get(&height)
        .or_else(|| chain.cached_headers.get(&height))?;
    Some(header.block_hash() == hash)
}

fn anchor_at_height(wallet: &Wallet, txid: Txid, height: u32) -> Option<ConfirmationBlockTime> {
    let node = wallet.tx_graph().get_tx_node(txid)?;
    node.anchors
        .iter()
        .find(|anchor| anchor.block_id.height == height)
        .copied()
}

/// What one pass read from the server's script histories.
#[derive(Default)]
struct ScanOutput {
    tx_update: TxUpdate<ConfirmationBlockTime>,
    fetched: HashSet<Txid>,
    missing_txids: Vec<Txid>,
    reported: HashSet<Txid>,
    unconfirmed: BTreeSet<Txid>,
    pending_anchors: BTreeSet<(Txid, u32)>,
    expected_missing: BTreeSet<Txid>,
    /// Scripts sent to `blockchain.scripthash.get_history` this pass.
    scripts: usize,
    batches: usize,
    /// History rows returned, confirmed and unconfirmed.
    rows: usize,
    /// `blockchain.transaction.get` calls. A transaction already in the graph is not counted.
    raw_fetches: usize,
}

impl ScanOutput {
    fn queue_tx(&mut self, wallet: &Wallet, txid: Txid) {
        if !self.fetched.insert(txid) {
            return;
        }
        match wallet.tx_graph().get_tx(txid) {
            Some(tx) => self.tx_update.txs.push(tx),
            None => self.missing_txids.push(txid),
        }
    }

    fn fetch_missing_txs<E: ElectrumApi>(
        &mut self,
        api: &E,
        progress: Option<&ElectrumProgress>,
    ) -> Result<(), WalletError> {
        let missing = std::mem::take(&mut self.missing_txids);
        if let Some(p) = progress {
            p.txs_total.store(missing.len() as u32, Ordering::Relaxed);
        }
        for chunk in missing.chunks(RAW_TX_BATCH_SIZE) {
            self.raw_fetches = self.raw_fetches.saturating_add(chunk.len());
            let raws = api.batch_transaction_get_raw(chunk).map_err(electrum_err)?;
            if raws.len() != chunk.len() {
                return Err(WalletError::Electrum(format!(
                    "electrum server returned {} transactions for {} txids",
                    raws.len(),
                    chunk.len()
                )));
            }
            for (txid, raw) in chunk.iter().zip(raws) {
                let tx = verify_transaction(&raw, txid)?;
                self.tx_update.txs.push(tx);
            }
            if let Some(p) = progress {
                p.txs_fetched
                    .fetch_add(chunk.len() as u32, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    fn mark_unconfirmed(&mut self, txid: Txid, sync_ts: u64) {
        self.tx_update.seen_ats.insert((txid, sync_ts));
        self.unconfirmed.insert(txid);
    }
}

fn fetch_raw_tx_chunk<E: ElectrumApi>(
    api: &E,
    chunk: &[Txid],
) -> Result<Vec<Arc<Transaction>>, WalletError> {
    let raws = api.batch_transaction_get_raw(chunk).map_err(electrum_err)?;
    if raws.len() != chunk.len() {
        return Err(WalletError::Electrum(format!(
            "electrum server returned {} transactions for {} txids",
            raws.len(),
            chunk.len()
        )));
    }
    let mut txs = Vec::with_capacity(chunk.len());
    for (txid, raw) in chunk.iter().zip(raws) {
        txs.push(verify_transaction(&raw, txid)?);
    }
    Ok(txs)
}

type MerkleNeed = (Txid, u32, Header, BlockId);

struct MerkleChunkOutcome {
    anchored: Vec<(ConfirmationBlockTime, Txid)>,
    unconfirmed: Vec<Txid>,
}

fn fetch_merkle_chunk<E: ElectrumApi>(
    api: &E,
    chunk: &[MerkleNeed],
) -> Result<MerkleChunkOutcome, WalletError> {
    let reqs: Vec<(Txid, usize)> = chunk
        .iter()
        .map(|(txid, height, _, _)| (*txid, *height as usize))
        .collect();
    let mut anchored = Vec::with_capacity(chunk.len());
    let mut unconfirmed = Vec::new();
    match api.batch_transaction_get_merkle(&reqs) {
        Ok(proofs) => {
            if proofs.len() != chunk.len() {
                return Err(WalletError::Electrum(format!(
                    "electrum server returned {} merkle proofs for {} transactions",
                    proofs.len(),
                    chunk.len()
                )));
            }
            for ((txid, height, header, block_id), proof) in chunk.iter().zip(proofs) {
                verify_merkle_proof(txid, header, *height, &proof)?;
                let anchor = ConfirmationBlockTime {
                    block_id: *block_id,
                    confirmation_time: u64::from(header.time),
                };
                anchored.push((anchor, *txid));
            }
        }
        Err(ElectrumError::Protocol(_)) => {
            for (txid, height, header, block_id) in chunk {
                match api.transaction_get_merkle(txid, *height as usize) {
                    Ok(proof) => {
                        verify_merkle_proof(txid, header, *height, &proof)?;
                        let anchor = ConfirmationBlockTime {
                            block_id: *block_id,
                            confirmation_time: u64::from(header.time),
                        };
                        anchored.push((anchor, *txid));
                    }
                    Err(ElectrumError::Protocol(e)) => {
                        diag::log(format!(
                            "electrum: no merkle branch for {txid} at {height} ({e}); keeping it unconfirmed"
                        ));
                        unconfirmed.push(*txid);
                    }
                    Err(e) => return Err(electrum_err(e)),
                }
            }
        }
        Err(e) => return Err(electrum_err(e)),
    }
    Ok(MerkleChunkOutcome {
        anchored,
        unconfirmed,
    })
}

fn fetch_script_histories_resilient<E: ElectrumApi>(
    api: &E,
    batch: &[(u32, SpkWithExpectedTxids)],
    max_batch_size: &mut usize,
    batches_counter: &mut usize,
) -> Result<Vec<Vec<bdk_electrum::electrum_client::GetHistoryRes>>, WalletError> {
    let mut out = Vec::with_capacity(batch.len());
    let mut cursor = 0;
    while cursor < batch.len() {
        let width = (*max_batch_size).max(1).min(batch.len() - cursor);
        let slice = &batch[cursor..cursor + width];
        match api.batch_script_get_history(slice.iter().map(|(_, s)| s.spk.as_script())) {
            Ok(histories) => {
                if histories.len() != slice.len() {
                    return Err(WalletError::Electrum(format!(
                        "electrum server returned {} histories for {} scripts",
                        histories.len(),
                        slice.len()
                    )));
                }
                *batches_counter = batches_counter.saturating_add(1);
                out.extend(histories);
                cursor += width;
            }
            Err(_) if width > BATCH_SIZE.max(1) => {
                let halved = (width / 2).max(BATCH_SIZE.max(1));
                diag::log(format!(
                    "electrum: script history batch of {width} failed; halving max batch to {halved} and retrying"
                ));
                *max_batch_size = halved;
            }
            Err(e) => return Err(electrum_err(e)),
        }
    }
    Ok(out)
}

/// `bdk_electrum`'s `populate_with_spks`, with every raw transaction checked
/// against its txid and mined claims queued for merkle proofs.
///
/// Uses adaptive batch sizing (`100 -> 200 -> 400`) during full scans when scripts
/// are active, with automatic halving down to `BATCH_SIZE` (`50`) if a server
/// rejects a large batch.
#[allow(clippy::too_many_arguments)]
fn scan_spks<E: ElectrumApi>(
    api: &E,
    wallet: &Wallet,
    out: &mut ScanOutput,
    sync_ts: u64,
    tip_height: u32,
    mut spks: impl Iterator<Item = (u32, SpkWithExpectedTxids)>,
    stop_gap: usize,
    last_revealed: Option<u32>,
    progress: Option<&ElectrumProgress>,
) -> Result<Option<u32>, WalletError> {
    let mut unused = 0usize;
    let mut last_active = None;
    let mut max_batch_size = if stop_gap == usize::MAX {
        (BATCH_SIZE * 2).max(1)
    } else {
        (BATCH_SIZE * 8).max(1)
    };
    let mut batch_size = (BATCH_SIZE * 2).max(1).min(max_batch_size);
    loop {
        let batch: Vec<_> = spks.by_ref().take(batch_size).collect();
        if batch.is_empty() {
            return Ok(last_active);
        }
        out.scripts = out.scripts.saturating_add(batch.len());
        let histories =
            fetch_script_histories_resilient(api, &batch, &mut max_batch_size, &mut out.batches)?;
        if let Some(p) = progress {
            p.scripts_scanned
                .store(out.scripts as u32, Ordering::Relaxed);
        }
        for ((index, spk), history) in batch.into_iter().zip(histories) {
            out.rows = out.rows.saturating_add(history.len());
            let beyond_revealed = last_revealed.is_none_or(|lr| index > lr);
            if !history.is_empty() {
                last_active = Some(index);
                unused = 0;
                if let Some(p) = progress {
                    p.scripts_active.fetch_add(1, Ordering::Relaxed);
                }
            } else if beyond_revealed {
                unused = unused.saturating_add(1);
                if unused >= stop_gap {
                    return Ok(last_active);
                }
            }
            let listed: HashSet<Txid> = history.iter().map(|res| res.tx_hash).collect();
            out.expected_missing
                .extend(spk.expected_txids.difference(&listed).copied());
            for res in history {
                out.queue_tx(wallet, res.tx_hash);
                out.reported.insert(res.tx_hash);
                match u32::try_from(res.height) {
                    Ok(height) if height > 0 && height <= tip_height => {
                        out.pending_anchors.insert((res.tx_hash, height));
                    }
                    _ => out.mark_unconfirmed(res.tx_hash, sync_ts),
                }
            }
        }
        if stop_gap < usize::MAX {
            if unused == 0 {
                batch_size = batch_size.saturating_mul(2).min(max_batch_size);
            } else if stop_gap.saturating_sub(unused) <= BATCH_SIZE {
                batch_size = BATCH_SIZE.max(1).min(max_batch_size);
            } else {
                batch_size = (BATCH_SIZE * 2).max(1).min(max_batch_size);
            }
        } else {
            batch_size = max_batch_size;
        }
    }
}

/// How many mined claims were already anchored, and how many needed a merkle proof.
struct AnchorStats {
    pending: usize,
    merkle_fetches: usize,
    cached: usize,
}

/// Resolve cached anchors and prefetch any missing block headers on the primary
/// server before merkle proofs are requested.
fn prepare_anchors<E: ElectrumApi>(
    api: &E,
    wallet: &Wallet,
    chain: &mut VerifiedChain,
    out: &mut ScanOutput,
    network: WalletNetwork,
    progress: Option<&ElectrumProgress>,
) -> Result<(AnchorStats, Vec<MerkleNeed>), WalletError> {
    let pending_anchors = std::mem::take(&mut out.pending_anchors);
    let mut stats = AnchorStats {
        pending: pending_anchors.len(),
        merkle_fetches: 0,
        cached: 0,
    };
    let mut unanchored = Vec::new();
    for (txid, height) in pending_anchors {
        // A transaction already anchored at this height does not need another
        // header round-trip. Heights inside this pass's window (or stored from
        // an earlier pass) still have to match that header, so a reorg there
        // falls through and is proved again. Below the window, with no stored
        // header, the anchor was checked when it was first applied.
        if let Some(known) = anchor_at_height(wallet, txid, height) {
            match header_agrees(chain, height, known.block_id.hash) {
                Some(true) | None => {
                    stats.cached = stats.cached.saturating_add(1);
                    out.tx_update.anchors.insert((known, txid));
                    continue;
                }
                Some(false) => {}
            }
        }
        unanchored.push((txid, height));
    }

    let heights: Vec<u32> = unanchored.iter().map(|(_, h)| *h).collect();
    chain.prefetch_headers_at(api, &heights, network)?;

    let mut need_merkle = Vec::new();
    for (txid, height) in unanchored {
        let header = chain.header_at(api, height, network)?;
        let block_id = BlockId {
            height,
            hash: header.block_hash(),
        };
        let known = wallet.tx_graph().get_tx_node(txid).and_then(|node| {
            node.anchors
                .iter()
                .find(|anchor| anchor.block_id == block_id)
                .copied()
        });
        match known {
            Some(anchor) => {
                stats.cached = stats.cached.saturating_add(1);
                out.tx_update.anchors.insert((anchor, txid));
            }
            None => need_merkle.push((txid, height, header, block_id)),
        }
    }

    if let Some(p) = progress {
        p.anchors_total
            .store(need_merkle.len() as u32, Ordering::Relaxed);
    }
    Ok((stats, need_merkle))
}

/// Minimum combined raw-tx + uncached-merkle fetches before probing shard servers.
const MIN_SHARD_FETCHES: usize = 20;
const SHARD_PROBE_TIMEOUT_SECS: u8 = 2;
const SHARD_TOTAL_BUDGET: std::time::Duration = std::time::Duration::from_millis(1500);
const SHARD_SECOND_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// Count how many mined history claims are not already anchored in `wallet`
/// at a height consistent with `chain`, without issuing any network requests.
fn count_unanchored_claims(
    wallet: &Wallet,
    chain: &VerifiedChain,
    pending_anchors: &BTreeSet<(Txid, u32)>,
) -> usize {
    pending_anchors
        .iter()
        .filter(|&&(txid, height)| {
            if let Some(known) = anchor_at_height(wallet, txid, height) {
                if matches!(
                    header_agrees(chain, height, known.block_id.hash),
                    Some(true) | None
                ) {
                    return false;
                }
            }
            true
        })
        .count()
}

fn connect_verified_shards(
    primary_url: &str,
    shard_urls: &[String],
    validate_domain: bool,
    tip_height: u32,
    tip_hash: BlockHash,
    max_shards: usize,
) -> Vec<crate::electrum::ElectrumClient> {
    if max_shards == 0 {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    seen.insert(primary_url.to_string());
    let mut candidates = Vec::new();
    for url in shard_urls {
        if seen.insert(url.clone()) {
            candidates.push(url.clone());
        }
    }
    if candidates.is_empty() {
        return Vec::new();
    }

    let probe_started = std::time::Instant::now();
    let total_candidates = candidates.len();
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Option<crate::electrum::ElectrumClient>)>();

    for (idx, url) in candidates.into_iter().enumerate() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let client = (|| {
                let c = crate::electrum::connect_with_timeout(
                    &url,
                    validate_domain,
                    SHARD_PROBE_TIMEOUT_SECS,
                )
                .ok()?;
                crate::electrum::handshake(&c).ok()?;
                let hdr = c.inner.block_header(tip_height as usize).ok()?;
                (hdr.block_hash() == tip_hash).then_some(c)
            })();
            let _ = tx.send((idx, client));
        });
    }
    drop(tx);

    let total_deadline = probe_started + SHARD_TOTAL_BUDGET;
    let mut grace_deadline: Option<std::time::Instant> = None;
    let mut received = 0usize;
    let mut verified: Vec<(usize, crate::electrum::ElectrumClient)> = Vec::new();

    while received < total_candidates && verified.len() < max_shards {
        let deadline = match grace_deadline {
            Some(g) => total_deadline.min(g),
            None => total_deadline,
        };
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match rx.recv_timeout(remaining) {
            Ok((idx, maybe_client)) => {
                received += 1;
                if let Some(client) = maybe_client {
                    verified.push((idx, client));
                    if grace_deadline.is_none() {
                        grace_deadline = Some(std::time::Instant::now() + SHARD_SECOND_GRACE);
                    }
                }
            }
            Err(_) => break,
        }
    }

    verified.sort_by_key(|(idx, _)| *idx);
    let shards: Vec<_> = verified
        .into_iter()
        .take(max_shards)
        .map(|(_, c)| c)
        .collect();
    diag::log(format!(
        "sync: electrum shards connected={} tried={} ms={}",
        shards.len(),
        total_candidates,
        probe_started.elapsed().as_millis() as u64
    ));
    shards
}

/// Anchor each mined claim whose merkle branch verifies against a verified
/// header. A server that cannot produce a branch leaves the transaction
/// unconfirmed; a branch that fails verification fails the sync.
fn verify_anchors<E: ElectrumApi>(
    api: &E,
    wallet: &Wallet,
    chain: &mut VerifiedChain,
    out: &mut ScanOutput,
    network: WalletNetwork,
    sync_ts: u64,
    progress: Option<&ElectrumProgress>,
) -> Result<AnchorStats, WalletError> {
    let (mut stats, need_merkle) = prepare_anchors(api, wallet, chain, out, network, progress)?;
    for chunk in need_merkle.chunks(MERKLE_BATCH_SIZE) {
        stats.merkle_fetches = stats.merkle_fetches.saturating_add(chunk.len());
        let outcome = fetch_merkle_chunk(api, chunk)?;
        out.tx_update.anchors.extend(outcome.anchored);
        for txid in outcome.unconfirmed {
            out.mark_unconfirmed(txid, sync_ts);
        }
        if let Some(p) = progress {
            p.anchors_verified
                .fetch_add(chunk.len() as u32, Ordering::Relaxed);
        }
    }
    Ok(stats)
}

/// The checkpoint update: the agreement block, the server's recent blocks and
/// any heights replacing local checkpoints above it, and each anchor's block.
fn build_chain_update(
    wallet: &Wallet,
    chain: &VerifiedChain,
    anchors: &BTreeSet<(ConfirmationBlockTime, Txid)>,
) -> Result<CheckPoint, WalletError> {
    let agreement_cp = wallet
        .latest_checkpoint()
        .get(chain.agreement)
        .ok_or_else(|| WalletError::Electrum("SPV agreement block left the local chain".into()))?;
    let recent_from = chain.tip_height.saturating_sub(REORG_SUFFIX);
    let extension = chain
        .headers
        .range(chain.agreement + 1..)
        .take_while(|(h, _)| **h <= chain.tip_height)
        .filter(|(h, _)| **h >= recent_from || chain.local_hashes.contains_key(h))
        .map(|(h, header)| (*h, header.block_hash()));
    let mut tip = agreement_cp
        .extend(extension)
        .map_err(|_| WalletError::Electrum("SPV chain update does not connect".into()))?;
    for (anchor, _) in anchors {
        let BlockId { height, hash } = anchor.block_id;
        if tip.get(height).is_none() && height <= tip.height() {
            tip = tip.insert(height, hash);
        }
    }
    Ok(tip)
}

/// Verified Electrum header chain for an in-progress SPV sync pass.
///
/// Created by [`prepare_electrum_spv`] and consumed by [`finish_electrum_spv_with_shards`]
/// so callers can start MWEB and tip cross-checking as soon as the tip header
/// is verified, while script scanning and merkle verification run in parallel.
pub struct PreparedSpvSync {
    state: ElectrumSpvState,
    protected: HashSet<Txid>,
    server_url: String,
    server: String,
    sync_ts: u64,
    chain: VerifiedChain,
    tip: Header,
    account_dir: PathBuf,
    network: WalletNetwork,
}

impl PreparedSpvSync {
    pub fn tip_height(&self) -> u32 {
        self.chain.tip_height
    }

    pub fn tip_hash(&self) -> BlockHash {
        self.tip.block_hash()
    }

    pub fn agreement(&self) -> u32 {
        self.chain.agreement
    }

    /// Map of height -> block hash combining local checkpoints up to `agreement`
    /// and the server's verified headers above `agreement`, for `cross_check_tip`.
    pub fn verified_chain_hashes(&self) -> std::collections::HashMap<u32, BlockHash> {
        let mut out: std::collections::HashMap<u32, BlockHash> = self
            .chain
            .local_hashes
            .iter()
            .filter(|(&h, _)| h <= self.chain.agreement)
            .map(|(&h, &hash)| (h, hash))
            .collect();
        for (&h, hdr) in &self.chain.headers {
            if h <= self.chain.tip_height {
                out.insert(h, hdr.block_hash());
            }
        }
        out
    }
}

/// Verify the Electrum server's header chain and return a [`PreparedSpvSync`]
/// pinned to the verified tip before script scanning begins.
pub fn prepare_electrum_spv<E: ElectrumApi>(
    wallet: &Wallet,
    api: &E,
    network: WalletNetwork,
    account_dir: &Path,
    server_url: &str,
    protected: &HashSet<Txid>,
) -> Result<PreparedSpvSync, WalletError> {
    let mut state = load_spv_state(account_dir);
    let protected = merge_protected(&mut state, protected);
    let server = crate::redact::redact_userinfo(server_url);
    let sync_ts = unix_now().max(state.last_sync_ts.saturating_add(1));
    let local_headers = decode_headers(&state.verified_headers);

    let headers_started = std::time::Instant::now();
    let chain = verify_server_chain(wallet, api, network, &local_headers)?;
    let tip = *chain
        .headers
        .get(&chain.tip_height)
        .ok_or_else(|| WalletError::Electrum("SPV verified chain lost its tip header".into()))?;
    diag::log(format!(
        "sync: electrum headers tip={} count={} sub_ms={} range_ms={} walk_ms={} ancestors_ms={} pow_ms={} ms={}",
        chain.tip_height,
        chain.headers.len(),
        chain.sub_ms,
        chain.range_ms,
        chain.walk_ms,
        chain.ancestors_ms,
        chain.pow_ms,
        headers_started.elapsed().as_millis() as u64
    ));
    Ok(PreparedSpvSync {
        state,
        protected,
        server_url: server_url.to_string(),
        server,
        sync_ts,
        chain,
        tip,
        account_dir: account_dir.to_path_buf(),
        network,
    })
}

/// Complete an Electrum SPV pass prepared by [`prepare_electrum_spv`], optionally
/// sharding multi-batch raw-tx and merkle-proof fetches across additional
/// tip-verified Electrum servers.
pub fn finish_electrum_spv_with_shards<E: ElectrumApi + Sync>(
    wallet: &mut PersistedWallet<Connection>,
    api: &E,
    prepared: PreparedSpvSync,
    full_scan: bool,
    progress: Option<&ElectrumProgress>,
    shard_urls: &[String],
    validate_domain: bool,
) -> Result<SpvSyncOutcome, WalletError> {
    let PreparedSpvSync {
        state,
        protected,
        server_url,
        server,
        sync_ts,
        mut chain,
        tip,
        account_dir,
        network,
    } = prepared;

    let mut out = ScanOutput::default();
    let mut last_active_indices = BTreeMap::new();
    let scripts_started = std::time::Instant::now();
    if full_scan {
        diag::log("sync: electrum SPV full_scan starting");
        let mut request: FullScanRequest<KeychainKind> = wallet.start_full_scan_at(sync_ts).build();
        for keychain in request.keychains() {
            let last_revealed = request.last_revealed(&keychain);
            let spks = request
                .iter_spks(keychain)
                .map(|(index, spk)| (index, SpkWithExpectedTxids::from(spk)));
            if let Some(index) = scan_spks(
                api,
                wallet,
                &mut out,
                sync_ts,
                chain.tip_height,
                spks,
                STOP_GAP,
                last_revealed,
                progress,
            )? {
                last_active_indices.insert(keychain, index);
            }
        }
    } else {
        diag::log("sync: electrum SPV sync starting");
        let mut request: SyncRequest<(KeychainKind, u32)> =
            wallet.start_sync_with_revealed_spks_at(sync_ts).build();
        let spks = request
            .drain_spks_with_expected_txids()
            .enumerate()
            .map(|(i, spk)| (i as u32, spk))
            .collect::<Vec<_>>();
        scan_spks(
            api,
            wallet,
            &mut out,
            sync_ts,
            chain.tip_height,
            spks.into_iter(),
            usize::MAX,
            None,
            progress,
        )?;
    }

    let unanchored_count = count_unanchored_claims(wallet, &chain, &out.pending_anchors);
    let raw_chunks_count = out.missing_txids.len().div_ceil(RAW_TX_BATCH_SIZE);
    let merkle_est_count = unanchored_count.div_ceil(MERKLE_BATCH_SIZE);
    let total_fetches = out.missing_txids.len().saturating_add(unanchored_count);
    let use_shards = !shard_urls.is_empty()
        && total_fetches >= MIN_SHARD_FETCHES
        && (raw_chunks_count + merkle_est_count >= 2);
    let shard_probe_started = std::time::Instant::now();
    let shards = if use_shards {
        connect_verified_shards(
            &server_url,
            shard_urls,
            validate_domain,
            chain.tip_height,
            tip.block_hash(),
            2,
        )
    } else {
        Vec::new()
    };
    let shard_probe_elapsed = shard_probe_started.elapsed();

    let anchors = if shards.is_empty() {
        out.fetch_missing_txs(api, progress)?;
        diag::log(format!(
            "sync: electrum scripts n={} batches={} rows={} raw_fetches={} ms={}",
            out.scripts,
            out.batches,
            out.rows,
            out.raw_fetches,
            scripts_started
                .elapsed()
                .saturating_sub(shard_probe_elapsed)
                .as_millis() as u64
        ));
        let anchors_started = std::time::Instant::now();
        let anchors = verify_anchors(
            api, wallet, &mut chain, &mut out, network, sync_ts, progress,
        )?;
        diag::log(format!(
            "sync: electrum anchors pending={} merkle_fetches={} cached={} ms={}",
            anchors.pending,
            anchors.merkle_fetches,
            anchors.cached,
            anchors_started.elapsed().as_millis() as u64
        ));
        anchors
    } else {
        // Resolve cached anchors and prefetch any missing headers on the primary
        // server first, then overlap raw-tx and merkle-proof batches across the
        // primary server and verified shard servers.
        let anchors_started = std::time::Instant::now();
        let (mut stats, need_merkle) =
            prepare_anchors(api, wallet, &mut chain, &mut out, network, progress)?;
        let missing = std::mem::take(&mut out.missing_txids);
        out.raw_fetches = missing.len();
        stats.merkle_fetches = need_merkle.len();
        if let Some(p) = progress {
            p.txs_total.store(missing.len() as u32, Ordering::Relaxed);
        }
        let raw_chunks: Vec<&[Txid]> = missing.chunks(RAW_TX_BATCH_SIZE).collect();
        let merkle_chunks: Vec<&[MerkleNeed]> = need_merkle.chunks(MERKLE_BATCH_SIZE).collect();
        let total_workers = 1 + shards.len();

        let (raw_results, merkle_results) = std::thread::scope(|scope| {
            let mut shard_handles = Vec::new();
            for (worker_idx, shard) in shards.iter().enumerate() {
                let worker_id = worker_idx + 1;
                let my_raw: Vec<(usize, &[Txid])> = raw_chunks
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(i, _)| i % total_workers == worker_id)
                    .collect();
                let my_merkle: Vec<(usize, &[MerkleNeed])> = merkle_chunks
                    .iter()
                    .copied()
                    .enumerate()
                    .filter(|(i, _)| (i + raw_chunks.len()) % total_workers == worker_id)
                    .collect();
                shard_handles.push(scope.spawn(move || {
                    let mut raw_out = Vec::with_capacity(my_raw.len());
                    for (idx, chunk) in my_raw {
                        let res = fetch_raw_tx_chunk(&shard.inner, chunk);
                        if res.is_ok() {
                            if let Some(p) = progress {
                                p.txs_fetched
                                    .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                            }
                        }
                        raw_out.push((idx, res));
                    }
                    let mut merkle_out = Vec::with_capacity(my_merkle.len());
                    for (idx, chunk) in my_merkle {
                        let res = fetch_merkle_chunk(&shard.inner, chunk);
                        if res.is_ok() {
                            if let Some(p) = progress {
                                p.anchors_verified
                                    .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                            }
                        }
                        merkle_out.push((idx, res));
                    }
                    (raw_out, merkle_out)
                }));
            }

            let mut raw_slots: Vec<Option<Result<Vec<Arc<Transaction>>, WalletError>>> =
                (0..raw_chunks.len()).map(|_| None).collect();
            for (i, chunk) in raw_chunks
                .iter()
                .copied()
                .enumerate()
                .filter(|(i, _)| i.is_multiple_of(total_workers))
            {
                let res = fetch_raw_tx_chunk(api, chunk);
                if res.is_ok() {
                    if let Some(p) = progress {
                        p.txs_fetched
                            .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                    }
                }
                raw_slots[i] = Some(res);
            }

            let mut merkle_slots: Vec<Option<Result<MerkleChunkOutcome, WalletError>>> =
                (0..merkle_chunks.len()).map(|_| None).collect();
            for (i, chunk) in merkle_chunks
                .iter()
                .copied()
                .enumerate()
                .filter(|(i, _)| (i + raw_chunks.len()).is_multiple_of(total_workers))
            {
                let res = fetch_merkle_chunk(api, chunk);
                if res.is_ok() {
                    if let Some(p) = progress {
                        p.anchors_verified
                            .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                    }
                }
                merkle_slots[i] = Some(res);
            }

            for handle in shard_handles {
                if let Ok((r_vec, m_vec)) = handle.join() {
                    for (idx, res) in r_vec {
                        raw_slots[idx] = Some(res);
                    }
                    for (idx, res) in m_vec {
                        merkle_slots[idx] = Some(res);
                    }
                }
            }
            (raw_slots, merkle_slots)
        });

        // Any shard chunk that failed is retried on the primary server before failing the sync.
        for (i, slot) in raw_results.into_iter().enumerate() {
            let txs = match slot {
                Some(Ok(txs)) => txs,
                _ => {
                    let chunk = raw_chunks[i];
                    let txs = fetch_raw_tx_chunk(api, chunk)?;
                    if let Some(p) = progress {
                        p.txs_fetched
                            .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                    }
                    txs
                }
            };
            out.tx_update.txs.extend(txs);
        }
        diag::log(format!(
            "sync: electrum scripts n={} batches={} rows={} raw_fetches={} shards={} ms={}",
            out.scripts,
            out.batches,
            out.rows,
            out.raw_fetches,
            shards.len(),
            scripts_started
                .elapsed()
                .saturating_sub(shard_probe_elapsed)
                .as_millis() as u64
        ));

        for (i, slot) in merkle_results.into_iter().enumerate() {
            let outcome = match slot {
                Some(Ok(outcome)) => outcome,
                _ => {
                    let chunk = merkle_chunks[i];
                    let outcome = fetch_merkle_chunk(api, chunk)?;
                    if let Some(p) = progress {
                        p.anchors_verified
                            .fetch_add(chunk.len() as u32, Ordering::Relaxed);
                    }
                    outcome
                }
            };
            out.tx_update.anchors.extend(outcome.anchored);
            for txid in outcome.unconfirmed {
                out.mark_unconfirmed(txid, sync_ts);
            }
        }
        diag::log(format!(
            "sync: electrum anchors pending={} merkle_fetches={} cached={} shards={} ms={}",
            stats.pending,
            stats.merkle_fetches,
            stats.cached,
            shards.len(),
            anchors_started.elapsed().as_millis() as u64
        ));
        stats
    };
    let _ = anchors;

    let mut evict: BTreeSet<Txid> = std::mem::take(&mut out.expected_missing);
    evict.extend(
        state
            .server_unconfirmed_txids
            .iter()
            .filter_map(|s| Txid::from_str(s).ok())
            .filter(|txid| !spends_own_output(wallet, *txid)),
    );
    evict.retain(|txid| !out.reported.contains(txid) && !protected.contains(txid));
    out.tx_update
        .evicted_ats
        .extend(evict.iter().map(|txid| (*txid, sync_ts)));

    let chain_update = build_chain_update(wallet, &chain, &out.tx_update.anchors)?;
    let mut next = state.clone();
    next.last_server_url = Some(server);
    next.server_unconfirmed_txids = out
        .unconfirmed
        .iter()
        .filter(|txid| !protected.contains(*txid))
        .map(Txid::to_string)
        .collect();
    next.verified_headers.retain(|h, _| *h <= chain.agreement);
    for (height, header) in &chain.headers {
        next.verified_headers
            .insert(*height, hex::encode(serialize(header)));
    }
    while next.verified_headers.len() > KEEP_VERIFIED_HEADERS {
        next.verified_headers.pop_first();
    }
    next.last_sync_ts = sync_ts;

    let tx_update = out.tx_update;
    if full_scan {
        wallet.apply_update(FullScanResponse {
            tx_update,
            last_active_indices,
            chain_update: Some(chain_update),
        })
    } else {
        wallet.apply_update(SyncResponse {
            tx_update,
            chain_update: Some(chain_update),
        })
    }
    .map_err(|e| WalletError::Electrum(e.to_string()))?;

    Ok(SpvSyncOutcome {
        tip_height: chain.tip_height,
        tip_time: u64::from(tip.time),
        account_dir,
        state: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::absolute::LockTime;
    use bdk_wallet::bitcoin::block::Version as BlockVersion;
    use bdk_wallet::bitcoin::consensus::encode::serialize;
    use bdk_wallet::bitcoin::constants::genesis_block;
    use bdk_wallet::bitcoin::hashes::{sha256d, Hash, HashEngine};
    use bdk_wallet::bitcoin::transaction::Version as TxVersion;
    use bdk_wallet::bitcoin::{
        Amount, Network, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness,
    };

    fn sha256d_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut eng = sha256d::Hash::engine();
        eng.input(left);
        eng.input(right);
        sha256d::Hash::from_engine(eng).to_byte_array()
    }

    fn electrum_sibling_bytes(internal_node_bytes: [u8; 32]) -> [u8; 32] {
        let mut rev = internal_node_bytes;
        rev.reverse();
        rev
    }

    /// Mine a header under Litecoin's `scrypt(1024, 1, 1)` PoW. Only fast at
    /// regtest bits (`0x207fffff`); real Litecoin targets take ~a million hashes.
    fn mine_scrypt_header(mut header: Header) -> Header {
        let target = Target::from_compact(header.bits);
        for nonce in header.nonce..=u32::MAX {
            header.nonce = nonce;
            let pow = scrypt_pow_hash(&header);
            if target.is_met_by(pow) {
                return header;
            }
        }
        panic!("failed to find scrypt nonce for test header");
    }

    fn make_standard_tx(prev_byte: u8, vout: u32, sats: u64) -> Transaction {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&[prev_byte; 20]);
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([prev_byte; 32]),
                    vout,
                },
                script_sig: ScriptBuf::from_bytes(vec![0x01, prev_byte]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
            mw_tx: None,
            is_hog_ex: false,
        }
    }

    /// A consensus-valid 64-byte transaction (the CVE-2017-12842 gadget):
    /// version 4 + one input 42 + one output with a 4-byte script 14 + locktime 4.
    fn make_64_byte_tx() -> Transaction {
        let tx = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x11; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0xaa, 0xbb]),
            }],
            mw_tx: None,
            is_hog_ex: false,
        };
        assert_eq!(serialize(&tx).len(), 64);
        assert_eq!(tx.base_size(), 64);
        tx
    }

    #[test]
    fn merkle_proof_accepts_single_multi_and_legitimate_right_duplicate() {
        let gen = genesis_block(Network::Testnet4).header;
        let t0 = make_standard_tx(1, 0, 100_000).compute_txid();
        let t1 = make_standard_tx(2, 0, 200_000).compute_txid();
        let t2 = make_standard_tx(3, 0, 300_000).compute_txid();

        // 1. Single-tx (coinbase-only) block: empty merkle path, pos == 0.
        let mut h1 = gen;
        h1.merkle_root = TxMerkleNode::from_byte_array(t0.to_byte_array());
        let proof_single = GetMerkleRes {
            block_height: 1,
            pos: 0,
            merkle: vec![],
        };
        verify_merkle_proof(&t0, &h1, 1, &proof_single).expect("valid single-tx proof");

        // 2. Two-tx block: [t0, t1], prove t1 at pos 1.
        let root_2 = sha256d_pair(&t0.to_byte_array(), &t1.to_byte_array());
        let mut h2 = gen;
        h2.merkle_root = TxMerkleNode::from_byte_array(root_2);
        let proof_two = GetMerkleRes {
            block_height: 2,
            pos: 1,
            merkle: vec![electrum_sibling_bytes(t0.to_byte_array())],
        };
        verify_merkle_proof(&t1, &h2, 2, &proof_two).expect("valid 2-tx proof");

        // 3. Three-tx block [t0, t1, t2]: t2 at pos=2 is the odd last leaf, so its right sibling
        // at level 0 is legitimately t2 itself, and its left sibling at level 1 is H(t0 || t1).
        let h01 = sha256d_pair(&t0.to_byte_array(), &t1.to_byte_array());
        let h22 = sha256d_pair(&t2.to_byte_array(), &t2.to_byte_array());
        let root_3 = sha256d_pair(&h01, &h22);
        let mut h3 = gen;
        h3.merkle_root = TxMerkleNode::from_byte_array(root_3);
        let proof_three = GetMerkleRes {
            block_height: 3,
            pos: 2,
            merkle: vec![
                electrum_sibling_bytes(t2.to_byte_array()),
                electrum_sibling_bytes(h01),
            ],
        };
        verify_merkle_proof(&t2, &h3, 3, &proof_three)
            .expect("legitimate odd-leaf right-sibling duplicate must pass");
    }

    #[test]
    fn merkle_proof_rejects_cve_2017_12842_64_byte_tx_inner_node() {
        let tx64 = make_64_byte_tx();
        let raw64 = serialize(&tx64);
        assert_eq!(raw64.len(), 64);

        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&raw64[..32]);
        right.copy_from_slice(&raw64[32..64]);

        // An attacker takes a real confirmed 64-byte transaction (whose txid = sha256d(left || right)
        // is in the merkle tree) and claims `right` is a confirmed transaction at `pos = 1` with left
        // sibling `left`.
        let fake_leaf_txid = Txid::from_byte_array(right);
        let parent_hash = sha256d_pair(&left, &right);
        assert_eq!(parent_hash, tx64.compute_txid().to_byte_array());

        let mut header = genesis_block(Network::Testnet4).header;
        header.merkle_root = TxMerkleNode::from_byte_array(parent_hash);

        let forged_proof = GetMerkleRes {
            block_height: 10,
            pos: 1,
            merkle: vec![electrum_sibling_bytes(left)],
        };

        // Note that `electrum_client::utils::validate_merkle_proof` accepts this forged proof!
        assert!(
            bdk_electrum::electrum_client::utils::validate_merkle_proof(
                &fake_leaf_txid,
                &header.merkle_root,
                &forged_proof
            ),
            "pin 6ffa5afa validate_merkle_proof is vulnerable to CVE-2017-12842"
        );

        let err = verify_merkle_proof(&fake_leaf_txid, &header, 10, &forged_proof)
            .expect_err("CVE-2017-12842 inner node must be rejected");
        assert_eq!(
            err,
            SpvError::InnerNodeIsValidTx {
                height: 10,
                level: 0
            }
        );
    }

    #[test]
    fn merkle_proof_rejects_cve_2012_2459_left_sibling_duplicate_and_non_rightmost_duplicate() {
        let gen = genesis_block(Network::Testnet4).header;
        let t0 = make_standard_tx(1, 0, 100_000).compute_txid();
        let t1 = make_standard_tx(2, 0, 200_000).compute_txid();
        let t2 = make_standard_tx(3, 0, 300_000).compute_txid();

        let h01 = sha256d_pair(&t0.to_byte_array(), &t1.to_byte_array());
        let h22 = sha256d_pair(&t2.to_byte_array(), &t2.to_byte_array());
        let root_3 = sha256d_pair(&h01, &h22);
        let mut header = gen;
        header.merkle_root = TxMerkleNode::from_byte_array(root_3);

        // 1. Forged pos=3 (odd index -> sibling is on the LEFT, equal to t2).
        // `electrum_client::utils::validate_merkle_proof` accepts this!
        let forged_left_dup = GetMerkleRes {
            block_height: 5,
            pos: 3,
            merkle: vec![
                electrum_sibling_bytes(t2.to_byte_array()),
                electrum_sibling_bytes(h01),
            ],
        };
        assert!(
            bdk_electrum::electrum_client::utils::validate_merkle_proof(
                &t2,
                &header.merkle_root,
                &forged_left_dup
            ),
            "pin 6ffa5afa validate_merkle_proof is vulnerable to CVE-2012-2459"
        );

        let err = verify_merkle_proof(&t2, &header, 5, &forged_left_dup)
            .expect_err("left sibling duplicate must be rejected");
        assert_eq!(
            err,
            SpvError::LeftSiblingDuplicate {
                height: 5,
                level: 0
            }
        );

        // 2. Non-rightmost duplicate: duplicate right sibling at level 0 (pos=0, even), followed by
        // another right sibling at level 1 (index=0, even) that is distinct, meaning this leaf was NOT
        // at the rightmost edge of the tree!
        let h00 = sha256d_pair(&t0.to_byte_array(), &t0.to_byte_array());
        let fake_root = sha256d_pair(&h00, &h01);
        let mut header2 = gen;
        header2.merkle_root = TxMerkleNode::from_byte_array(fake_root);
        let non_rightmost_dup = GetMerkleRes {
            block_height: 6,
            pos: 0,
            merkle: vec![
                electrum_sibling_bytes(t0.to_byte_array()),
                electrum_sibling_bytes(h01),
            ],
        };
        let err2 = verify_merkle_proof(&t0, &header2, 6, &non_rightmost_dup)
            .expect_err("duplicate followed by right sibling must be rejected");
        assert_eq!(
            err2,
            SpvError::RightDuplicateNotRightmost {
                height: 6,
                level: 1
            }
        );
    }

    #[test]
    fn merkle_proof_rejects_bad_height_out_of_range_pos_and_wrong_root() {
        let gen = genesis_block(Network::Testnet4).header;
        let t0 = make_standard_tx(1, 0, 100_000).compute_txid();
        let t1 = make_standard_tx(2, 0, 200_000).compute_txid();
        let root = sha256d_pair(&t0.to_byte_array(), &t1.to_byte_array());
        let mut header = gen;
        header.merkle_root = TxMerkleNode::from_byte_array(root);

        // Wrong block_height in proof
        let bad_height = GetMerkleRes {
            block_height: 99,
            pos: 0,
            merkle: vec![electrum_sibling_bytes(t1.to_byte_array())],
        };
        assert!(matches!(
            verify_merkle_proof(&t0, &header, 10, &bad_height),
            Err(SpvError::InvalidMerklePosition { .. })
        ));

        // Out-of-bounds pos (pos = 2 in a depth-1 tree of 2 leaves; `validate_merkle_proof` accepts!)
        let bad_pos = GetMerkleRes {
            block_height: 10,
            pos: 2,
            merkle: vec![electrum_sibling_bytes(t1.to_byte_array())],
        };
        assert!(matches!(
            verify_merkle_proof(&t0, &header, 10, &bad_pos),
            Err(SpvError::InvalidMerklePosition { .. })
        ));

        // Empty merkle path with non-zero pos
        let mut single_header = gen;
        single_header.merkle_root = TxMerkleNode::from_byte_array(t0.to_byte_array());
        let bad_single_pos = GetMerkleRes {
            block_height: 10,
            pos: 1,
            merkle: vec![],
        };
        assert!(matches!(
            verify_merkle_proof(&t0, &single_header, 10, &bad_single_pos),
            Err(SpvError::InvalidMerklePosition { .. })
        ));

        // Wrong root
        let wrong_root_proof = GetMerkleRes {
            block_height: 10,
            pos: 0,
            merkle: vec![electrum_sibling_bytes(t0.to_byte_array())],
        };
        assert!(matches!(
            verify_merkle_proof(&t0, &header, 10, &wrong_root_proof),
            Err(SpvError::MerkleRootMismatch { .. })
        ));
    }

    #[test]
    fn header_pow_verifies_litecoin_scrypt_and_rejects_bad_pow_or_regtest_bits() {
        // 1. Mainnet genesis block passes scrypt PoW and matches known scrypt hash:
        //    d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6badf7d97 (internal LE)
        let mainnet_gen = genesis_block(Network::Bitcoin).header;
        verify_header_pow(&mainnet_gen, 0, WalletNetwork::Mainnet)
            .expect("Litecoin mainnet genesis must pass scrypt PoW");

        // 2. Testnet4 genesis block passes scrypt PoW
        let testnet_gen = genesis_block(Network::Testnet4).header;
        verify_header_pow(&testnet_gen, 0, WalletNetwork::Testnet)
            .expect("Litecoin testnet4 genesis must pass scrypt PoW");

        // 3. Genesis mismatch at height 0 (e.g. testnet genesis presented on mainnet)
        assert!(matches!(
            verify_header_pow(&testnet_gen, 0, WalletNetwork::Mainnet),
            Err(SpvError::GenesisMismatch { .. })
        ));

        // 4. Regtest bits (0x207fffff > Litecoin powLimit 0x1e0fffff) or zero/negative bits rejected
        for bad_bits in [0x207fffff_u32, 0x00000000, 0x1e800000, 0x1f00ffff] {
            let mut h = testnet_gen;
            h.bits = CompactTarget::from_consensus(bad_bits);
            assert!(
                matches!(
                    verify_header_pow(&h, 1, WalletNetwork::Testnet),
                    Err(SpvError::InvalidCompactTarget { .. })
                ),
                "bad bits {bad_bits:#010x} must be rejected"
            );
        }

        // 5. Header whose scrypt hash does not meet a stricter target is rejected, even if its
        // SHA256d block_hash happens to be low or valid under regtest.
        let mut insufficient = testnet_gen;
        insufficient.prev_blockhash = testnet_gen.block_hash();
        insufficient.bits = CompactTarget::from_consensus(0x1b00ffff);
        insufficient.nonce = 0;
        assert!(matches!(
            verify_header_pow(&insufficient, 1, WalletNetwork::Testnet),
            Err(SpvError::InsufficientProofOfWork { .. })
        ));
    }

    #[test]
    fn header_retarget_and_testnet4_min_difficulty_match_litecoin_consensus() {
        let gen = genesis_block(Network::Bitcoin).header;

        // 1. Mid-epoch on Mainnet: bits must equal parent's bits.
        let mut h1 = gen;
        h1.prev_blockhash = gen.block_hash();
        h1.time = gen.time + 150;
        let expected = expected_header_bits(1, &h1, WalletNetwork::Mainnet, |height| {
            assert_eq!(height, 0);
            Ok(gen)
        })
        .unwrap();
        assert_eq!(expected, gen.bits);

        // 2. Retarget at height 2016 on Mainnet: uses height 0 (2016 - 2016) as first block.
        // Fast epoch (quarter of 302,400s = 75,600s) -> target divides by 4.
        let mut h2015 = gen;
        h2015.bits = CompactTarget::from_consensus(0x1d00ffff);
        h2015.time = gen.time + 75_600;
        let retarget_fast = calculate_next_work_required(&h2015, gen.time, WalletNetwork::Mainnet);
        let expected_fast = Target::from_compact(h2015.bits)
            .min_transition_threshold()
            .to_compact_lossy();
        assert_eq!(retarget_fast, expected_fast);

        // 3. Retarget with `> 235`-bit target (`0x1e0ffff0`) does not overflow U256 when multiplied
        // by max timespan (1,209,600s) and clamps to Litecoin powLimit (`0x1e0fffff`).
        let mut h2015_max = gen;
        h2015_max.bits = CompactTarget::from_consensus(0x1e0ffff0);
        h2015_max.time = gen.time + 10_000_000;
        let retarget_slow =
            calculate_next_work_required(&h2015_max, gen.time, WalletNetwork::Mainnet);
        assert_eq!(retarget_slow, CompactTarget::from_consensus(0x1e0fffff));

        // 4. Retarget at height 4032: Litecoin's time-warp fix looks back 2016 blocks to height 2015
        // (4031 - 2016 = 2015), NOT 2016!
        let mut queried_heights = Vec::new();
        let mut h4032 = gen;
        h4032.time = gen.time + 600_000;
        let _ = expected_header_bits(4032, &h4032, WalletNetwork::Mainnet, |h| {
            queried_heights.push(h);
            let mut hdr = gen;
            hdr.time = gen.time + h * 150;
            Ok(hdr)
        })
        .unwrap();
        assert!(
            queried_heights.contains(&4031) && queried_heights.contains(&2015),
            "height 4032 retarget must query 4031 and 2015 (2016-block lookback), got {queried_heights:?}"
        );

        // 5. Testnet4 min-difficulty rule (> 300s gap -> 0x1e0fffff) and walk-back rule (<= 300s gap
        // after a min-difficulty block returns the last non-min-difficulty bits).
        let t_gen = genesis_block(Network::Testnet4).header;
        let real_bits = CompactTarget::from_consensus(0x1d00ffff);
        let min_diff_bits = CompactTarget::from_consensus(0x1e0fffff);

        let mut b2016 = t_gen;
        b2016.bits = real_bits;
        b2016.time = t_gen.time + 2016 * 150;

        let mut b2017 = b2016;
        b2017.prev_blockhash = b2016.block_hash();
        b2017.time = b2016.time + 301; // > 2 * 150s -> min difficulty allowed
        b2017.bits = min_diff_bits;

        let bits_2017 = expected_header_bits(2017, &b2017, WalletNetwork::Testnet, |h| match h {
            2016 => Ok(b2016),
            _ => unreachable!("unexpected height {h}"),
        })
        .unwrap();
        assert_eq!(bits_2017, min_diff_bits);

        let mut b2018 = b2017;
        b2018.prev_blockhash = b2017.block_hash();
        b2018.time = b2017.time + 120; // <= 300s -> must walk back to 2016's `real_bits`
        b2018.bits = real_bits;

        let bits_2018 = expected_header_bits(2018, &b2018, WalletNetwork::Testnet, |h| match h {
            2017 => Ok(b2017),
            2016 => Ok(b2016),
            _ => unreachable!("unexpected height {h}"),
        })
        .unwrap();
        assert_eq!(bits_2018, real_bits);
    }

    /// A min-difficulty child of `parent` under [`easy_pow_for_test`].
    fn easy_child(parent: &Header, tag: u8) -> Header {
        mine_scrypt_header(Header {
            version: BlockVersion::TWO,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([tag; 32]),
            time: parent.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        })
    }

    #[test]
    fn header_chain_resolution_rejects_prev_mismatch_lagging_and_weaker_fork() {
        let _pow = easy_pow_for_test();
        let gen = genesis_block(Network::Testnet4).header;
        let b1 = easy_child(&gen, 1);
        let b2_local = easy_child(&b1, 2);

        let local_chain: BTreeMap<u32, Header> =
            [(0, gen), (1, b1), (2, b2_local)].into_iter().collect();

        // 1. Lagging server (server tip 1 < local tip 2) -> ServerLagging
        let lagging_server: BTreeMap<u32, Header> = [(0, gen), (1, b1)].into_iter().collect();
        assert_eq!(
            verify_header_chain(&local_chain, 2, &lagging_server, 1, WalletNetwork::Testnet),
            Err(SpvError::ServerLagging {
                local_tip: 2,
                server_tip: 1,
            })
        );

        // 2. Prev-hash mismatch at height 2
        let mut b2_broken = b2_local;
        b2_broken.prev_blockhash = gen.block_hash();
        let b2_broken = mine_scrypt_header(b2_broken);
        let broken_server: BTreeMap<u32, Header> =
            [(0, gen), (1, b1), (2, b2_broken)].into_iter().collect();
        assert!(matches!(
            verify_header_chain(&local_chain, 1, &broken_server, 2, WalletNetwork::Testnet),
            Err(SpvError::PrevHashMismatch { height: 2, .. })
        ));

        // 3. Competing fork at height 2 with equal cumulative work -> InsufficientForkWork
        let b2_fork = easy_child(&b1, 3);
        let equal_or_less_fork: BTreeMap<u32, Header> =
            [(0, gen), (1, b1), (2, b2_fork)].into_iter().collect();
        assert_eq!(
            verify_header_chain(
                &local_chain,
                2,
                &equal_or_less_fork,
                2,
                WalletNetwork::Testnet
            ),
            Err(SpvError::InsufficientForkWork {
                fork_height: 1,
                local_tip: 2,
                server_tip: 2,
            })
        );

        // 4. Competing fork extending to height 3 with strictly greater cumulative work succeeds
        let b3_fork = easy_child(&b2_fork, 4);
        let heavier_fork: BTreeMap<u32, Header> = [(0, gen), (1, b1), (2, b2_fork), (3, b3_fork)]
            .into_iter()
            .collect();
        verify_header_chain(&local_chain, 2, &heavier_fork, 3, WalletNetwork::Testnet)
            .expect("heavier valid fork must be accepted");
    }

    #[test]
    fn transaction_verifier_rejects_mismatched_txid_64_byte_dup_inputs_and_max_money() {
        let valid_tx = make_standard_tx(7, 0, 500_000);
        let raw_valid = serialize(&valid_tx);
        let txid = valid_tx.compute_txid();

        // 1. Valid transaction passes
        let parsed = verify_transaction(&raw_valid, &txid).expect("valid tx must pass");
        assert_eq!(parsed.compute_txid(), txid);

        // 2. Wrong txid rejected
        let wrong_txid = Txid::from_byte_array([0x99; 32]);
        assert!(matches!(
            verify_transaction(&raw_valid, &wrong_txid),
            Err(SpvError::InvalidTransaction { .. })
        ));

        // 3. 64-byte base transaction rejected (CVE-2017-12842)
        let tx64 = make_64_byte_tx();
        let raw64 = serialize(&tx64);
        let tx64_id = tx64.compute_txid();
        assert!(matches!(
            verify_transaction(&raw64, &tx64_id),
            Err(SpvError::InvalidTransaction { .. })
        ));

        // 4. Duplicate input outpoint rejected (CVE-2018-17144)
        let mut dup_in = valid_tx.clone();
        dup_in.input.push(dup_in.input[0].clone());
        let raw_dup = serialize(&dup_in);
        let dup_id = dup_in.compute_txid();
        assert!(matches!(
            verify_transaction(&raw_dup, &dup_id),
            Err(SpvError::InvalidTransaction { .. })
        ));

        // 5. Output exceeding MAX_MONEY rejected
        let mut over_max = valid_tx;
        over_max.output[0].value = Amount::from_sat(crate::tx_invariants::MAX_MONEY + 1);
        let raw_over = serialize(&over_max);
        let over_id = over_max.compute_txid();
        assert!(matches!(
            verify_transaction(&raw_over, &over_id),
            Err(SpvError::InvalidTransaction { .. })
        ));
    }
}

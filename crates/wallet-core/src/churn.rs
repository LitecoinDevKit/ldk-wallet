//! One-coin MWEB self-spend job.
//!
//! Scoring and phase changes are pure. Broadcast and header fetches stay in
//! `app` / `mweb`. A hop counts only when the inclusion block's kernel and
//! output MMR sizes did not each grow by exactly one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::dto::{
    ChurnDepthRecord, ChurnHop, ChurnPhase, ChurnStatus, CoverHold, CHURN_MAX_TARGET,
};
use crate::error::WalletError;
use crate::mweb_frozen;

pub const CHURN_JOB_FILE: &str = "churn_job.json";
pub const CHURN_DEPTH_FILE: &str = "churn_depth.json";
/// Signed hops the broadcaster can send without the seed. Mode `0600`.
pub const CHURN_ARMED_FILE: &str = "churn_armed.json";

/// A hop may be broadcast for this long after it becomes the armed hop.
pub const ARMED_EXPIRY_SECS: u64 = 24 * 60 * 60;
/// Or this many blocks, whichever comes first. About a day of Litecoin blocks.
pub const ARMED_EXPIRY_BLOCKS: u32 = 576;

/// Other MWEB mempool transactions a hop waits for when the sheet leaves the count alone.
pub const COVER_MIN_DEFAULT: u32 = 2;
pub const COVER_MIN_MAX: u32 = 10;

/// Opt-in spread drawn after the first check that meets the count.
pub const SPREAD_MIN_SECS: u64 = 60;
pub const SPREAD_MAX_SECS: u64 = 180;

pub const EXPIRED_SPEND: &str = "This signed self-spend expired. Try again to prepare a new one.";
pub const FOREIGN_SPEND: &str = "This coin was spent by another transaction.";

/// Sizes from one MWEB header.
///
/// `output_mmr_size` is cumulative over the chain. `kernel_mmr_size` is not:
/// litecoind rebuilds the kernel MMR for every block, so the field holds the
/// number of kernels in that block alone. The name follows the wire field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrSizes {
    pub kernel_mmr_size: u64,
    pub output_mmr_size: u64,
}

/// Result of comparing a 1-in-1 hop's inclusion header with its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopScore {
    /// Parent or inclusion header was missing, or the pair cannot contain our hop.
    Unscored,
    /// One kernel in the block and one new output: the block was only this spend.
    Solo,
    /// At least one foreign kernel or output was in the block.
    Mixed {
        other_kernels: u64,
        other_outputs: u64,
    },
}

/// Score a known 1-in-1 (one kernel, one output of ours) from its inclusion
/// header and the parent. Kernels come from the inclusion header alone; outputs
/// are the growth of the output MMR since the parent.
pub fn score_1in1_hop(parent: Option<MmrSizes>, inclusion: Option<MmrSizes>) -> HopScore {
    let (Some(parent), Some(inclusion)) = (parent, inclusion) else {
        return HopScore::Unscored;
    };
    let kernels = inclusion.kernel_mmr_size;
    let Some(output_delta) = inclusion
        .output_mmr_size
        .checked_sub(parent.output_mmr_size)
    else {
        return HopScore::Unscored;
    };
    // Our hop adds one kernel and one output. A block with neither cannot
    // contain it (wrong height, or a header from before inclusion).
    if kernels == 0 || output_delta == 0 {
        return HopScore::Unscored;
    }
    if kernels == 1 && output_delta == 1 {
        HopScore::Solo
    } else {
        HopScore::Mixed {
            other_kernels: kernels.saturating_sub(1),
            other_outputs: output_delta.saturating_sub(1),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChurnJob {
    #[serde(default = "default_version")]
    pub version: u32,
    pub phase: ChurnPhase,
    pub current_output_id: String,
    pub origin_output_id: String,
    pub target_depth: u32,
    pub effective_depth: u32,
    #[serde(default)]
    pub from_pegin: bool,
    pub fee_sats: u64,
    #[serde(default)]
    pub pending_wtxid: Option<String>,
    #[serde(default)]
    pub created_output_id: Option<String>,
    #[serde(default)]
    pub last_other_kernels: Option<u64>,
    #[serde(default)]
    pub last_other_outputs: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Wallet tip when this hop was broadcast. The hop is in a later block.
    #[serde(default)]
    pub broadcast_height: Option<u32>,
    /// What the last scoring pass saw. Diagnostic only; never shown in the UI.
    #[serde(default)]
    pub last_check: Option<String>,
    /// MWEB header sizes read for this hop so far, by height. A pass that
    /// reads some headers and then loses its peer keeps them for the next one.
    #[serde(default)]
    pub header_cache: BTreeMap<u32, MmrSizes>,
    /// The armed hop must be signed again before it can be broadcast.
    #[serde(default)]
    pub needs_resign: bool,
    /// Why a signed hop is still on disk.
    #[serde(default)]
    pub cover_hold: Option<CoverHold>,
    /// Other MWEB mempool transactions a hop waits for. Chosen on the sheet.
    #[serde(default = "default_cover_min")]
    pub cover_min: u32,
    /// Wait a random 1–3 minutes after the count is first met.
    #[serde(default)]
    pub spread_send: bool,
    /// What the last successful mempool read counted as foreign MWEB transactions.
    #[serde(default)]
    pub last_cover_count: Option<u64>,
    /// When the mempool was last asked, whether or not the read worked.
    #[serde(default)]
    pub last_cover_check_unix: Option<u64>,
    /// Every transaction in the mempool at the last successful read.
    #[serde(default)]
    pub last_cover_total: Option<u64>,
    /// MWEB kernels across the foreign transactions at the last successful read.
    #[serde(default)]
    pub last_cover_kernels: Option<u64>,
    /// MWEB outputs across the foreign transactions at the last successful read.
    #[serde(default)]
    pub last_cover_outputs: Option<u64>,
    /// Why the last mempool read failed. Cleared by the next read that works.
    #[serde(default)]
    pub last_cover_error: Option<String>,
    /// A spread deadline is running on the armed record.
    #[serde(default)]
    pub spreading: bool,
}

fn default_cover_min() -> u32 {
    COVER_MIN_DEFAULT
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct ChurnDepthFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    coins: BTreeMap<String, StoredDepth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct StoredDepth {
    non_solo_blocks: u32,
    #[serde(default)]
    last_other_kernels: Option<u64>,
    #[serde(default)]
    last_other_outputs: Option<u64>,
    /// Counted blocks, oldest first.
    #[serde(default)]
    hops: Vec<ChurnHop>,
    #[serde(default)]
    from_pegin: bool,
}

impl StoredDepth {
    fn record(&self, output_id: &str) -> ChurnDepthRecord {
        ChurnDepthRecord {
            output_id: output_id.to_string(),
            non_solo_blocks: self.non_solo_blocks,
            last_other_kernels: self.last_other_kernels,
            last_other_outputs: self.last_other_outputs,
            hops: self.hops.clone(),
            from_pegin: self.from_pegin,
        }
    }
}

impl From<&ChurnDepthRecord> for StoredDepth {
    fn from(record: &ChurnDepthRecord) -> Self {
        Self {
            non_solo_blocks: record.non_solo_blocks,
            last_other_kernels: record.last_other_kernels,
            last_other_outputs: record.last_other_outputs,
            hops: record.hops.clone(),
            from_pegin: record.from_pegin,
        }
    }
}

pub fn job_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHURN_JOB_FILE)
}

pub fn depth_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHURN_DEPTH_FILE)
}

/// True when an in-progress self-spend is holding this output, so nothing else may unfreeze it.
pub fn held_by_active_job(data_dir: &Path, output_id: &str) -> Result<bool, WalletError> {
    let Some(job) = read_job(data_dir)? else {
        return Ok(false);
    };
    if !job.phase.is_active() {
        return Ok(false);
    }
    let id = mweb_frozen::normalize_output_id(output_id)?;
    let current = mweb_frozen::normalize_output_id(&job.current_output_id)?;
    Ok(id == current)
}

pub fn read_job(data_dir: &Path) -> Result<Option<ChurnJob>, WalletError> {
    let path = job_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_job(data_dir: &Path, job: &ChurnJob) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    let json = serde_json::to_string_pretty(job).map_err(|e| WalletError::Meta(e.to_string()))?;
    fs::write(job_path(data_dir), json)?;
    Ok(())
}

fn read_depth_file(data_dir: &Path) -> Result<ChurnDepthFile, WalletError> {
    let path = depth_path(data_dir);
    if !path.is_file() {
        return Ok(ChurnDepthFile {
            version: 1,
            coins: BTreeMap::new(),
        });
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

fn write_depth_file(data_dir: &Path, file: &ChurnDepthFile) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    if file.coins.is_empty() {
        match fs::remove_file(depth_path(data_dir)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e)),
        }
    } else {
        let json =
            serde_json::to_string_pretty(file).map_err(|e| WalletError::Meta(e.to_string()))?;
        fs::write(depth_path(data_dir), json)?;
        Ok(())
    }
}

pub fn depth_of(data_dir: &Path, output_id: &str) -> Result<Option<ChurnDepthRecord>, WalletError> {
    let id = mweb_frozen::normalize_output_id(output_id)?;
    Ok(read_depth_file(data_dir)?
        .coins
        .get(&id)
        .map(|stored| stored.record(&id)))
}

pub fn list_depth(data_dir: &Path) -> Result<Vec<ChurnDepthRecord>, WalletError> {
    let file = read_depth_file(data_dir)?;
    Ok(file
        .coins
        .iter()
        .map(|(id, stored)| stored.record(id))
        .collect())
}

/// Merge exported depth records. Incoming ids overwrite. Absent ids stay.
pub fn upsert_depth(data_dir: &Path, records: &[ChurnDepthRecord]) -> Result<usize, WalletError> {
    let mut file = read_depth_file(data_dir)?;
    let mut n = 0usize;
    for record in records {
        let Ok(id) = mweb_frozen::normalize_output_id(&record.output_id) else {
            continue;
        };
        file.coins.insert(id, StoredDepth::from(record));
        n += 1;
    }
    if n > 0 {
        write_depth_file(data_dir, &file)?;
    }
    Ok(n)
}

pub fn normalize_target(target_depth: u32) -> Result<u32, WalletError> {
    let target = if target_depth == 0 { 1 } else { target_depth };
    if !(1..=CHURN_MAX_TARGET).contains(&target) {
        return Err(WalletError::BuildTx(format!(
            "Choose between 1 and {CHURN_MAX_TARGET} blocks."
        )));
    }
    Ok(target)
}

/// `0` means the default. Otherwise 1 through `COVER_MIN_MAX`.
pub fn normalize_cover_min(cover_min: u32) -> Result<u32, WalletError> {
    let n = if cover_min == 0 {
        COVER_MIN_DEFAULT
    } else {
        cover_min
    };
    if !(1..=COVER_MIN_MAX).contains(&n) {
        return Err(WalletError::BuildTx(format!(
            "Choose between 1 and {COVER_MIN_MAX} other private transactions."
        )));
    }
    Ok(n)
}

/// Inputs the start command already resolved from the coin and the job file.
pub struct StartCheck {
    pub mature: bool,
    pub frozen: bool,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub job_active: bool,
    pub target_depth: u32,
}

pub fn check_start(check: &StartCheck) -> Result<u32, WalletError> {
    let target = normalize_target(check.target_depth)?;
    if check.job_active {
        return Err(WalletError::BuildTx(
            "A self-spend is already in progress.".into(),
        ));
    }
    if check.frozen {
        return Err(WalletError::BuildTx(
            "Unfreeze this coin before spending it to yourself.".into(),
        ));
    }
    if !check.mature {
        return Err(WalletError::BuildTx(
            "This coin is not spendable yet.".into(),
        ));
    }
    if check.amount_sats <= check.fee_sats.saturating_mul(u64::from(target)) {
        return Err(WalletError::BuildTx(
            "This coin is too small to pay the fee.".into(),
        ));
    }
    Ok(target)
}

pub fn new_job(
    output_id: &str,
    from_pegin: bool,
    target_depth: u32,
    fee_sats: u64,
    cover_min: u32,
    spread_send: bool,
) -> Result<ChurnJob, WalletError> {
    let id = mweb_frozen::normalize_output_id(output_id)?;
    Ok(ChurnJob {
        version: 1,
        phase: ChurnPhase::WaitingToBroadcast,
        current_output_id: id.clone(),
        origin_output_id: id,
        target_depth,
        effective_depth: 0,
        from_pegin,
        fee_sats,
        pending_wtxid: None,
        created_output_id: None,
        last_other_kernels: None,
        last_other_outputs: None,
        last_error: None,
        broadcast_height: None,
        last_check: None,
        header_cache: BTreeMap::new(),
        needs_resign: false,
        cover_hold: None,
        cover_min,
        spread_send,
        last_cover_count: None,
        last_cover_check_unix: None,
        last_cover_total: None,
        last_cover_kernels: None,
        last_cover_outputs: None,
        last_cover_error: None,
        spreading: false,
    })
}

/// Save what one mempool read saw, or why it failed, on the job.
pub fn note_cover_read(job: &mut ChurnJob, read: &crate::mweb::CoverRead) {
    job.last_cover_count = Some(read.foreign_txs);
    job.last_cover_check_unix = Some(read.checked_at_unix);
    job.last_cover_total = Some(read.total_txs);
    job.last_cover_kernels = Some(read.kernels);
    job.last_cover_outputs = Some(read.outputs);
    job.last_cover_error = None;
}

/// A failed read keeps the last good counts so the card does not go blank,
/// but the timestamp and the error move.
pub fn note_cover_error(job: &mut ChurnJob, now_unix: u64, error: &str) {
    job.last_cover_check_unix = Some(now_unix);
    job.last_cover_error = Some(error.to_string());
}

/// Forget every mempool observation. Used when a hop leaves the cover gate.
pub fn clear_cover_read(job: &mut ChurnJob) {
    job.last_cover_count = None;
    job.last_cover_check_unix = None;
    job.last_cover_total = None;
    job.last_cover_kernels = None;
    job.last_cover_outputs = None;
    job.last_cover_error = None;
}

/// About a day of Litecoin blocks. The walk never looks further back than this.
pub const SCORE_WINDOW_CAP: u32 = 576;

/// Blocks mined after broadcast before an output that is still not on chain is
/// treated as not included. One block is the first chance to land.
pub const INCLUSION_GRACE_BLOCKS: u32 = 6;

/// The hop is signed and the cover gate may look at the mempool.
/// A resign or a saved error keeps it held.
pub fn ready_to_broadcast(job: &ChurnJob) -> bool {
    job.phase == ChurnPhase::WaitingForCover && job.last_error.is_none() && !job.needs_resign
}

pub fn grace_elapsed(broadcast_height: u32, tip_height: u32) -> bool {
    tip_height.saturating_sub(broadcast_height) >= INCLUSION_GRACE_BLOCKS
}

/// Record a broadcast. The next hop must not be built until this one is scored.
/// `broadcast_height` is the wallet tip at send time; the hop lands strictly after it.
pub fn note_broadcast(
    job: &mut ChurnJob,
    wtxid: &str,
    new_output_id: &str,
    broadcast_height: u32,
) -> Result<(), WalletError> {
    if !matches!(
        job.phase,
        ChurnPhase::WaitingForCover | ChurnPhase::WaitingToBroadcast
    ) {
        return Err(WalletError::BuildTx(
            "This self-spend is not ready to broadcast.".into(),
        ));
    }
    let new_id = mweb_frozen::normalize_output_id(new_output_id)?;
    job.pending_wtxid = Some(wtxid.to_string());
    job.created_output_id = Some(new_id.clone());
    job.current_output_id = new_id;
    job.phase = ChurnPhase::WaitingConfirm;
    job.last_error = None;
    job.broadcast_height = Some(broadcast_height);
    job.last_check = None;
    job.header_cache.clear();
    job.cover_hold = None;
    job.needs_resign = false;
    clear_cover_read(job);
    job.spreading = false;
    Ok(())
}

/// Where a hop can sit: `(broadcast_height, dated_height]`, capped at [`SCORE_WINDOW_CAP`] blocks.
/// The range includes the parent of the first candidate so its MMR delta can be read.
pub fn header_span(
    broadcast_height: Option<u32>,
    dated_height: u32,
) -> Option<std::ops::RangeInclusive<u32>> {
    if dated_height == 0 {
        return None;
    }
    let oldest = dated_height.saturating_sub(SCORE_WINDOW_CAP - 1);
    let first = match broadcast_height {
        Some(broadcast) => {
            let after = broadcast.saturating_add(1);
            if after > dated_height {
                return None;
            }
            after.max(oldest)
        }
        None => oldest.max(1),
    };
    let parent = first.checked_sub(1)?;
    Some(parent..=dated_height)
}

/// A scored inclusion block, or a window that cannot be decided yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InclusionFind {
    Found { height: u32, score: HopScore },
    NotYet,
}

/// Find the block that contains a 1-in-1 hop.
///
/// `headers` runs from the parent of the first candidate through the dated height.
/// `None` sizes mean that header could not be read. A zero MMR delta is a block
/// that does not contain the hop, not a failed read.
///
/// With a leaf index, the inclusion block is the one whose output MMR crosses
/// that index. Without one, the hop is scored only when a single block in the
/// window grew. Anything else stays undecided so the job can wait.
pub fn find_inclusion(
    headers: &[(u32, Option<MmrSizes>)],
    leaf_index: Option<u64>,
) -> InclusionFind {
    if headers.len() < 2 {
        return InclusionFind::NotYet;
    }
    let mut grew = Vec::new();
    let mut unread = false;
    for pair in headers.windows(2) {
        let height = pair[1].0;
        let (Some(parent), Some(inclusion)) = (pair[0].1, pair[1].1) else {
            unread = true;
            continue;
        };
        let score = score_1in1_hop(Some(parent), Some(inclusion));
        if let Some(leaf) = leaf_index {
            if parent.output_mmr_size <= leaf && leaf < inclusion.output_mmr_size {
                return match score {
                    HopScore::Solo | HopScore::Mixed { .. } => {
                        InclusionFind::Found { height, score }
                    }
                    HopScore::Unscored => InclusionFind::NotYet,
                };
            }
        }
        if matches!(score, HopScore::Solo | HopScore::Mixed { .. }) {
            grew.push((height, score));
        }
    }
    if leaf_index.is_some() || unread || grew.len() != 1 {
        return InclusionFind::NotYet;
    }
    let (height, score) = grew[0];
    InclusionFind::Found { height, score }
}

/// Apply a found inclusion. [`InclusionFind::NotYet`] leaves the phase alone.
pub fn consider_inclusion(
    job: &mut ChurnJob,
    found: InclusionFind,
) -> Result<Option<(u32, HopScore)>, WalletError> {
    match found {
        InclusionFind::NotYet => Ok(None),
        InclusionFind::Found { height, score } => {
            apply_score(job, score)?;
            Ok(Some((height, score)))
        }
    }
}

/// Where a leaf sits relative to the blocks after broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafBlock {
    /// Lowest height whose output MMR exceeds the leaf.
    Found(u32),
    /// The tip's output MMR does not contain this leaf.
    NotInChain,
    /// A header the search needed could not be read.
    Unread,
}

/// Binary-search the block that created `leaf`.
///
/// Output MMR size is monotonic. `output_mmr_at` may be called for heights in
/// `broadcast_height..=end_height`. A missing read stays [`LeafBlock::Unread`]
/// so a later sync can try the same leaf again.
pub fn locate_leaf_block(
    broadcast_height: u32,
    end_height: u32,
    leaf: u64,
    mut output_mmr_at: impl FnMut(u32) -> Option<u64>,
) -> LeafBlock {
    let Some(first) = broadcast_height.checked_add(1) else {
        return LeafBlock::NotInChain;
    };
    if first > end_height {
        return LeafBlock::NotInChain;
    }
    let Some(parent_size) = output_mmr_at(broadcast_height) else {
        return LeafBlock::Unread;
    };
    // The hop's output did not exist at broadcast. A leaf already in that
    // header is not this spend.
    if parent_size > leaf {
        return LeafBlock::Unread;
    }
    let Some(end_size) = output_mmr_at(end_height) else {
        return LeafBlock::Unread;
    };
    if end_size <= leaf {
        return LeafBlock::NotInChain;
    }
    let mut lo = first;
    let mut hi = end_height;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let Some(size) = output_mmr_at(mid) else {
            return LeafBlock::Unread;
        };
        if size <= leaf {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let Some(parent_of) = lo.checked_sub(1) else {
        return LeafBlock::Unread;
    };
    let parent_of_size = if parent_of == broadcast_height {
        parent_size
    } else {
        let Some(size) = output_mmr_at(parent_of) else {
            return LeafBlock::Unread;
        };
        size
    };
    if parent_of_size <= leaf {
        LeafBlock::Found(lo)
    } else {
        LeafBlock::Unread
    }
}

/// Result of looking for the new output among leaves created after broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafHunt {
    Found(u64),
    Absent,
    Unread,
}

/// What to do with a waiting hop whose new coin has no leaf index yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndatedHop {
    UseLeaf(u64),
    NotIncluded,
    NotYet,
}

/// What the stored tip leafset alone says about an undated hop.
///
/// The spent input still being in the leafset means the spend is not in any
/// block up to that tip. Past the grace window that is a miss. An input that
/// has left the leafset, or no answer, needs the header and UTXO reads.
pub fn leafset_verdict(
    broadcast_height: u32,
    tip_height: u32,
    inputs_unspent: Option<bool>,
) -> Option<UndatedHop> {
    match inputs_unspent {
        Some(true) if grace_elapsed(broadcast_height, tip_height) => Some(UndatedHop::NotIncluded),
        Some(true) => Some(UndatedHop::NotYet),
        _ => None,
    }
}

/// Decide a hop that sync has not tagged with a leaf index.
///
/// A flat output MMR through the grace window means the spend cannot be in a
/// block yet. Once other outputs exist, only a finished scan that missed our
/// output — and a spent input that is still in the leafset — says the same.
/// An input that has already left the leafset means the spend landed, so a
/// missed scan stays waiting instead of putting that coin back.
pub fn undated_hop(
    broadcast_height: u32,
    tip_height: u32,
    parent_output_mmr: u64,
    tip_output_mmr: u64,
    hunt: LeafHunt,
    inputs_unspent: Option<bool>,
) -> UndatedHop {
    if tip_output_mmr <= parent_output_mmr {
        return if grace_elapsed(broadcast_height, tip_height) {
            UndatedHop::NotIncluded
        } else {
            UndatedHop::NotYet
        };
    }
    match hunt {
        LeafHunt::Found(leaf) => UndatedHop::UseLeaf(leaf),
        LeafHunt::Unread => UndatedHop::NotYet,
        LeafHunt::Absent => {
            if inputs_unspent == Some(true) && grace_elapsed(broadcast_height, tip_height) {
                UndatedHop::NotIncluded
            } else {
                UndatedHop::NotYet
            }
        }
    }
}

/// The broadcast never landed. Point the job at the coin that can be sent again.
/// A saved error keeps [`ready_to_broadcast`] false until the user retries.
pub fn note_not_included(job: &mut ChurnJob, restored_output_id: &str) -> Result<(), WalletError> {
    if !matches!(
        job.phase,
        ChurnPhase::WaitingConfirm | ChurnPhase::PausedUnscored
    ) {
        return Err(WalletError::BuildTx(
            "This self-spend is not waiting on a block.".into(),
        ));
    }
    let id = mweb_frozen::normalize_output_id(restored_output_id)?;
    job.current_output_id = id;
    job.pending_wtxid = None;
    job.created_output_id = None;
    job.broadcast_height = None;
    job.header_cache.clear();
    job.last_error = Some("This spend was not included in a block.".into());
    job.needs_resign = true;
    job.phase = ChurnPhase::WaitingToBroadcast;
    Ok(())
}

pub fn note_broadcast_error(job: &mut ChurnJob, error: String) {
    job.last_error = Some(error);
    job.phase = ChurnPhase::WaitingToBroadcast;
}

/// Move the depth record onto the new output without counting a block yet.
pub fn inherit_depth(
    data_dir: &Path,
    from_output_id: &str,
    to_output_id: &str,
    from_pegin: bool,
) -> Result<(), WalletError> {
    let from_id = mweb_frozen::normalize_output_id(from_output_id)?;
    let to_id = mweb_frozen::normalize_output_id(to_output_id)?;
    let mut file = read_depth_file(data_dir)?;
    let prev = file.coins.remove(&from_id).unwrap_or_default();
    file.coins.insert(
        to_id,
        StoredDepth {
            non_solo_blocks: prev.non_solo_blocks,
            last_other_kernels: None,
            last_other_outputs: None,
            hops: prev.hops,
            from_pegin: from_pegin || prev.from_pegin,
        },
    );
    write_depth_file(data_dir, &file)
}

/// Apply a header score. Only legal in `WaitingConfirm` or `PausedUnscored`.
pub fn apply_score(job: &mut ChurnJob, score: HopScore) -> Result<(), WalletError> {
    if !matches!(
        job.phase,
        ChurnPhase::WaitingConfirm | ChurnPhase::PausedUnscored
    ) {
        return Err(WalletError::BuildTx(
            "This self-spend is not waiting on a block.".into(),
        ));
    }
    match score {
        HopScore::Unscored => {
            job.phase = ChurnPhase::PausedUnscored;
        }
        HopScore::Solo => {
            job.last_other_kernels = None;
            job.last_other_outputs = None;
            job.phase = ChurnPhase::PausedSolo;
        }
        HopScore::Mixed {
            other_kernels,
            other_outputs,
        } => {
            job.effective_depth = job.effective_depth.saturating_add(1);
            job.last_other_kernels = Some(other_kernels);
            job.last_other_outputs = Some(other_outputs);
            job.phase = if job.effective_depth >= job.target_depth {
                ChurnPhase::Done
            } else {
                ChurnPhase::WaitingForCover
            };
        }
    }
    Ok(())
}

/// Fold a score into the depth map for the coin the hop created.
pub fn commit_score(
    data_dir: &Path,
    output_id: &str,
    from_pegin: bool,
    score: HopScore,
) -> Result<(), WalletError> {
    if matches!(score, HopScore::Unscored) {
        return Ok(());
    }
    let id = mweb_frozen::normalize_output_id(output_id)?;
    let mut file = read_depth_file(data_dir)?;
    let mut entry = file.coins.remove(&id).unwrap_or(StoredDepth {
        from_pegin,
        ..StoredDepth::default()
    });
    entry.from_pegin = entry.from_pegin || from_pegin;
    match score {
        HopScore::Unscored | HopScore::Solo => {}
        HopScore::Mixed {
            other_kernels,
            other_outputs,
        } => {
            entry.non_solo_blocks = entry.non_solo_blocks.saturating_add(1);
            entry.hops.push(ChurnHop {
                other_kernels,
                other_outputs,
            });
            entry.last_other_kernels = Some(other_kernels);
            entry.last_other_outputs = Some(other_outputs);
        }
    }
    file.coins.insert(id, entry);
    write_depth_file(data_dir, &file)
}

pub fn request_retry(job: &mut ChurnJob) -> Result<(), WalletError> {
    match job.phase {
        ChurnPhase::PausedUnscored => {
            job.phase = ChurnPhase::WaitingConfirm;
            job.last_error = None;
            Ok(())
        }
        ChurnPhase::PausedSolo => {
            // The prepared chain is used up. The next hop is a new signature.
            job.needs_resign = true;
            job.phase = ChurnPhase::WaitingForCover;
            job.last_error = None;
            job.cover_hold = None;
            Ok(())
        }
        ChurnPhase::WaitingToBroadcast | ChurnPhase::WaitingForCover => {
            job.last_error = None;
            job.cover_hold = None;
            job.phase = ChurnPhase::WaitingForCover;
            Ok(())
        }
        _ => Err(WalletError::BuildTx(
            "There is no paused self-spend to try again.".into(),
        )),
    }
}

pub fn request_cancel(job: &mut ChurnJob) -> Result<(), WalletError> {
    if !job.phase.is_active() {
        return Err(WalletError::BuildTx(
            "There is no self-spend to cancel.".into(),
        ));
    }
    // Once broadcast, the hop is on the network. Cancel would only drop local
    // tracking; it cannot unbroadcast. Wait for inclusion, solo pause, or a
    // not-included recovery path instead.
    if job.phase == ChurnPhase::WaitingConfirm {
        return Err(WalletError::BuildTx(
            "This self-spend is already on the network. Wait for the next block.".into(),
        ));
    }
    job.phase = ChurnPhase::Cancelled;
    Ok(())
}

pub fn status_view(job: &ChurnJob) -> ChurnStatus {
    ChurnStatus {
        phase: job.phase,
        output_id: job.current_output_id.clone(),
        target_depth: job.target_depth,
        effective_depth: job.effective_depth,
        fee_sats: job.fee_sats,
        from_pegin: job.from_pegin,
        last_other_kernels: job.last_other_kernels,
        last_other_outputs: job.last_other_outputs,
        last_error: job.last_error.clone(),
        cover_hold: job.cover_hold,
        cover_min: job.cover_min,
        spread_send: job.spread_send,
        last_cover_count: job.last_cover_count,
        last_cover_check_unix: job.last_cover_check_unix,
        last_cover_total: job.last_cover_total,
        last_cover_kernels: job.last_cover_kernels,
        last_cover_outputs: job.last_cover_outputs,
        last_cover_error: job.last_cover_error.clone(),
        spreading: job.spreading,
    }
}

/// Depth annotations for the Coins list. A missing file means non-peg-in coins are unknown.
pub fn annotations(
    data_dir: &Path,
) -> Result<(BTreeMap<String, ChurnDepthRecord>, Option<ChurnJob>), WalletError> {
    let mut map = BTreeMap::new();
    for record in list_depth(data_dir)? {
        map.insert(record.output_id.clone(), record);
    }
    Ok((map, read_job(data_dir)?))
}

/// What to do after a hop is scored, given whether another signed hop is on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScoreFollow {
    /// Leave the phase `apply_score` chose.
    Stay,
    /// A quiet or mixed block still has a prepared hop. Arm it.
    ArmNext,
    /// The prepared chain is used up before the target count.
    FinishShort,
}

/// A mixed hop below the target asks for another broadcast. A solo hop pauses
/// unless a signed hop is already waiting. Neither path signs a replacement.
pub fn follow_score(phase: ChurnPhase, hops_remaining: bool) -> ScoreFollow {
    match (phase, hops_remaining) {
        (ChurnPhase::WaitingForCover, true) | (ChurnPhase::PausedSolo, true) => {
            ScoreFollow::ArmNext
        }
        (ChurnPhase::WaitingForCover, false) => ScoreFollow::FinishShort,
        _ => ScoreFollow::Stay,
    }
}

/// Clear the in-flight hop so the next signed spend can be scored on its own.
pub fn mark_waiting_for_cover(job: &mut ChurnJob) {
    job.phase = ChurnPhase::WaitingForCover;
    job.pending_wtxid = None;
    job.broadcast_height = None;
    job.last_check = None;
    job.last_error = None;
    job.cover_hold = None;
    job.needs_resign = false;
    job.header_cache.clear();
}

pub fn finish_chain(job: &mut ChurnJob) {
    job.phase = ChurnPhase::Done;
    job.cover_hold = None;
    job.needs_resign = false;
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_spread() -> u64 {
    rand::thread_rng().gen_range(SPREAD_MIN_SECS..=SPREAD_MAX_SECS)
}

pub fn armed_expired(armed_at: u64, armed_height: u32, now: u64, tip: Option<u32>) -> bool {
    if now.saturating_sub(armed_at) >= ARMED_EXPIRY_SECS {
        return true;
    }
    match tip {
        Some(tip) => tip.saturating_sub(armed_height) >= ARMED_EXPIRY_BLOCKS,
        None => false,
    }
}

/// One signed self-spend. Raw transaction bytes live only in this file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArmedHop {
    pub raw_hex: String,
    pub txid: String,
    pub wtxid: String,
    pub spent_output_id: String,
    pub created_output_id: String,
    pub receive_index: u32,
    pub fee_sats: u64,
    #[serde(default)]
    pub local_applied: bool,
    #[serde(default)]
    pub broadcast: bool,
    /// Spend secrets for the created output, inserted into the coin db at broadcast.
    #[serde(default)]
    pub created_coin: Option<serde_json::Value>,
}

/// The chain prepared while the wallet was unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArmedRecord {
    #[serde(default = "default_version")]
    pub version: u32,
    pub hops: Vec<ArmedHop>,
    pub armed_index: u32,
    pub armed_at_unix: u64,
    pub armed_height: u32,
    pub cover_min: u32,
    /// Opt-in spread deadline, drawn after the first check that met the count.
    #[serde(default)]
    pub send_after: Option<u64>,
    #[serde(default)]
    pub own_ids: BTreeSet<String>,
    /// Raw transactions were deleted. Unlock still needs the wtxid to undo a local mark.
    #[serde(default)]
    pub expired: bool,
}

impl ArmedRecord {
    pub fn current(&self) -> Option<&ArmedHop> {
        self.hops.get(self.armed_index as usize)
    }

    pub fn current_mut(&mut self) -> Option<&mut ArmedHop> {
        self.hops.get_mut(self.armed_index as usize)
    }

    /// Another signed hop exists after the one in flight.
    pub fn hops_remaining(&self) -> bool {
        let next = self.armed_index.saturating_add(1) as usize;
        self.hops
            .get(next)
            .is_some_and(|hop| !hop.broadcast && !hop.raw_hex.is_empty())
    }
}

/// Drop the raw transaction and the created-coin secrets from this hop onward.
pub fn wipe_raw_tail(record: &mut ArmedRecord) {
    let start = record.armed_index as usize;
    for hop in record.hops.iter_mut().skip(start) {
        if hop.broadcast {
            continue;
        }
        hop.raw_hex.clear();
        hop.created_coin = None;
    }
    record.expired = true;
    record.send_after = None;
}

pub fn arm_next(record: &mut ArmedRecord, now: u64, height: u32) -> bool {
    if !record.hops_remaining() {
        return false;
    }
    record.armed_index = record.armed_index.saturating_add(1);
    record.armed_at_unix = now;
    record.armed_height = height;
    record.send_after = None;
    record.expired = false;
    true
}

/// Ids this wallet must not count as cover: unconfirmed history plus every hop.
pub fn snapshot_own_ids(
    unconfirmed: impl IntoIterator<Item = String>,
    hops: &[ArmedHop],
) -> BTreeSet<String> {
    let mut ids: BTreeSet<String> = unconfirmed.into_iter().collect();
    for hop in hops {
        if !hop.txid.is_empty() {
            ids.insert(hop.txid.clone());
        }
        if !hop.wtxid.is_empty() {
            ids.insert(hop.wtxid.clone());
        }
    }
    ids
}

pub fn is_foreign_id(txid: &str, wtxid: &str, own: &BTreeSet<String>) -> bool {
    !own.contains(txid) && !own.contains(wtxid)
}

/// One mempool check against the user's count.
///
/// `Below` and `Spreading` are separate so the caller only drops a spread
/// deadline when the count has actually fallen under the minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverStep {
    /// Fewer other transactions than the count. Any spread deadline is dropped.
    Below,
    /// The count was met for the first time with the spread on.
    StartSpread {
        send_after: u64,
    },
    /// The count still holds and the spread deadline has not passed.
    Spreading,
    Send,
}

/// `spread_secs` is chosen by the caller so a test can pin it.
pub fn cover_step(
    now: u64,
    count: u64,
    minimum: u32,
    spread: bool,
    send_after: Option<u64>,
    spread_secs: u64,
) -> CoverStep {
    if count < u64::from(minimum) {
        return CoverStep::Below;
    }
    if !spread {
        return CoverStep::Send;
    }
    match send_after {
        None => CoverStep::StartSpread {
            send_after: now.saturating_add(spread_secs),
        },
        Some(deadline) if now < deadline => CoverStep::Spreading,
        Some(_) => CoverStep::Send,
    }
}

pub fn armed_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CHURN_ARMED_FILE)
}

pub fn read_armed(data_dir: &Path) -> Result<Option<ArmedRecord>, WalletError> {
    let path = armed_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read_to_string(&path).map_err(WalletError::Io)?;
    serde_json::from_str(&bytes).map_err(|e| WalletError::Meta(e.to_string()))
}

pub fn write_armed(data_dir: &Path, record: &ArmedRecord) -> Result<(), WalletError> {
    fs::create_dir_all(data_dir)?;
    let json =
        serde_json::to_string_pretty(record).map_err(|e| WalletError::Meta(e.to_string()))?;
    let path = armed_path(data_dir);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(WalletError::Io)?;
    file.write_all(json.as_bytes()).map_err(WalletError::Io)?;
    let mut perms = file.metadata().map_err(WalletError::Io)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o600);
    fs::set_permissions(&path, perms).map_err(WalletError::Io)?;
    Ok(())
}

pub fn remove_armed(data_dir: &Path) -> Result<(), WalletError> {
    match fs::remove_file(armed_path(data_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(WalletError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn sizes(kernel: u64, output: u64) -> MmrSizes {
        MmrSizes {
            kernel_mmr_size: kernel,
            output_mmr_size: output,
        }
    }

    fn job_waiting_confirm() -> ChurnJob {
        let mut job = new_job(&"ab".repeat(32), true, 2, 50_000, COVER_MIN_DEFAULT, false).unwrap();
        note_broadcast(&mut job, "wtxid", &"cd".repeat(32), 100).unwrap();
        job
    }

    #[test]
    fn solo_when_one_kernel_and_one_new_output() {
        // The parent's kernel count is that block's own and does not matter.
        assert_eq!(
            score_1in1_hop(Some(sizes(5, 20)), Some(sizes(1, 21))),
            HopScore::Solo
        );
    }

    #[test]
    fn foreign_kernel_or_output_counts() {
        // Mainnet 3197964 -> 3197965: five kernels in the parent block, two in
        // ours, one new output. The parent count must not be subtracted.
        assert_eq!(
            score_1in1_hop(Some(sizes(5, 379_093)), Some(sizes(2, 379_094))),
            HopScore::Mixed {
                other_kernels: 1,
                other_outputs: 0
            }
        );
        assert_eq!(
            score_1in1_hop(Some(sizes(0, 20)), Some(sizes(3, 24))),
            HopScore::Mixed {
                other_kernels: 2,
                other_outputs: 3
            }
        );
    }

    #[test]
    fn missing_header_is_unscored() {
        assert_eq!(score_1in1_hop(None, Some(sizes(1, 21))), HopScore::Unscored);
        assert_eq!(score_1in1_hop(Some(sizes(1, 20)), None), HopScore::Unscored);
        // No kernels, or no new output: this block cannot hold the hop.
        assert_eq!(
            score_1in1_hop(Some(sizes(1, 20)), Some(sizes(0, 21))),
            HopScore::Unscored
        );
        assert_eq!(
            score_1in1_hop(Some(sizes(1, 20)), Some(sizes(1, 20))),
            HopScore::Unscored
        );
    }

    #[test]
    fn missing_header_does_not_increment_depth() {
        let mut job = job_waiting_confirm();
        apply_score(&mut job, HopScore::Unscored).unwrap();
        assert_eq!(job.phase, ChurnPhase::PausedUnscored);
        assert_eq!(job.effective_depth, 0);
        assert!(!ready_to_broadcast(&job));
    }

    #[test]
    fn solo_does_not_broadcast_the_next_hop() {
        let mut job = job_waiting_confirm();
        assert!(!ready_to_broadcast(&job));
        apply_score(&mut job, HopScore::Solo).unwrap();
        assert_eq!(job.phase, ChurnPhase::PausedSolo);
        assert_eq!(job.effective_depth, 0);
        assert!(!ready_to_broadcast(&job));
    }

    #[test]
    fn mixed_below_target_may_broadcast_only_after_the_score() {
        let mut job = job_waiting_confirm();
        apply_score(
            &mut job,
            HopScore::Mixed {
                other_kernels: 1,
                other_outputs: 2,
            },
        )
        .unwrap();
        assert_eq!(job.phase, ChurnPhase::WaitingForCover);
        assert_eq!(job.effective_depth, 1);
        assert!(ready_to_broadcast(&job));
        assert_eq!(job.last_other_kernels, Some(1));
        assert_eq!(job.last_other_outputs, Some(2));
    }

    #[test]
    fn mixed_at_target_finishes() {
        let mut job =
            new_job(&"ab".repeat(32), false, 1, 50_000, COVER_MIN_DEFAULT, false).unwrap();
        note_broadcast(&mut job, "wtxid", &"cd".repeat(32), 100).unwrap();
        apply_score(
            &mut job,
            HopScore::Mixed {
                other_kernels: 4,
                other_outputs: 4,
            },
        )
        .unwrap();
        assert_eq!(job.phase, ChurnPhase::Done);
        assert!(!ready_to_broadcast(&job));
    }

    #[test]
    fn second_hop_is_refused_while_unconfirmed() {
        let mut job = job_waiting_confirm();
        assert!(!ready_to_broadcast(&job));
        let err = note_broadcast(&mut job, "again", &"ef".repeat(32), 100).unwrap_err();
        assert!(err.to_string().contains("not ready"));
        assert_eq!(job.phase, ChurnPhase::WaitingConfirm);
    }

    #[test]
    fn start_rejects_frozen_immature_and_a_second_job() {
        let base = StartCheck {
            mature: true,
            frozen: false,
            amount_sats: 100_000,
            fee_sats: 50_000,
            job_active: false,
            target_depth: 1,
        };
        assert!(check_start(&base).is_ok());
        assert!(check_start(&StartCheck {
            frozen: true,
            ..base
        })
        .unwrap_err()
        .to_string()
        .contains("Unfreeze"));
        assert!(check_start(&StartCheck {
            mature: false,
            ..base
        })
        .unwrap_err()
        .to_string()
        .contains("not spendable"));
        assert!(check_start(&StartCheck {
            job_active: true,
            ..base
        })
        .unwrap_err()
        .to_string()
        .contains("already in progress"));
        assert!(check_start(&StartCheck {
            target_depth: 11,
            ..base
        })
        .is_err());
        assert_eq!(
            check_start(&StartCheck {
                target_depth: 0,
                ..base
            })
            .unwrap(),
            1
        );
    }

    #[test]
    fn active_job_holds_the_coin_until_cancel() {
        let dir = tempdir().unwrap();
        let id = "ab".repeat(32);
        let mut job = new_job(&id, false, 1, 50_000, COVER_MIN_DEFAULT, false).unwrap();
        write_job(dir.path(), &job).unwrap();
        assert!(held_by_active_job(dir.path(), &id).unwrap());
        request_cancel(&mut job).unwrap();
        write_job(dir.path(), &job).unwrap();
        assert!(!held_by_active_job(dir.path(), &id).unwrap());
    }

    #[test]
    fn cancel_rejected_while_waiting_for_confirm() {
        let mut job = job_waiting_confirm();
        let err = request_cancel(&mut job).unwrap_err().to_string();
        assert!(err.contains("already on the network"));
        assert_eq!(job.phase, ChurnPhase::WaitingConfirm);
    }

    #[test]
    fn cancel_unfreezes_the_current_coin() {
        let dir = tempdir().unwrap();
        let id = "ab".repeat(32);
        let mut job = new_job(&id, true, 1, 50_000, COVER_MIN_DEFAULT, false).unwrap();
        mweb_frozen::set_locked(dir.path(), &id, true).unwrap();
        write_job(dir.path(), &job).unwrap();
        request_cancel(&mut job).unwrap();
        write_job(dir.path(), &job).unwrap();
        mweb_frozen::set_locked(dir.path(), &job.current_output_id, false).unwrap();
        assert!(!mweb_frozen::contains(dir.path(), &id));
        assert_eq!(
            read_job(dir.path()).unwrap().unwrap().phase,
            ChurnPhase::Cancelled
        );
    }

    #[test]
    fn depth_moves_to_the_new_output_and_counts_only_a_mix() {
        let dir = tempdir().unwrap();
        let from = "ab".repeat(32);
        let to = "cd".repeat(32);
        inherit_depth(dir.path(), &from, &to, true).unwrap();
        commit_score(dir.path(), &to, true, HopScore::Solo).unwrap();
        let solo = depth_of(dir.path(), &to).unwrap().unwrap();
        assert_eq!(solo.non_solo_blocks, 0);
        assert!(solo.from_pegin);
        assert!(solo.last_other_kernels.is_none());
        commit_score(
            dir.path(),
            &to,
            true,
            HopScore::Mixed {
                other_kernels: 2,
                other_outputs: 3,
            },
        )
        .unwrap();
        let mixed = depth_of(dir.path(), &to).unwrap().unwrap();
        assert_eq!(mixed.non_solo_blocks, 1);
        assert_eq!(mixed.last_other_kernels, Some(2));
        assert_eq!(mixed.last_other_outputs, Some(3));
        assert_eq!(
            mixed.hops,
            vec![ChurnHop {
                other_kernels: 2,
                other_outputs: 3,
            }]
        );
        assert!(depth_of(dir.path(), &from).unwrap().is_none());

        let next = "ef".repeat(32);
        inherit_depth(dir.path(), &to, &next, true).unwrap();
        let moved = depth_of(dir.path(), &next).unwrap().unwrap();
        assert_eq!(moved.non_solo_blocks, 1);
        assert!(moved.last_other_kernels.is_none());
        assert_eq!(moved.hops, mixed.hops);
        commit_score(
            dir.path(),
            &next,
            true,
            HopScore::Mixed {
                other_kernels: 5,
                other_outputs: 6,
            },
        )
        .unwrap();
        commit_score(dir.path(), &next, true, HopScore::Solo).unwrap();
        let both = depth_of(dir.path(), &next).unwrap().unwrap();
        assert_eq!(both.non_solo_blocks, 2);
        assert_eq!(both.last_other_kernels, Some(5));
        assert_eq!(both.last_other_outputs, Some(6));
        assert_eq!(
            both.hops,
            vec![
                ChurnHop {
                    other_kernels: 2,
                    other_outputs: 3,
                },
                ChurnHop {
                    other_kernels: 5,
                    other_outputs: 6,
                },
            ]
        );
        assert!(depth_of(dir.path(), &to).unwrap().is_none());
    }

    #[test]
    fn empty_tip_scores_the_earlier_hop() {
        let headers = [
            (10, Some(sizes(3, 20))),
            (11, Some(sizes(1, 21))),
            (12, Some(sizes(0, 21))),
        ];
        let mut job = job_waiting_confirm();
        let applied = consider_inclusion(&mut job, find_inclusion(&headers, None)).unwrap();
        assert_eq!(applied.map(|(height, _)| height), Some(11));
        assert_eq!(job.phase, ChurnPhase::PausedSolo);
    }

    #[test]
    fn missing_headers_leave_the_job_waiting() {
        let headers = [(10, None), (11, None)];
        let mut job = job_waiting_confirm();
        let applied = consider_inclusion(&mut job, find_inclusion(&headers, None)).unwrap();
        assert!(applied.is_none());
        assert_eq!(job.phase, ChurnPhase::WaitingConfirm);
    }

    #[test]
    fn two_growing_blocks_without_a_leaf_stay_undecided() {
        let headers = [
            (10, Some(sizes(0, 20))),
            (11, Some(sizes(1, 21))),
            (12, Some(sizes(2, 23))),
        ];
        assert_eq!(find_inclusion(&headers, None), InclusionFind::NotYet);
    }

    #[test]
    fn leaf_index_picks_the_block_that_crossed_it() {
        let headers = [
            (10, Some(sizes(0, 20))),
            (11, Some(sizes(1, 21))),
            (12, Some(sizes(2, 23))),
        ];
        assert_eq!(
            find_inclusion(&headers, Some(21)),
            InclusionFind::Found {
                height: 12,
                score: HopScore::Mixed {
                    other_kernels: 1,
                    other_outputs: 1,
                },
            }
        );
    }

    #[test]
    fn old_job_without_broadcast_height_still_loads() {
        let json = r#"{
            "version": 1,
            "phase": "waiting-confirm",
            "current_output_id": "aa",
            "origin_output_id": "aa",
            "target_depth": 1,
            "effective_depth": 0,
            "fee_sats": 1
        }"#;
        let job: ChurnJob = serde_json::from_str(json).unwrap();
        assert_eq!(job.broadcast_height, None);
        assert_eq!(job.phase, ChurnPhase::WaitingConfirm);
    }

    fn chain(heights: &[(u32, u64)]) -> impl Fn(u32) -> Option<u64> + '_ {
        move |height| {
            heights
                .iter()
                .find(|(h, _)| *h == height)
                .map(|(_, size)| *size)
        }
    }

    #[test]
    fn locate_picks_the_later_block_when_two_blocks_grew() {
        let sizes = chain(&[(10, 20), (11, 21), (12, 23)]);
        assert_eq!(locate_leaf_block(10, 12, 21, sizes), LeafBlock::Found(12));
    }

    #[test]
    fn locate_stops_when_the_tip_has_not_reached_the_leaf() {
        let sizes = chain(&[(10, 20), (14, 20)]);
        assert_eq!(locate_leaf_block(10, 14, 20, sizes), LeafBlock::NotInChain);
    }

    #[test]
    fn locate_stays_unread_when_a_probed_header_is_missing() {
        let sizes = chain(&[(10, 20), (12, 23)]);
        assert_eq!(locate_leaf_block(10, 12, 21, sizes), LeafBlock::Unread);
    }

    #[test]
    fn flat_output_mmr_is_not_included_only_after_the_grace_window() {
        assert_eq!(
            undated_hop(100, 105, 20, 20, LeafHunt::Absent, None),
            UndatedHop::NotYet
        );
        assert_eq!(
            undated_hop(100, 106, 20, 20, LeafHunt::Absent, None),
            UndatedHop::NotIncluded
        );
    }

    #[test]
    fn a_missed_output_is_not_included_when_the_input_is_still_unspent() {
        assert_eq!(
            undated_hop(100, 110, 20, 25, LeafHunt::Absent, Some(true)),
            UndatedHop::NotIncluded
        );
        assert_eq!(
            undated_hop(100, 110, 20, 25, LeafHunt::Absent, Some(false)),
            UndatedHop::NotYet
        );
        assert_eq!(
            undated_hop(100, 110, 20, 25, LeafHunt::Absent, None),
            UndatedHop::NotYet
        );
        assert_eq!(
            undated_hop(100, 110, 20, 25, LeafHunt::Found(22), None),
            UndatedHop::UseLeaf(22)
        );
    }

    #[test]
    fn leafset_alone_decides_only_when_the_input_is_still_unspent() {
        assert_eq!(
            leafset_verdict(100, 110, Some(true)),
            Some(UndatedHop::NotIncluded)
        );
        assert_eq!(
            leafset_verdict(100, 103, Some(true)),
            Some(UndatedHop::NotYet)
        );
        assert_eq!(leafset_verdict(100, 110, Some(false)), None);
        assert_eq!(leafset_verdict(100, 110, None), None);
    }

    #[test]
    fn header_cache_survives_a_reload_and_resets_on_a_new_hop() {
        let mut job = job_waiting_confirm();
        job.header_cache.insert(101, sizes(5, 9));
        job.last_check = Some("tip=105".into());
        let json = serde_json::to_string(&job).unwrap();
        let loaded: ChurnJob = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.header_cache.get(&101), Some(&sizes(5, 9)));
        assert_eq!(loaded.last_check.as_deref(), Some("tip=105"));
        let mut job = loaded;
        note_not_included(&mut job, &"ab".repeat(32)).unwrap();
        assert!(job.header_cache.is_empty());
        request_retry(&mut job).unwrap();
        job.header_cache.insert(1, sizes(1, 1));
        note_broadcast(&mut job, "w", &"cd".repeat(32), 200).unwrap();
        assert!(job.header_cache.is_empty());
        assert!(job.last_check.is_none());
    }

    #[test]
    fn a_spend_that_missed_its_block_waits_for_the_user_to_retry() {
        let mut job = job_waiting_confirm();
        let restored = "ab".repeat(32);
        note_not_included(&mut job, &restored).unwrap();
        assert_eq!(job.phase, ChurnPhase::WaitingToBroadcast);
        assert_eq!(job.current_output_id, restored);
        assert!(job.broadcast_height.is_none());
        assert!(job.pending_wtxid.is_none());
        assert!(!ready_to_broadcast(&job));
        request_retry(&mut job).unwrap();
        assert!(job.needs_resign);
        assert!(!ready_to_broadcast(&job));
    }

    #[test]
    fn cover_sends_on_one_look() {
        assert_eq!(cover_step(1_000, 1, 2, false, None, 90), CoverStep::Below);
        assert_eq!(cover_step(1_000, 2, 2, false, None, 90), CoverStep::Send);
        assert_eq!(cover_step(1_000, 7, 2, false, None, 90), CoverStep::Send);
    }

    #[test]
    fn spread_waits_once_then_sends() {
        assert_eq!(
            cover_step(1_000, 3, 2, true, None, 90),
            CoverStep::StartSpread { send_after: 1_090 }
        );
        assert_eq!(
            cover_step(1_060, 3, 2, true, Some(1_090), 90),
            CoverStep::Spreading
        );
        assert_eq!(
            cover_step(1_090, 3, 2, true, Some(1_090), 90),
            CoverStep::Send
        );
        assert_eq!(
            cover_step(1_060, 1, 2, true, Some(1_090), 90),
            CoverStep::Below
        );
    }

    #[test]
    fn mempool_read_is_saved_and_cleared_on_broadcast() {
        let mut job = new_job(&"ab".repeat(32), false, 1, 50_000, 2, false).unwrap();
        job.phase = ChurnPhase::WaitingForCover;
        assert!(job.last_cover_check_unix.is_none());

        note_cover_error(&mut job, 100, "http status 401");
        assert_eq!(job.last_cover_check_unix, Some(100));
        assert_eq!(job.last_cover_error.as_deref(), Some("http status 401"));
        assert!(job.last_cover_count.is_none());

        note_cover_read(
            &mut job,
            &crate::mweb::CoverRead {
                total_txs: 12,
                mweb_txs: 3,
                foreign_txs: 2,
                kernels: 2,
                outputs: 4,
                unreadable_txs: 0,
                checked_at_unix: 160,
            },
        );
        assert_eq!(job.last_cover_count, Some(2));
        assert_eq!(job.last_cover_check_unix, Some(160));
        assert_eq!(job.last_cover_total, Some(12));
        assert_eq!(job.last_cover_kernels, Some(2));
        assert_eq!(job.last_cover_outputs, Some(4));
        assert!(job.last_cover_error.is_none());

        let view = status_view(&job);
        assert_eq!(view.last_cover_count, Some(2));
        assert_eq!(view.last_cover_check_unix, Some(160));
        assert_eq!(view.last_cover_total, Some(12));
        assert_eq!(view.last_cover_kernels, Some(2));
        assert_eq!(view.last_cover_outputs, Some(4));
        assert!(view.last_cover_error.is_none());

        note_broadcast(&mut job, "wtxid", &"cd".repeat(32), 200).unwrap();
        assert!(job.last_cover_count.is_none());
        assert!(job.last_cover_check_unix.is_none());
        assert!(job.last_cover_total.is_none());
        assert!(job.last_cover_kernels.is_none());
        assert!(job.last_cover_outputs.is_none());
        assert!(job.last_cover_error.is_none());
    }

    #[test]
    fn older_job_files_read_without_the_mempool_fields() {
        let json = serde_json::json!({
            "phase": "waiting-for-cover",
            "current_output_id": "ab".repeat(32),
            "origin_output_id": "ab".repeat(32),
            "target_depth": 1,
            "effective_depth": 0,
            "fee_sats": 50_000,
            "last_cover_count": 0
        });
        let job: ChurnJob = serde_json::from_value(json).unwrap();
        assert_eq!(job.last_cover_count, Some(0));
        assert!(job.last_cover_check_unix.is_none());
        assert!(job.last_cover_error.is_none());
    }

    #[test]
    fn cover_min_is_one_to_ten() {
        assert_eq!(normalize_cover_min(0).unwrap(), COVER_MIN_DEFAULT);
        assert_eq!(normalize_cover_min(1).unwrap(), 1);
        assert_eq!(normalize_cover_min(10).unwrap(), 10);
        assert!(normalize_cover_min(11).is_err());
    }

    #[test]
    fn own_ids_are_not_foreign_cover() {
        let mut own = BTreeSet::new();
        own.insert("txid".into());
        own.insert("wtxid".into());
        assert!(!is_foreign_id("txid", "other", &own));
        assert!(!is_foreign_id("other", "wtxid", &own));
        assert!(is_foreign_id("someone", "else", &own));
    }

    #[test]
    fn expiry_is_a_day_or_576_blocks() {
        assert!(!armed_expired(0, 100, ARMED_EXPIRY_SECS - 1, Some(100)));
        assert!(armed_expired(0, 100, ARMED_EXPIRY_SECS, None));
        assert!(armed_expired(0, 100, 10, Some(100 + ARMED_EXPIRY_BLOCKS)));
        assert!(!armed_expired(
            0,
            100,
            10,
            Some(100 + ARMED_EXPIRY_BLOCKS - 1)
        ));
    }

    #[test]
    fn solo_with_another_signed_hop_arms_it() {
        assert_eq!(
            follow_score(ChurnPhase::PausedSolo, true),
            ScoreFollow::ArmNext
        );
        assert_eq!(
            follow_score(ChurnPhase::PausedSolo, false),
            ScoreFollow::Stay
        );
        assert_eq!(
            follow_score(ChurnPhase::WaitingForCover, true),
            ScoreFollow::ArmNext
        );
        assert_eq!(
            follow_score(ChurnPhase::WaitingForCover, false),
            ScoreFollow::FinishShort
        );
        assert_eq!(follow_score(ChurnPhase::Done, true), ScoreFollow::Stay);
    }

    #[test]
    fn armed_file_is_owner_readable_only() {
        let dir = tempdir().unwrap();
        let hop = ArmedHop {
            raw_hex: "aa".into(),
            txid: "txid".into(),
            wtxid: "wtxid".into(),
            spent_output_id: "ab".repeat(32),
            created_output_id: "cd".repeat(32),
            receive_index: 4,
            fee_sats: 50_000,
            local_applied: false,
            broadcast: false,
            created_coin: None,
        };
        let mut record = ArmedRecord {
            version: 1,
            hops: vec![hop],
            armed_index: 0,
            armed_at_unix: 10,
            armed_height: 20,
            cover_min: 3,
            send_after: None,
            own_ids: BTreeSet::new(),
            expired: false,
        };
        write_armed(dir.path(), &record).unwrap();
        let mode = fs::metadata(armed_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        record.hops.push(ArmedHop {
            raw_hex: "bb".into(),
            txid: "t2".into(),
            wtxid: "w2".into(),
            spent_output_id: "cd".repeat(32),
            created_output_id: "ef".repeat(32),
            receive_index: 5,
            fee_sats: 50_000,
            local_applied: false,
            broadcast: false,
            created_coin: None,
        });
        assert!(record.hops_remaining());
        assert!(arm_next(&mut record, 99, 30));
        assert_eq!(record.armed_index, 1);
        assert_eq!(record.armed_at_unix, 99);
        wipe_raw_tail(&mut record);
        assert!(record.expired);
        assert!(record.hops[1].raw_hex.is_empty());
        assert!(!record.hops[1].broadcast);
    }
}

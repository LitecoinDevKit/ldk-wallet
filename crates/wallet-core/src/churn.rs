//! One-coin MWEB self-spend job.
//!
//! Scoring and phase changes are pure. Broadcast and header fetches stay in
//! `app` / `mweb`. A hop counts only when the inclusion block's kernel and
//! output MMR sizes did not each grow by exactly one.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dto::{
    ChurnDepthRecord, ChurnPhase, ChurnStatus, CHURN_MAX_TARGET,
};
use crate::error::WalletError;
use crate::mweb_frozen;

pub const CHURN_JOB_FILE: &str = "churn_job.json";
pub const CHURN_DEPTH_FILE: &str = "churn_depth.json";

/// Kernel and output MMR sizes from one MWEB header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmrSizes {
    pub kernel_mmr_size: u64,
    pub output_mmr_size: u64,
}

/// Result of comparing a 1-in-1 hop's inclusion header with its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopScore {
    /// Parent or inclusion header was missing, or the pair cannot contain our hop.
    Unscored,
    /// Both MMR sizes grew by exactly 1: the block was only this spend.
    Solo,
    /// At least one foreign kernel or output was in the block.
    Mixed {
        other_kernels: u64,
        other_outputs: u64,
    },
}

/// Compare adjacent headers for a known 1-in-1 (one kernel, one output of ours).
pub fn score_1in1_hop(parent: Option<MmrSizes>, inclusion: Option<MmrSizes>) -> HopScore {
    let (Some(parent), Some(inclusion)) = (parent, inclusion) else {
        return HopScore::Unscored;
    };
    let Some(kernel_delta) = inclusion.kernel_mmr_size.checked_sub(parent.kernel_mmr_size) else {
        return HopScore::Unscored;
    };
    let Some(output_delta) = inclusion.output_mmr_size.checked_sub(parent.output_mmr_size) else {
        return HopScore::Unscored;
    };
    // Our hop adds one kernel and one output. A zero delta means this pair
    // does not contain it (wrong height, or a header from before inclusion).
    if kernel_delta == 0 || output_delta == 0 {
        return HopScore::Unscored;
    }
    if kernel_delta == 1 && output_delta == 1 {
        HopScore::Solo
    } else {
        HopScore::Mixed {
            other_kernels: kernel_delta.saturating_sub(1),
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
    if check.amount_sats <= check.fee_sats {
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
    })
}

pub fn ready_to_broadcast(job: &ChurnJob) -> bool {
    job.phase == ChurnPhase::WaitingToBroadcast
}

/// Record a broadcast. The next hop must not be built until this one is scored.
pub fn note_broadcast(job: &mut ChurnJob, wtxid: &str, new_output_id: &str) -> Result<(), WalletError> {
    if job.phase != ChurnPhase::WaitingToBroadcast {
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
                ChurnPhase::WaitingToBroadcast
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
        HopScore::Unscored => {}
        HopScore::Solo => {
            entry.last_other_kernels = None;
            entry.last_other_outputs = None;
        }
        HopScore::Mixed {
            other_kernels,
            other_outputs,
        } => {
            entry.non_solo_blocks = entry.non_solo_blocks.saturating_add(1);
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
        ChurnPhase::PausedSolo | ChurnPhase::WaitingToBroadcast => {
            job.phase = ChurnPhase::WaitingToBroadcast;
            job.last_error = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sizes(kernel: u64, output: u64) -> MmrSizes {
        MmrSizes {
            kernel_mmr_size: kernel,
            output_mmr_size: output,
        }
    }

    fn job_waiting_confirm() -> ChurnJob {
        let mut job = new_job(&"ab".repeat(32), true, 2, 50_000).unwrap();
        note_broadcast(&mut job, "wtxid", &"cd".repeat(32)).unwrap();
        job
    }

    #[test]
    fn solo_when_both_deltas_are_one() {
        assert_eq!(
            score_1in1_hop(Some(sizes(10, 20)), Some(sizes(11, 21))),
            HopScore::Solo
        );
    }

    #[test]
    fn foreign_kernel_or_output_counts() {
        assert_eq!(
            score_1in1_hop(Some(sizes(10, 20)), Some(sizes(12, 21))),
            HopScore::Mixed {
                other_kernels: 1,
                other_outputs: 0
            }
        );
        assert_eq!(
            score_1in1_hop(Some(sizes(10, 20)), Some(sizes(13, 24))),
            HopScore::Mixed {
                other_kernels: 2,
                other_outputs: 3
            }
        );
    }

    #[test]
    fn missing_header_is_unscored() {
        assert_eq!(score_1in1_hop(None, Some(sizes(11, 21))), HopScore::Unscored);
        assert_eq!(score_1in1_hop(Some(sizes(10, 20)), None), HopScore::Unscored);
        assert_eq!(
            score_1in1_hop(Some(sizes(10, 20)), Some(sizes(10, 21))),
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
        assert_eq!(job.phase, ChurnPhase::WaitingToBroadcast);
        assert_eq!(job.effective_depth, 1);
        assert!(ready_to_broadcast(&job));
        assert_eq!(job.last_other_kernels, Some(1));
        assert_eq!(job.last_other_outputs, Some(2));
    }

    #[test]
    fn mixed_at_target_finishes() {
        let mut job = new_job(&"ab".repeat(32), false, 1, 50_000).unwrap();
        note_broadcast(&mut job, "wtxid", &"cd".repeat(32)).unwrap();
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
        let err = note_broadcast(&mut job, "again", &"ef".repeat(32)).unwrap_err();
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
        let mut job = new_job(&id, false, 1, 50_000).unwrap();
        write_job(dir.path(), &job).unwrap();
        assert!(held_by_active_job(dir.path(), &id).unwrap());
        request_cancel(&mut job).unwrap();
        write_job(dir.path(), &job).unwrap();
        assert!(!held_by_active_job(dir.path(), &id).unwrap());
    }

    #[test]
    fn cancel_unfreezes_the_current_coin() {
        let dir = tempdir().unwrap();
        let id = "ab".repeat(32);
        let mut job = new_job(&id, true, 1, 50_000).unwrap();
        mweb_frozen::set_locked(dir.path(), &id, true).unwrap();
        write_job(dir.path(), &job).unwrap();
        request_cancel(&mut job).unwrap();
        write_job(dir.path(), &job).unwrap();
        mweb_frozen::set_locked(dir.path(), &job.current_output_id, false).unwrap();
        assert!(!mweb_frozen::contains(dir.path(), &id));
        assert_eq!(read_job(dir.path()).unwrap().unwrap().phase, ChurnPhase::Cancelled);
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
        assert!(depth_of(dir.path(), &from).unwrap().is_none());
    }
}

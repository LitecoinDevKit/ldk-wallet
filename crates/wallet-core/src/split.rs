//! 1-in-N-out self-split planner (equal + denominations).
//!
//! Pure amount math: fee first, then distribute. Preview and broadcast share
//! this so the last output cannot drift.

use crate::dto::{SplitOutput, SplitPreview};
use crate::error::WalletError;

/// Hard cap on split outputs (not including change).
pub const MAX_SPLIT_OUTPUTS: u32 = 50;
/// Equal mode requires at least two pieces.
pub const MIN_EQUAL_COUNT: u32 = 2;
/// Practical dust / leftover floor (ltc1 at 30 sat/vB, and MWEB junk-coin policy).
pub const SPLIT_DUST_SATS: u64 = 2940;
/// MWEB consensus allows 1 litoshi outputs; 0 is rejected.
pub const MWEB_MIN_OUTPUT_SATS: u64 = 1;

/// vsize of 1 P2WPKH input + `n_out` P2WPKH outputs (no extra inputs).
pub fn estimate_public_vsize(n_out: usize) -> u64 {
    11u64.saturating_add(68).saturating_add(31 * n_out as u64)
}

pub fn estimate_public_fee(n_split_outputs: usize, with_change: bool, fee_rate_sat_vb: u64) -> u64 {
    let n_out = n_split_outputs.saturating_add(usize::from(with_change));
    estimate_public_vsize(n_out).saturating_mul(fee_rate_sat_vb.max(1))
}

#[derive(Debug, Clone)]
pub struct PlanParams {
    pub input_sats: u64,
    pub equal_count: Option<u32>,
    pub amounts: Vec<u64>,
    /// 0 means estimate from `fee_rate_sat_vb` (Public) or `mweb_fee` (Private).
    pub fee_sats: u64,
    pub fee_rate_sat_vb: u64,
    pub public: bool,
    pub mweb_fee: u64,
}

pub fn plan_split(p: &PlanParams) -> Result<SplitPreview, WalletError> {
    let equal = p.equal_count.filter(|n| *n > 0);
    if equal.is_some() && !p.amounts.is_empty() {
        return Err(WalletError::BuildTx(
            "split request cannot set both equal_count and amounts".into(),
        ));
    }
    if equal.is_none() && p.amounts.is_empty() {
        return Err(WalletError::BuildTx(
            "split needs equal_count or at least one denomination amount".into(),
        ));
    }

    if let Some(n) = equal {
        plan_equal(p, n)
    } else {
        plan_denoms(p)
    }
}

fn min_recipient(public: bool) -> u64 {
    if public {
        SPLIT_DUST_SATS
    } else {
        MWEB_MIN_OUTPUT_SATS
    }
}

fn plan_equal(p: &PlanParams, count: u32) -> Result<SplitPreview, WalletError> {
    if count < MIN_EQUAL_COUNT {
        return Err(WalletError::BuildTx(format!(
            "equal split needs at least {MIN_EQUAL_COUNT} outputs"
        )));
    }
    if count > MAX_SPLIT_OUTPUTS {
        return Err(WalletError::BuildTx(format!(
            "split is limited to {MAX_SPLIT_OUTPUTS} outputs"
        )));
    }
    let fee_rate = p.fee_rate_sat_vb.max(1);
    let fee = if p.fee_sats > 0 {
        p.fee_sats
    } else if p.public {
        estimate_public_fee(count as usize, false, fee_rate)
    } else {
        p.mweb_fee
    };
    if p.input_sats <= fee {
        return Err(WalletError::BuildTx(format!(
            "coin of {} litoshis cannot cover a {} litoshis fee",
            p.input_sats, fee
        )));
    }
    let spendable = p.input_sats - fee;
    let n = count as u64;
    let base = spendable / n;
    let rem = spendable % n;
    let min_out = min_recipient(p.public);
    if base < min_out {
        return Err(WalletError::BuildTx(format!(
            "Output of {base} litoshis is below the network dust limit ({min_out} litoshis)."
        )));
    }
    let last = base + rem;
    if last < min_out {
        return Err(WalletError::BuildTx(format!(
            "Output of {last} litoshis is below the network dust limit ({min_out} litoshis)."
        )));
    }
    let mut outputs = Vec::with_capacity(count as usize);
    for i in 0..count {
        let amount_sats = if i + 1 == count { last } else { base };
        outputs.push(SplitOutput {
            amount_sats,
            is_change: false,
        });
    }
    Ok(SplitPreview {
        input_sats: p.input_sats,
        outputs,
        fee_sats: fee,
        fee_rate_sat_vb: if p.public { fee_rate } else { 0 },
        change_sats: 0,
        creates_change: false,
    })
}

fn plan_denoms(p: &PlanParams) -> Result<SplitPreview, WalletError> {
    let n = p.amounts.len() as u32;
    if n == 0 {
        return Err(WalletError::BuildTx(
            "split needs at least one denomination amount".into(),
        ));
    }
    if n > MAX_SPLIT_OUTPUTS {
        return Err(WalletError::BuildTx(format!(
            "split is limited to {MAX_SPLIT_OUTPUTS} outputs"
        )));
    }
    let min_out = min_recipient(p.public);
    for &amt in &p.amounts {
        if amt < min_out {
            return Err(WalletError::BuildTx(format!(
                "Output of {amt} litoshis is below the network dust limit ({min_out} litoshis)."
            )));
        }
    }
    let denom_total = p
        .amounts
        .iter()
        .try_fold(0u64, |acc, a| acc.checked_add(*a))
        .ok_or_else(|| WalletError::BuildTx("denomination total overflowed".into()))?;

    let fee_rate = p.fee_rate_sat_vb.max(1);
    let (fee, leftover) = if p.fee_sats > 0 {
        let fee = p.fee_sats;
        let leftover = p.input_sats.checked_sub(denom_total.saturating_add(fee));
        (fee, leftover)
    } else if p.public {
        resolve_public_denom_fee(p.input_sats, denom_total, n as usize, fee_rate)?
    } else {
        let fee = p.mweb_fee;
        let leftover = p.input_sats.checked_sub(denom_total.saturating_add(fee));
        (fee, leftover)
    };

    let leftover = leftover.ok_or_else(|| {
        WalletError::BuildTx(format!(
            "denominations plus fee ({} + {} litoshis) exceed the coin ({} litoshis)",
            denom_total, fee, p.input_sats
        ))
    })?;

    let mut outputs: Vec<SplitOutput> = p
        .amounts
        .iter()
        .map(|&amount_sats| SplitOutput {
            amount_sats,
            is_change: false,
        })
        .collect();
    let (change_sats, creates_change) = if leftover == 0 {
        (0, false)
    } else if leftover < SPLIT_DUST_SATS {
        return Err(WalletError::BuildTx(format!(
            "leftover {leftover} litoshis is below the dust floor ({SPLIT_DUST_SATS} litoshis); add a denomination or use Equal split"
        )));
    } else {
        outputs.push(SplitOutput {
            amount_sats: leftover,
            is_change: true,
        });
        (leftover, true)
    };

    Ok(SplitPreview {
        input_sats: p.input_sats,
        outputs,
        fee_sats: fee,
        fee_rate_sat_vb: if p.public { fee_rate } else { 0 },
        change_sats,
        creates_change,
    })
}

fn resolve_public_denom_fee(
    input: u64,
    denom_total: u64,
    n: usize,
    fee_rate: u64,
) -> Result<(u64, Option<u64>), WalletError> {
    let fee_no_change = estimate_public_fee(n, false, fee_rate);
    let Some(leftover) = input.checked_sub(denom_total.saturating_add(fee_no_change)) else {
        return Ok((fee_no_change, None));
    };
    if leftover == 0 {
        return Ok((fee_no_change, Some(0)));
    }
    if leftover < SPLIT_DUST_SATS {
        return Ok((fee_no_change, Some(leftover)));
    }
    let fee_change = estimate_public_fee(n, true, fee_rate);
    let leftover2 = input.checked_sub(denom_total.saturating_add(fee_change));
    Ok((fee_change, leftover2))
}

/// Greedy largest-first pack of `denoms` (descending) into `available`.
#[allow(dead_code)]
pub fn greedy_fill(available: u64, denoms_desc: &[u64]) -> Vec<u64> {
    let mut remaining = available;
    let mut out = Vec::new();
    for &d in denoms_desc {
        if d == 0 {
            continue;
        }
        while remaining >= d && (out.len() as u32) < MAX_SPLIT_OUTPUTS {
            out.push(d);
            remaining -= d;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_equal(input: u64, count: u32, fee_rate: u64, fee_sats: u64) -> SplitPreview {
        plan_split(&PlanParams {
            input_sats: input,
            equal_count: Some(count),
            amounts: vec![],
            fee_sats,
            fee_rate_sat_vb: fee_rate,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap()
    }

    #[test]
    fn equal_remainder_on_last_no_change() {
        let fee = estimate_public_fee(3, false, 1);
        let input = 1_000_000;
        let preview = public_equal(input, 3, 1, 0);
        assert_eq!(preview.fee_sats, fee);
        assert!(!preview.creates_change);
        assert_eq!(preview.change_sats, 0);
        let spendable = input - fee;
        assert_eq!(preview.outputs.len(), 3);
        assert_eq!(preview.outputs[0].amount_sats, spendable / 3);
        assert_eq!(preview.outputs[1].amount_sats, spendable / 3);
        assert_eq!(
            preview.outputs[2].amount_sats,
            spendable / 3 + spendable % 3
        );
        let sum: u64 = preview.outputs.iter().map(|o| o.amount_sats).sum();
        assert_eq!(sum + preview.fee_sats, input);
        assert!(preview.outputs.iter().all(|o| !o.is_change));
    }

    #[test]
    fn equal_explicit_fee_matches_preview() {
        let first = public_equal(5_000_000, 4, 2, 0);
        let second = public_equal(5_000_000, 4, 2, first.fee_sats);
        assert_eq!(first, second);
    }

    #[test]
    fn denom_leftover_becomes_change() {
        let amounts = vec![100_000, 100_000];
        let preview = plan_split(&PlanParams {
            input_sats: 1_000_000,
            equal_count: None,
            amounts: amounts.clone(),
            fee_sats: 0,
            fee_rate_sat_vb: 1,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap();
        assert!(preview.creates_change);
        assert!(preview.change_sats >= SPLIT_DUST_SATS);
        assert_eq!(preview.outputs.last().unwrap().is_change, true);
        let sum: u64 = preview.outputs.iter().map(|o| o.amount_sats).sum();
        assert_eq!(sum + preview.fee_sats, 1_000_000);
    }

    #[test]
    fn denom_subdust_leftover_rejected() {
        let fee = estimate_public_fee(1, false, 1);
        // leftover = 1000 < 2940
        let input = 10_000 + fee + 1_000;
        let err = plan_split(&PlanParams {
            input_sats: input,
            equal_count: None,
            amounts: vec![10_000],
            fee_sats: fee,
            fee_rate_sat_vb: 1,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("leftover"), "{msg}");
        assert!(msg.contains("dust"), "{msg}");
    }

    #[test]
    fn denom_overfill_rejected() {
        let err = plan_split(&PlanParams {
            input_sats: 50_000,
            equal_count: None,
            amounts: vec![40_000, 40_000],
            fee_sats: 10_000,
            fee_rate_sat_vb: 1,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap_err();
        assert!(err.to_string().contains("exceed"));
    }

    #[test]
    fn dust_output_error_names_floor() {
        let err = plan_split(&PlanParams {
            input_sats: 10_000,
            equal_count: None,
            amounts: vec![100],
            fee_sats: 200,
            fee_rate_sat_vb: 1,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("100 litoshis"), "{msg}");
        assert!(msg.contains(&SPLIT_DUST_SATS.to_string()), "{msg}");
    }

    #[test]
    fn mweb_equal_uses_kernel_fee() {
        let preview = plan_split(&PlanParams {
            input_sats: 1_000_000,
            equal_count: Some(4),
            amounts: vec![],
            fee_sats: 0,
            fee_rate_sat_vb: 1,
            public: false,
            mweb_fee: 50_000,
        })
        .unwrap();
        assert_eq!(preview.fee_sats, 50_000);
        assert_eq!(preview.fee_rate_sat_vb, 0);
        let sum: u64 = preview.outputs.iter().map(|o| o.amount_sats).sum();
        assert_eq!(sum + 50_000, 1_000_000);
    }

    #[test]
    fn greedy_fill_largest_first() {
        let filled = greedy_fill(37_000_000, &[10_000_000, 5_000_000, 1_000_000]);
        assert_eq!(
            filled,
            vec![10_000_000, 10_000_000, 10_000_000, 5_000_000, 1_000_000, 1_000_000]
        );
    }

    #[test]
    fn equal_count_cap() {
        let err = plan_split(&PlanParams {
            input_sats: 100_000_000,
            equal_count: Some(51),
            amounts: vec![],
            fee_sats: 1000,
            fee_rate_sat_vb: 1,
            public: true,
            mweb_fee: 50_000,
        })
        .unwrap_err();
        assert!(err.to_string().contains("50"));
    }
}

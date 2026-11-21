use crate::error::LitVmError;
use crate::network::{MAX_FEE_GWEI, MAX_PRIORITY_GWEI, MAX_TOTAL_FEE_WEI};

/// EIP-1559 replacement floor: 12.5% above the in-mempool tx (Geth default).
pub const RBF_NUM: u128 = 1125;
pub const RBF_DEN: u128 = 1000;

/// `ceil(old * 12.5%)`, at least 1 wei above `old`, then `max` with current market.
pub fn bump_eip1559(old: u128, current: u128) -> u128 {
    let bumped = old.saturating_mul(RBF_NUM).div_ceil(RBF_DEN);
    let floor = if bumped <= old {
        old.saturating_add(1)
    } else {
        bumped
    };
    floor.max(current)
}

pub fn cap_priority_gwei(value: u128) -> Result<u128, LitVmError> {
    cap_gwei(value, MAX_PRIORITY_GWEI, "priority fee")
}

pub fn cap_max_fee_gwei(value: u128) -> Result<u128, LitVmError> {
    cap_gwei(value, MAX_FEE_GWEI, "max fee")
}

fn cap_gwei(value: u128, cap_gwei: u128, label: &str) -> Result<u128, LitVmError> {
    let cap = cap_gwei.saturating_mul(1_000_000_000);
    if value > cap {
        return Err(LitVmError::FeeCongested(format!(
            "{label} {value} wei/gas exceeds {cap_gwei} gwei headroom (Orbit L1 data cost is high — try again shortly)"
        )));
    }
    Ok(value)
}

pub fn check_total_fee(gas_limit: u64, max_fee_per_gas: u128) -> Result<u128, LitVmError> {
    let total = (gas_limit as u128).saturating_mul(max_fee_per_gas);
    if total > MAX_TOTAL_FEE_WEI {
        return Err(LitVmError::FeeCap(format!(
            "total fee {total} wei exceeds {} wei (0.05 zkLTC) safety cap — refusing in case the RPC is hostile",
            MAX_TOTAL_FEE_WEI
        )));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_is_at_least_12_5_percent() {
        assert_eq!(bump_eip1559(1_000, 0), 1_125);
        assert_eq!(bump_eip1559(8, 0), 9); // ceil(8*1.125)=9
        assert_eq!(bump_eip1559(1, 0), 2); // at least +1
    }

    #[test]
    fn bump_takes_current_if_higher() {
        assert_eq!(bump_eip1559(1_000, 5_000), 5_000);
        assert_eq!(bump_eip1559(1_000, 1_100), 1_125);
    }

    #[test]
    fn total_fee_cap_rejects_drain() {
        // 2M gas * 20 gwei = 0.04 zkLTC — under 0.05
        assert!(check_total_fee(2_000_000, 20 * 1_000_000_000).is_ok());
        // 2M gas * 30 gwei = 0.06 zkLTC — over
        assert!(check_total_fee(2_000_000, 30 * 1_000_000_000).is_err());
        // Extreme u64::MAX * u128::MAX saturates and is rejected by MAX_TOTAL_FEE_WEI.
        assert!(check_total_fee(u64::MAX, u128::MAX).is_err());
        assert_eq!(bump_eip1559(u128::MAX, 0), u128::MAX);
    }
}

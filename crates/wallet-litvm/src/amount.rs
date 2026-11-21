use alloy::primitives::U256;

use crate::error::LitVmError;

pub const DECIMALS: u32 = 18;

pub fn parse_zkltc(input: &str) -> Result<U256, LitVmError> {
    let raw = input.replace([' ', '\u{00a0}', '\u{202f}'], "");
    if raw.is_empty() || raw == "." || raw.contains(',') || raw.starts_with('-') {
        return Err(LitVmError::InvalidAmount("enter a zkLTC amount".into()));
    }
    if !raw.chars().all(|c| c.is_ascii_digit() || c == '.')
        || raw.chars().filter(|c| *c == '.').count() > 1
    {
        return Err(LitVmError::InvalidAmount("invalid zkLTC amount".into()));
    }
    let (whole, frac) = match raw.split_once('.') {
        Some((w, f)) => (w, f),
        None => (raw.as_str(), ""),
    };
    if frac.len() > DECIMALS as usize {
        return Err(LitVmError::InvalidAmount(
            "zkLTC allows at most 18 decimal places".into(),
        ));
    }
    let mut digits = String::new();
    if whole.is_empty() || whole == "0" {
        // keep going
    }
    digits.push_str(if whole.is_empty() { "0" } else { whole });
    digits.push_str(frac);
    digits.push_str(&"0".repeat(DECIMALS as usize - frac.len()));
    let trimmed = digits.trim_start_matches('0');
    let trimmed = if trimmed.is_empty() { "0" } else { trimmed };
    U256::from_str_radix(trimmed, 10).map_err(|e| LitVmError::InvalidAmount(e.to_string()))
}

pub fn format_zkltc(wei: U256) -> String {
    let mut s = wei.to_string();
    if s.len() <= DECIMALS as usize {
        s = format!("{:0>width$}", s, width = DECIMALS as usize + 1);
    }
    let split = s.len() - DECIMALS as usize;
    let (whole, frac) = s.split_at(split);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_round_trip() {
        let wei = parse_zkltc("1.5").unwrap();
        assert_eq!(format_zkltc(wei), "1.5");
        assert_eq!(
            parse_zkltc("0.000000000000000001").unwrap(),
            U256::from(1u64)
        );
        assert_eq!(format_zkltc(U256::from(1u64)), "0.000000000000000001");
        assert_eq!(format_zkltc(U256::from(10u64).pow(U256::from(18u64))), "1");
    }

    #[test]
    fn parse_and_format_seeded_property_and_bounds() {
        for bad in [
            "",
            ".",
            "-1",
            "1,5",
            "1.2.3",
            "0.0000000000000000001", // 19 decimals
            "1e18",
            "NaN",
            "Infinity",
        ] {
            assert!(
                parse_zkltc(bad).is_err(),
                "expected invalid zkLTC amount to fail: {bad:?}"
            );
        }

        // Deterministic xorshift64 over 200 random wei values: format -> parse round-trips identically.
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let hi = s.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            let wei = U256::from_limbs([s, hi, 0, 0]);
            let formatted = format_zkltc(wei);
            let reparsed = parse_zkltc(&formatted).expect("reparse formatted zkLTC");
            assert_eq!(reparsed, wei, "round-trip drift for {formatted}");
        }
    }
}

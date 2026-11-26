//! Transaction construction, amount/fee arithmetic, Litecoin dust policy, and shape invariants.
//!
//! Centralizes the value-safety rules shared across public sends, splits, transfers,
//! peg-ins, peg-outs, private sends, and self-spends:
//! - Checked litoshi arithmetic bounded by [`MAX_MONEY`] (`84,000,000` LTC).
//! - Fee-rate bounds (`1..=MAX_FEE_RATE_SAT_VB`) so hostile servers or inputs cannot overflow fee math.
//! - Destination script and address-kind validation (forbidding empty MWEB scripts and v8/v9 bridge
//!   programs on public outputs, and forbidding transparent addresses on MWEB outputs).
//! - [`LitecoinDustCoinSelection`] enforcing Litecoin Core's 30 sat/vB dust floor (`2,940` litoshis
//!   for P2WPKH, `3,300` for witness-v9 peg-in) on change and drain outputs instead of `rust-litecoin`'s
//!   inherited 3 sat/vB (`294` litoshis) constant.
//! - Post-construction shape and value conservation verifiers for transparent PSBTs, hybrid peg-ins,
//!   and MWEB transactions.

use std::collections::HashSet;
use std::str::FromStr;

use bdk_mweb::MwebCoin;
use bdk_wallet::bitcoin::address::AddressData;
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::All;
use bdk_wallet::bitcoin::{
    Address, Amount, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Transaction, TxIn, WitnessVersion,
};
use bdk_wallet::coin_selection::{
    CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm, Excess,
    InsufficientFunds,
};
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::WeightedUtxo;

use crate::error::WalletError;
use crate::network::WalletNetwork;

/// Consensus maximum supply in litoshis (`84,000,000` LTC = `8,400,000,000,000,000` litoshis).
pub const MAX_MONEY: u64 = bdk_mweb::limits::MAX_MONEY;

/// Upper bound on transparent fee rates (`100,000` sat/vB = `0.1` LTC/vB).
///
/// Prevents integer overflow in `vsize * fee_rate` and rejects implausible estimates from
/// a broken or hostile Electrum / explorer server before building a transaction.
pub const MAX_FEE_RATE_SAT_VB: u64 = 100_000;

/// Witness-v9 peg-in script length (`OP_9` + `OP_PUSHBYTES_32` + 32-byte `kernel_id` = 34 bytes).
/// At Litecoin Core's 30 sat/vB dust relay fee, a 34-byte witness program has dust floor `3,300` litoshis.
pub const PEGIN_V9_DUST_SATS: u64 = 3_300;

/// Reject any litoshi value above [`MAX_MONEY`].
pub fn check_money(sats: u64, what: &str) -> Result<u64, WalletError> {
    if sats > MAX_MONEY {
        return Err(WalletError::BuildTx(format!(
            "{what} ({sats} litoshis) exceeds maximum Litecoin supply ({MAX_MONEY} litoshis)"
        )));
    }
    Ok(sats)
}

/// Checked addition of two litoshi amounts, rejecting overflow or a sum above [`MAX_MONEY`].
pub fn checked_add_money(a: u64, b: u64, what: &str) -> Result<u64, WalletError> {
    check_money(a, what)?;
    check_money(b, what)?;
    let sum = a
        .checked_add(b)
        .ok_or_else(|| WalletError::BuildTx(format!("{what} overflowed u64")))?;
    check_money(sum, what)
}

/// Sum an iterator of litoshi amounts, rejecting overflow or a total above [`MAX_MONEY`].
pub fn checked_sum_sats<I>(iter: I, what: &str) -> Result<u64, WalletError>
where
    I: IntoIterator<Item = u64>,
{
    iter.into_iter()
        .try_fold(0u64, |acc, v| checked_add_money(acc, v, what))
}

/// Convert a positive outgoing litoshi total into a negative `i64` net delta safely.
pub fn neg_net_sats(total_out: u64) -> Result<i64, WalletError> {
    let checked = check_money(total_out, "outgoing total")?;
    Ok(-(checked as i64))
}

/// Clamp a floating-point sat/vB estimate into `1..=MAX_FEE_RATE_SAT_VB`.
pub fn clamp_estimated_fee_rate(sat_vb_float: f64) -> u64 {
    if !sat_vb_float.is_finite() || sat_vb_float <= 0.0 {
        return 1;
    }
    if sat_vb_float >= MAX_FEE_RATE_SAT_VB as f64 {
        return MAX_FEE_RATE_SAT_VB;
    }
    (sat_vb_float.ceil() as u64).clamp(1, MAX_FEE_RATE_SAT_VB)
}

/// Validate a caller-supplied or estimated fee rate in sat/vB.
pub fn validate_fee_rate_sat_vb(fee_rate_sat_vb: u64) -> Result<FeeRate, WalletError> {
    if fee_rate_sat_vb == 0 {
        return Err(WalletError::BuildTx(
            "fee_rate_sat_vb must be non-zero (got 0)".into(),
        ));
    }
    if fee_rate_sat_vb > MAX_FEE_RATE_SAT_VB {
        return Err(WalletError::BuildTx(format!(
            "fee_rate_sat_vb {fee_rate_sat_vb} exceeds maximum allowed fee rate ({MAX_FEE_RATE_SAT_VB} sat/vB)"
        )));
    }
    FeeRate::from_sat_per_vb(fee_rate_sat_vb)
        .ok_or_else(|| WalletError::BuildTx(format!("invalid fee_rate_sat_vb ({fee_rate_sat_vb})")))
}

/// Litecoin Core 30 sat/vB dust threshold (`DUST_RELAY_TX_FEE = 30,000` litoshis/kB).
pub fn ltc_dust_threshold(script: &Script) -> u64 {
    bdk_mweb::policy::dust_threshold(script)
}

/// Extra litoshis above the peg-out relay floor. An exact floor was rejected
/// once the byte count was even one short.
const PEGOUT_FEE_BUFFER_SATS: u64 = 16;

/// Relay minimum for an MWEB kernel this wallet builds.
///
/// `standard_outputs` counts every MWEB output, including change. Peg-out scripts
/// add `ceil(len / 42)` each and are not standard outputs. Inputs add nothing.
/// That weight times `BASE_MWEB_FEE` (100 litoshis) is the MWEB part. An
/// MWEB-only peg-out also pays 1 litoshi per byte of each transparent peg-out
/// output, because `GetTransactionWeight` still counts those outputs. Paying
/// more does not get a faster block: this is a relay floor, not a mempool feerate.
pub fn min_kernel_fee<'a>(
    standard_outputs: usize,
    pegout_scripts: impl IntoIterator<Item = &'a Script>,
) -> u64 {
    let scripts: Vec<&Script> = pegout_scripts.into_iter().collect();
    let kernel = bdk_mweb::policy::min_mweb_fee(bdk_mweb::policy::mweb_weight(
        standard_outputs,
        scripts.iter().copied(),
    ));
    kernel.saturating_add(pegout_byte_fee(&scripts))
}

/// Serialized size of one peg-out `CTxOut`: 8-byte amount, compact size, script.
fn pegout_output_bytes(script: &Script) -> u64 {
    let script_len = script.len() as u64;
    let compact = if script_len < 253 {
        1
    } else if script_len <= u64::from(u16::MAX) {
        3
    } else {
        5
    };
    8 + compact + script_len
}

/// Byte fee for every peg-out output, plus [`PEGOUT_FEE_BUFFER_SATS`].
///
/// Weight is the serialized size times 4, and virtual size rounds that up to
/// a multiple of 4, which is the serialized size again. Min relay is 1
/// litoshi per vbyte.
fn pegout_byte_fee(scripts: &[&Script]) -> u64 {
    let bytes: u64 = scripts.iter().copied().map(pegout_output_bytes).sum();
    if bytes == 0 {
        return 0;
    }
    let weight = bytes.saturating_mul(4);
    let vsize = weight.div_ceil(4);
    vsize.saturating_add(PEGOUT_FEE_BUFFER_SATS)
}

/// True when `script` is a standard spendable public wallet script (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).
///
/// Rejects empty scripts (such as `Address::script_pubkey()` on an MWEB stealth address),
/// `OP_RETURN`, and witness v8/v9 MWEB bridge programs (`HogAddr` and peg-in kernel scripts).
pub fn is_standard_wallet_script(script: &Script) -> bool {
    if script.is_empty() || script.is_op_return() {
        return false;
    }
    if matches!(
        script.witness_version(),
        Some(WitnessVersion::V8 | WitnessVersion::V9)
    ) {
        return false;
    }
    script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
}

/// Validate a public destination address for a transparent send or peg-out.
///
/// Returns `(address, script_pubkey, ltc_dust_sats)`. Refuses MWEB stealth addresses
/// (whose `script_pubkey()` is empty and would create an anyone-can-spend output on `drain_to`),
/// witness v8/v9 MWEB bridge scripts, and non-standard scripts.
pub fn validate_public_recipient(
    raw: &str,
    network: WalletNetwork,
) -> Result<(Address, ScriptBuf, u64), WalletError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WalletError::InvalidAddress(
            "destination address required".into(),
        ));
    }
    let bdk_net = network.to_bitcoin_network();
    let address = Address::from_str(trimmed)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .require_network(bdk_net)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    if matches!(address.to_address_data(), AddressData::Mweb { .. }) {
        return Err(WalletError::InvalidAddress(
            "public destination cannot be a Private (MWEB) stealth address".into(),
        ));
    }
    let script = address.script_pubkey();
    if matches!(
        script.witness_version(),
        Some(WitnessVersion::V8 | WitnessVersion::V9)
    ) {
        return Err(WalletError::InvalidAddress(
            "public destination cannot be an MWEB bridge (witness v8/v9) script".into(),
        ));
    }
    if !is_standard_wallet_script(&script) {
        return Err(WalletError::InvalidAddress(
            "public destination is not a standard spendable address type".into(),
        ));
    }
    let dust_sats = ltc_dust_threshold(&script);
    Ok((address, script, dust_sats))
}

/// Validate a private (MWEB) stealth destination address (`ltcmweb1…` / `tmweb1…`).
pub fn validate_mweb_recipient(raw: &str, network: WalletNetwork) -> Result<Address, WalletError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(WalletError::InvalidAddress(
            "MWEB destination address required".into(),
        ));
    }
    let bdk_net = network.to_bitcoin_network();
    let address = Address::from_str(trimmed)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
        .require_network(bdk_net)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    if !matches!(address.to_address_data(), AddressData::Mweb { .. }) {
        return Err(WalletError::InvalidAddress(
            "private send requires an ltcmweb / tmweb stealth address".into(),
        ));
    }
    Ok(address)
}

/// Normalize and deduplicate hex output IDs while preserving first-seen order.
pub fn normalize_and_dedup_ids(ids: Option<&[String]>) -> Option<Vec<String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in ids.unwrap_or(&[]) {
        let norm = raw.trim().to_ascii_lowercase();
        if !norm.is_empty() && seen.insert(norm.clone()) {
            out.push(norm);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Parse and deduplicate transparent outpoints (`txid:vout`) while preserving first-seen order.
pub fn parse_and_dedup_outpoints(
    raw: Option<&[String]>,
) -> Result<Option<Vec<OutPoint>>, WalletError> {
    let Some(list) = raw else {
        return Ok(None);
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in list {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            continue;
        }
        let op = OutPoint::from_str(trimmed).map_err(|e| {
            WalletError::BuildTx(format!(
                "invalid outpoint '{trimmed}' (expected txid:vout): {e}"
            ))
        })?;
        if seen.insert(op) {
            out.push(op);
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// Coin-selection wrapper that enforces Litecoin Core's 30 sat/vB dust floor (`2,940` litoshis
/// on P2WPKH) on change and drain outputs instead of `rust-litecoin`'s 3 sat/vB (`294` litoshis).
#[derive(Debug, Default, Clone, Copy)]
pub struct LitecoinDustCoinSelection;

fn utxo_input_fee(wu: &WeightedUtxo, fee_rate: FeeRate) -> Amount {
    let weight = TxIn::default()
        .segwit_weight()
        .checked_add(wu.satisfaction_weight)
        .expect("weight addition cannot overflow");
    fee_rate * weight
}

impl CoinSelectionAlgorithm for LitecoinDustCoinSelection {
    fn coin_select<R: bdk_wallet::bitcoin::key::rand::RngCore>(
        &self,
        required_utxos: Vec<WeightedUtxo>,
        optional_utxos: Vec<WeightedUtxo>,
        fee_rate: FeeRate,
        target_amount: Amount,
        drain_script: &Script,
        rand: &mut R,
    ) -> Result<CoinSelectionResult, InsufficientFunds> {
        let optional_pool = optional_utxos.clone();
        let mut res = DefaultCoinSelectionAlgorithm::default().coin_select(
            required_utxos,
            optional_utxos,
            fee_rate,
            target_amount,
            drain_script,
            rand,
        )?;
        let ltc_dust = Amount::from_sat(ltc_dust_threshold(drain_script));

        match res.excess {
            Excess::NoChange {
                dust_threshold,
                remaining_amount,
                change_fee,
            } => {
                res.excess = Excess::NoChange {
                    dust_threshold: dust_threshold.max(ltc_dust),
                    remaining_amount,
                    change_fee,
                };
            }
            Excess::Change { amount, fee } if amount < ltc_dust => {
                // See if adding unused optional UTXOs with positive effective value can lift
                // change above `ltc_dust` for less input fee than forfeiting `amount`.
                let selected_ops: HashSet<OutPoint> =
                    res.selected.iter().map(|u| u.outpoint()).collect();
                let mut unused: Vec<(WeightedUtxo, Amount, Amount)> = optional_pool
                    .into_iter()
                    .filter(|wu| !selected_ops.contains(&wu.utxo.outpoint()))
                    .filter_map(|wu| {
                        let in_fee = utxo_input_fee(&wu, fee_rate);
                        let val = wu.utxo.txout().value;
                        val.checked_sub(in_fee)
                            .filter(|eff| *eff > Amount::ZERO)
                            .map(|eff| (wu, in_fee, eff))
                    })
                    .collect();
                unused.sort_by_key(|(_, _, eff)| std::cmp::Reverse(*eff));

                let mut cur_amount = amount;
                let mut extra_fee = Amount::ZERO;
                let mut added = Vec::new();
                for (wu, in_fee, eff) in unused {
                    cur_amount = cur_amount.checked_add(eff).unwrap_or(Amount::MAX);
                    extra_fee = extra_fee.checked_add(in_fee).unwrap_or(Amount::MAX);
                    added.push(wu.utxo);
                    if cur_amount >= ltc_dust {
                        break;
                    }
                }

                if cur_amount >= ltc_dust && extra_fee < amount {
                    res.selected.extend(added);
                    res.fee_amount = res.fee_amount.checked_add(extra_fee).unwrap_or(Amount::MAX);
                    res.excess = Excess::Change {
                        amount: cur_amount,
                        fee,
                    };
                } else {
                    res.excess = Excess::NoChange {
                        dust_threshold: ltc_dust,
                        remaining_amount: amount.checked_add(fee).unwrap_or(Amount::MAX),
                        change_fee: fee,
                    };
                }
            }
            Excess::Change { .. } => {}
        }

        Ok(res)
    }
}

/// Verify structural and value invariants on a built transparent PSBT (`send`, `split`, `transfer`).
///
/// Checks:
/// - Non-empty inputs and outputs, no MWEB body or HogEx flag.
/// - No duplicate input outpoints.
/// - Every output has a standard wallet script, `value >= ltc_dust_threshold`, and `value <= MAX_MONEY`.
/// - Exact value conservation: `sum(inputs) == sum(outputs) + fee_sats` with `fee_sats > 0`.
pub fn verify_transparent_psbt(psbt: &Psbt) -> Result<u64, WalletError> {
    let tx = &psbt.unsigned_tx;
    if tx.mw_tx.is_some() || tx.is_hog_ex {
        return Err(WalletError::BuildTx(
            "transparent transaction must not carry an MWEB payload or HogEx flag".into(),
        ));
    }
    if tx.input.is_empty() {
        return Err(WalletError::BuildTx("transaction has no inputs".into()));
    }
    if tx.output.is_empty() {
        return Err(WalletError::BuildTx("transaction has no outputs".into()));
    }
    if psbt.inputs.len() != tx.input.len() {
        return Err(WalletError::BuildTx(
            "PSBT input metadata count does not match unsigned transaction".into(),
        ));
    }

    let mut seen_outpoints = HashSet::with_capacity(tx.input.len());
    let mut input_sum = 0u64;
    for (txin, psbt_in) in tx.input.iter().zip(psbt.inputs.iter()) {
        if !seen_outpoints.insert(txin.previous_output) {
            return Err(WalletError::BuildTx(format!(
                "duplicate transaction input {}",
                txin.previous_output
            )));
        }
        let prev_sats = psbt_in
            .witness_utxo
            .as_ref()
            .map(|o| o.value.to_sat())
            .or_else(|| {
                psbt_in
                    .non_witness_utxo
                    .as_ref()
                    .and_then(|prev_tx| prev_tx.output.get(txin.previous_output.vout as usize))
                    .map(|o| o.value.to_sat())
            })
            .ok_or_else(|| {
                WalletError::BuildTx(format!(
                    "PSBT input {} is missing prevout value",
                    txin.previous_output
                ))
            })?;
        input_sum = checked_add_money(input_sum, prev_sats, "transaction input total")?;
    }

    let mut output_sum = 0u64;
    for (idx, txout) in tx.output.iter().enumerate() {
        let val = check_money(txout.value.to_sat(), "transaction output")?;
        if !is_standard_wallet_script(&txout.script_pubkey) {
            return Err(WalletError::BuildTx(format!(
                "output {} has a non-standard or forbidden script",
                idx
            )));
        }
        let dust = ltc_dust_threshold(&txout.script_pubkey);
        if val < dust {
            return Err(WalletError::BuildTx(format!(
                "output of {val} litoshis is below the network dust limit ({dust} litoshis)"
            )));
        }
        output_sum = checked_add_money(output_sum, val, "transaction output total")?;
    }

    let fee_sats = input_sum.checked_sub(output_sum).ok_or_else(|| {
        WalletError::BuildTx(format!(
            "transaction outputs ({output_sum} litoshis) exceed inputs ({input_sum} litoshis)"
        ))
    })?;
    if fee_sats == 0 {
        return Err(WalletError::BuildTx(
            "transaction fee must be greater than zero".into(),
        ));
    }
    let psbt_fee = psbt
        .fee_amount()
        .ok_or_else(|| WalletError::BuildTx("unable to compute PSBT fee".into()))?
        .to_sat();
    if psbt_fee != fee_sats {
        return Err(WalletError::BuildTx(format!(
            "PSBT fee ({psbt_fee} litoshis) does not match input-minus-output delta ({fee_sats} litoshis)"
        )));
    }
    Ok(fee_sats)
}

/// Verify structural, script, commitment, and value conservation invariants on a signed peg-in.
#[allow(clippy::too_many_arguments)]
pub fn verify_pegin_tx(
    psbt: &Psbt,
    tx: &Transaction,
    expected_kernel_id: &[u8; 32],
    pegin_amount_sats: u64,
    mweb_fee_sats: u64,
    transparent_fee_sats: u64,
    outputs: &[MwebCoin],
    secp: &Secp256k1<All>,
) -> Result<(), WalletError> {
    check_money(pegin_amount_sats, "peg-in amount")?;
    check_money(mweb_fee_sats, "peg-in MWEB fee")?;
    check_money(transparent_fee_sats, "peg-in transparent fee")?;
    if pegin_amount_sats <= mweb_fee_sats {
        return Err(WalletError::BuildTx(
            "peg-in amount must exceed the MWEB fee".into(),
        ));
    }
    if pegin_amount_sats < PEGIN_V9_DUST_SATS {
        return Err(WalletError::BuildTx(format!(
            "peg-in amount {pegin_amount_sats} litoshis is below the {PEGIN_V9_DUST_SATS} litoshis dust limit"
        )));
    }
    let min_mweb_fee = bdk_mweb::policy::min_mweb_fee(bdk_mweb::policy::mweb_weight(1, []));
    if mweb_fee_sats < min_mweb_fee {
        return Err(WalletError::BuildTx(format!(
            "MWEB fee {mweb_fee_sats} litoshis is below the minimum {min_mweb_fee} litoshis"
        )));
    }

    if tx.input.is_empty() || tx.output.is_empty() || tx.output.len() > 2 {
        return Err(WalletError::BuildTx(format!(
            "peg-in must have at least 1 input and 1..=2 transparent outputs (got {} inputs, {} outputs)",
            tx.input.len(),
            tx.output.len()
        )));
    }

    let expected_v9 = bdk_wallet::chain::mweb_pegin_script_pubkey(expected_kernel_id);
    let mut v9_count = 0usize;
    let mut output_sum = 0u64;
    for txout in &tx.output {
        let val = check_money(txout.value.to_sat(), "peg-in transparent output")?;
        output_sum = checked_add_money(output_sum, val, "peg-in transparent output total")?;
        if txout.script_pubkey == expected_v9 {
            if val != pegin_amount_sats {
                return Err(WalletError::BuildTx(format!(
                    "peg-in v9 output value ({val}) does not match requested peg-in amount ({pegin_amount_sats})"
                )));
            }
            v9_count += 1;
        } else {
            if !is_standard_wallet_script(&txout.script_pubkey) {
                return Err(WalletError::BuildTx(
                    "peg-in change output has a non-standard script".into(),
                ));
            }
            let dust = ltc_dust_threshold(&txout.script_pubkey);
            if val < dust {
                return Err(WalletError::BuildTx(format!(
                    "peg-in change output of {val} litoshis is below the dust limit ({dust} litoshis)"
                )));
            }
        }
    }
    if v9_count != 1 {
        return Err(WalletError::BuildTx(format!(
            "peg-in must contain exactly one witness-v9 output matching kernel_id (found {v9_count})"
        )));
    }

    let mut seen_outpoints = HashSet::with_capacity(tx.input.len());
    let mut input_sum = 0u64;
    for (txin, psbt_in) in tx.input.iter().zip(psbt.inputs.iter()) {
        if !seen_outpoints.insert(txin.previous_output) {
            return Err(WalletError::BuildTx(format!(
                "duplicate peg-in transparent input {}",
                txin.previous_output
            )));
        }
        let prev_sats = psbt_in
            .witness_utxo
            .as_ref()
            .map(|o| o.value.to_sat())
            .ok_or_else(|| WalletError::BuildTx("peg-in input missing witness_utxo".into()))?;
        input_sum = checked_add_money(input_sum, prev_sats, "peg-in transparent input total")?;
    }
    let actual_transparent_fee = input_sum
        .checked_sub(output_sum)
        .ok_or_else(|| WalletError::BuildTx("peg-in transparent outputs exceed inputs".into()))?;
    if actual_transparent_fee != transparent_fee_sats {
        return Err(WalletError::BuildTx(format!(
            "peg-in transparent fee ({actual_transparent_fee}) does not match expected ({transparent_fee_sats})"
        )));
    }

    let mw = tx
        .mw_tx
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("extracted peg-in is missing mw_tx".into()))?;
    if !mw.body.inputs.is_empty() || mw.body.outputs.len() != 1 || mw.body.kernels.len() != 1 {
        return Err(WalletError::Mweb(
            "peg-in MWEB body must have 0 inputs, 1 output, and 1 kernel".into(),
        ));
    }
    let kernel = &mw.body.kernels[0];
    if &bdk_mweb::kernel_id(kernel) != expected_kernel_id {
        return Err(WalletError::Mweb(
            "peg-in MWEB kernel_id does not match witness-v9 program".into(),
        ));
    }
    if kernel.pegin != Some(pegin_amount_sats as i64) {
        return Err(WalletError::Mweb(
            "peg-in kernel pegin_amount does not match v9 output".into(),
        ));
    }
    if kernel.fee != Some(mweb_fee_sats as i64) {
        return Err(WalletError::Mweb(
            "peg-in kernel fee does not match expected MWEB fee".into(),
        ));
    }
    if !kernel.pegouts.is_empty() {
        return Err(WalletError::Mweb(
            "peg-in kernel must not contain peg-outs".into(),
        ));
    }
    if outputs.len() != 1 {
        return Err(WalletError::Mweb(
            "peg-in must produce exactly one owned MWEB coin".into(),
        ));
    }
    let credit = pegin_amount_sats - mweb_fee_sats;
    let coin = &outputs[0];
    if coin.amount != credit {
        return Err(WalletError::Mweb(format!(
            "peg-in credited MWEB coin ({}) does not equal pegin_amount - mweb_fee ({credit})",
            coin.amount
        )));
    }
    let expected_commit = bdk_mweb::crypto::switch_commit(&coin.blind, coin.amount, secp)
        .map_err(|e| WalletError::Mweb(e.to_string()))?;
    if coin.commitment != expected_commit || mw.body.outputs[0].commitment != expected_commit {
        return Err(WalletError::Mweb(
            "peg-in output commitment does not open to credited amount and blind".into(),
        ));
    }
    Ok(())
}

/// Verify structural, policy, commitment, and value conservation invariants on a signed MWEB
/// transaction (`mweb_send`, `pegout`, `mweb_split`, `self_spend`).
#[allow(clippy::too_many_arguments)]
pub fn verify_mweb_spend_tx(
    tx: &Transaction,
    spent_coins: &[MwebCoin],
    recipient_amounts: &[u64],
    expected_pegouts: &[(ScriptBuf, u64)],
    fee_sats: u64,
    owned_outputs: &[MwebCoin],
    secp: &Secp256k1<All>,
) -> Result<(), WalletError> {
    if !tx.input.is_empty() || !tx.output.is_empty() || tx.is_hog_ex {
        return Err(WalletError::Mweb(
            "pure MWEB transaction must have empty transparent vin/vout and is_hog_ex=false".into(),
        ));
    }
    let mw = tx
        .mw_tx
        .as_ref()
        .ok_or_else(|| WalletError::Mweb("MWEB transaction is missing mw_tx".into()))?;
    if spent_coins.is_empty() || mw.body.inputs.len() != spent_coins.len() {
        return Err(WalletError::Mweb(
            "MWEB input count does not match spent coins".into(),
        ));
    }
    if mw.body.kernels.len() != 1 {
        return Err(WalletError::Mweb(
            "MWEB transaction must have exactly 1 kernel".into(),
        ));
    }

    let mut seen_inputs = HashSet::with_capacity(spent_coins.len());
    for coin in spent_coins {
        if !seen_inputs.insert(coin.output_id) {
            return Err(WalletError::BuildTx(
                "duplicate MWEB input coin in transaction".into(),
            ));
        }
    }
    for win in mw.body.inputs.windows(2) {
        if win[0].output_id >= win[1].output_id {
            return Err(WalletError::Mweb(
                "MWEB wire inputs are not strictly sorted by output_id".into(),
            ));
        }
    }
    for win in mw.body.outputs.windows(2) {
        if bdk_mweb::output_id(&win[0]) >= bdk_mweb::output_id(&win[1]) {
            return Err(WalletError::Mweb(
                "MWEB wire outputs are not strictly sorted by output_id".into(),
            ));
        }
    }

    let in_total = checked_sum_sats(spent_coins.iter().map(|c| c.amount), "MWEB input total")?;
    let recip_total = checked_sum_sats(recipient_amounts.iter().copied(), "MWEB recipient total")?;
    for &amt in recipient_amounts {
        if amt == 0 {
            return Err(WalletError::BuildTx(
                "MWEB output amount must be greater than zero".into(),
            ));
        }
    }
    let pegout_total = checked_sum_sats(
        expected_pegouts.iter().map(|(_, a)| *a),
        "MWEB peg-out total",
    )?;
    let needed = checked_sum_sats([recip_total, pegout_total, fee_sats], "MWEB spend needed")?;
    let change_sats = in_total.checked_sub(needed).ok_or_else(|| {
        WalletError::BuildTx("MWEB spend outputs + fee exceed input total".into())
    })?;
    let expected_mweb_outputs = recipient_amounts.len() + usize::from(change_sats > 0);
    if mw.body.outputs.len() != expected_mweb_outputs {
        return Err(WalletError::Mweb(format!(
            "MWEB output count ({}) does not match expected ({expected_mweb_outputs})",
            mw.body.outputs.len()
        )));
    }

    bdk_mweb::policy::check_authored(
        spent_coins.len(),
        expected_mweb_outputs,
        expected_pegouts,
        fee_sats,
    )
    .map_err(|e| WalletError::BuildTx(e.to_string()))?;

    let kernel = &mw.body.kernels[0];
    if kernel.pegin.is_some() {
        return Err(WalletError::Mweb(
            "MWEB spend kernel must not carry a pegin amount".into(),
        ));
    }
    let expected_kernel_fee = (fee_sats > 0).then_some(fee_sats as i64);
    if kernel.fee != expected_kernel_fee {
        return Err(WalletError::Mweb(
            "MWEB kernel fee does not match expected fee".into(),
        ));
    }
    if kernel.pegouts.len() != expected_pegouts.len() {
        return Err(WalletError::Mweb(
            "MWEB kernel pegout count does not match expected pegouts".into(),
        ));
    }
    for (wire_po, (exp_spk, exp_amt)) in kernel.pegouts.iter().zip(expected_pegouts.iter()) {
        if wire_po.script_pub_key != *exp_spk || wire_po.amount != *exp_amt as i64 {
            return Err(WalletError::Mweb(
                "MWEB kernel pegout does not match expected script and amount".into(),
            ));
        }
    }

    for coin in owned_outputs {
        if coin.amount == 0 || coin.amount > MAX_MONEY {
            return Err(WalletError::Mweb(
                "owned MWEB output coin has invalid amount".into(),
            ));
        }
        let expected_commit = bdk_mweb::crypto::switch_commit(&coin.blind, coin.amount, secp)
            .map_err(|e| WalletError::Mweb(e.to_string()))?;
        if coin.commitment != expected_commit {
            return Err(WalletError::Mweb(
                "owned MWEB output commitment does not open to its amount and blind".into(),
            ));
        }
        if !mw
            .body
            .outputs
            .iter()
            .any(|o| bdk_mweb::output_id(o) == coin.output_id && o.commitment == expected_commit)
        {
            return Err(WalletError::Mweb(
                "owned MWEB output coin is missing from wire outputs".into(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::ScriptBuf;

    #[test]
    fn money_and_fee_rate_bounds_reject_overflow_and_extremes() {
        assert_eq!(check_money(0, "amt").unwrap(), 0);
        assert_eq!(check_money(MAX_MONEY, "amt").unwrap(), MAX_MONEY);
        assert!(check_money(MAX_MONEY + 1, "amt").is_err());
        assert!(check_money(u64::MAX, "amt").is_err());

        assert_eq!(checked_add_money(100, 200, "sum").unwrap(), 300);
        assert!(checked_add_money(MAX_MONEY, 1, "sum").is_err());
        assert!(checked_add_money(u64::MAX, 1, "sum").is_err());

        assert_eq!(neg_net_sats(0).unwrap(), 0);
        assert_eq!(neg_net_sats(MAX_MONEY).unwrap(), -(MAX_MONEY as i64));
        assert!(neg_net_sats(MAX_MONEY + 1).is_err());

        assert!(validate_fee_rate_sat_vb(0).is_err());
        assert!(validate_fee_rate_sat_vb(1).is_ok());
        assert!(validate_fee_rate_sat_vb(MAX_FEE_RATE_SAT_VB).is_ok());
        assert!(validate_fee_rate_sat_vb(MAX_FEE_RATE_SAT_VB + 1).is_err());
        assert!(validate_fee_rate_sat_vb(u64::MAX).is_err());

        assert_eq!(clamp_estimated_fee_rate(f64::NAN), 1);
        assert_eq!(clamp_estimated_fee_rate(-5.0), 1);
        assert_eq!(clamp_estimated_fee_rate(0.0), 1);
        assert_eq!(clamp_estimated_fee_rate(1.2), 2);
        assert_eq!(clamp_estimated_fee_rate(1e18), MAX_FEE_RATE_SAT_VB);
        assert_eq!(clamp_estimated_fee_rate(f64::INFINITY), 1);
    }

    #[test]
    fn dedup_helpers_preserve_first_seen_order() {
        let ids = vec![
            "AA".repeat(32),
            "bb".repeat(32),
            "aa".repeat(32),
            "  ".to_string(),
        ];
        assert_eq!(
            normalize_and_dedup_ids(Some(&ids)),
            Some(vec!["aa".repeat(32), "bb".repeat(32)])
        );
        assert_eq!(normalize_and_dedup_ids(None), None);

        let op1 = format!("{}:0", "11".repeat(32));
        let op2 = format!("{}:1", "22".repeat(32));
        let ops = parse_and_dedup_outpoints(Some(&[op1.clone(), op2.clone(), op1.clone()]))
            .unwrap()
            .unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].to_string(), op1);
        assert_eq!(ops[1].to_string(), op2);
    }

    fn p2wpkh() -> ScriptBuf {
        ScriptBuf::from_bytes([0x00, 0x14].into_iter().chain([7u8; 20]).collect())
    }

    #[test]
    fn kernel_fee_is_weight_times_100() {
        assert_eq!(min_kernel_fee(1, std::iter::empty()), 2_100);
        assert_eq!(min_kernel_fee(2, std::iter::empty()), 3_900);
        assert_eq!(
            min_kernel_fee(3, std::iter::empty()) - min_kernel_fee(2, std::iter::empty()),
            1_800
        );
        let script = p2wpkh();
        // Kernel 400 plus the 31-byte P2WPKH output and the 16-litoshi buffer.
        assert_eq!(min_kernel_fee(0, [script.as_script()]), 447);
        assert_eq!(min_kernel_fee(1, [script.as_script()]), 2_247);
        assert_eq!(
            min_kernel_fee(0, [script.as_script(), script.as_script()]),
            578
        );
    }
}

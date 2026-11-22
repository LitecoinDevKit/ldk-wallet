use bdk_electrum::electrum_client::{Client, ConfigBuilder, ElectrumApi, Param};
use bdk_electrum::BdkElectrumClient;

use crate::error::WalletError;
use crate::network::WalletNetwork;

pub const STOP_GAP: usize = 50;
/// Scripts per `blockchain.scripthash.get_history` call. A warm sync re-asks
/// for every revealed script, so a batch of 5 is one round-trip per five
/// addresses. ElectrumX accepts 50.
pub const BATCH_SIZE: usize = 50;
/// Floor when Electrum has no fee estimate (or returns an unusable value).
pub const MIN_FEE_RATE_SAT_VB: u64 = 1;
/// Target confirmation blocks for `blockchain.estimatefee`.
const FEE_ESTIMATE_BLOCKS: usize = 2;

/// Concrete client type used across the crate.
pub type ElectrumClient = BdkElectrumClient<Client>;

/// Connect to an Electrum-LTC server.
///
/// `validate_domain` controls TLS certificate validation for `ssl://` URLs:
/// when true the server must present a CA-signed certificate matching its
/// hostname (protects against man-in-the-middle attacks); when false any
/// certificate is accepted, which many community Electrum-LTC servers with
/// self-signed certificates require.
pub fn connect(url: &str, validate_domain: bool) -> Result<BdkElectrumClient<Client>, WalletError> {
    connect_with_timeout(url, validate_domain, 30)
}

/// [`connect`] with an explicit timeout (seconds). Cross-checks use a short
/// timeout so a dead second server cannot stall the sync it is auditing.
pub fn connect_with_timeout(
    url: &str,
    validate_domain: bool,
    timeout_secs: u8,
) -> Result<BdkElectrumClient<Client>, WalletError> {
    let config = ConfigBuilder::new()
        .validate_domain(validate_domain)
        .timeout(Some(timeout_secs))
        .build();
    let safe_url = crate::redact::redact_userinfo(url);
    let client = Client::from_config(url, config).map_err(|e| {
        let safe_err = crate::redact::redact_userinfo(&e.to_string());
        let mut msg =
            format!("failed to connect to {safe_url} (timed out or unreachable): {safe_err}");
        if validate_domain && url.starts_with("ssl://") {
            msg.push_str(
                "; if this server uses a self-signed certificate, disable TLS certificate \
                 validation in Settings (reduces security) or pick a CA-certified server",
            );
        }
        WalletError::Electrum(msg)
    })?;
    Ok(BdkElectrumClient::new(client))
}

/// Try each candidate URL in order; return the first server that connects *and*
/// answers a ping, along with the URL that worked.
///
/// Public Electrum-LTC servers disappear regularly, so callers should pass the
/// user-configured URL followed by [`crate::WalletNetwork::default_electrum_urls`].
pub fn connect_first(
    urls: &[String],
    validate_domain: bool,
) -> Result<(BdkElectrumClient<Client>, String), WalletError> {
    let mut errors: Vec<String> = Vec::new();
    for url in urls {
        let safe_url = crate::redact::redact_userinfo(url);
        match connect(url, validate_domain) {
            Ok(client) => match handshake(&client) {
                Ok(()) => return Ok((client, url.clone())),
                Err(e) => {
                    let safe_err = crate::redact::redact_userinfo(&e.to_string());
                    errors.push(format!(
                        "{safe_url}: connected but unresponsive ({safe_err})"
                    ));
                }
            },
            Err(e) => errors.push(format!("{safe_url}: {e}")),
        }
    }
    Err(WalletError::Electrum(format!(
        "no Electrum server reachable — {}",
        errors.join("; ")
    )))
}

/// How many blocks two servers may differ at the tip before it is suspicious
/// (normal propagation delay, not disagreement).
const TIP_LAG_TOLERANCE: u32 = 2;

/// Cross-check the chain served by `url` against our local chain after a sync.
///
/// This is deliberately privacy-preserving: only block headers are requested,
/// never our scripts, so the second server learns nothing about the wallet.
/// It catches a sync server that is on a different chain or withholding
/// blocks; it cannot catch omission of individual transactions.
///
/// Returns `Ok(None)` when consistent, `Ok(Some(warning))` on disagreement,
/// and `Err` when the second server was unreachable (callers should skip,
/// not alarm).
pub fn cross_check_tip(
    url: &str,
    validate_domain: bool,
    local_tip_height: u32,
    local_hash_at: &dyn Fn(u32) -> Option<bdk_wallet::bitcoin::BlockHash>,
) -> Result<Option<String>, WalletError> {
    let client = connect_with_timeout(url, validate_domain, 10)?;
    handshake(&client).map_err(|e| WalletError::Electrum(e.to_string()))?;
    let sub = client
        .inner
        .block_headers_subscribe()
        .map_err(|e| WalletError::Electrum(e.to_string()))?;
    let safe_url = crate::redact::redact_userinfo(url);
    let their_tip = sub.height as u32;
    if their_tip > local_tip_height.saturating_add(TIP_LAG_TOLERANCE) {
        return Ok(Some(format!(
            "cross-check: independent server {safe_url} is at height {their_tip}, {} blocks ahead of \
             the server used for this sync — that server may be lagging or withholding blocks",
            their_tip - local_tip_height
        )));
    }
    let common = local_tip_height.min(their_tip);
    let Some(local_hash) = local_hash_at(common) else {
        return Ok(None);
    };
    let their_header = client
        .inner
        .block_header(common as usize)
        .map_err(|e| WalletError::Electrum(e.to_string()))?;
    if their_header.block_hash() != local_hash {
        return Ok(Some(format!(
            "WARNING: Electrum servers disagree at height {common}: {safe_url} reports a different \
             block than the server used for this sync. One of them may be dishonest — verify \
             your balance against a block explorer or your own node before transacting"
        )));
    }
    Ok(None)
}

/// Confirm the server actually answers requests. Introduce ourselves with
/// `server.version` first: some ElectrumX deployments refuse every other call
/// until the client identifies itself. Servers that don't care about
/// identification are covered by the plain ping fallback.
fn handshake(client: &ElectrumClient) -> Result<(), bdk_electrum::electrum_client::Error> {
    let version = client.inner.raw_call(
        "server.version",
        vec![
            Param::String("ltc-wallet".into()),
            Param::String("1.4".into()),
        ],
    );
    match version {
        Ok(_) => Ok(()),
        Err(_) => client.inner.ping(),
    }
}

/// Connect, handshake, and read tip height — used by Settings “Test connection”.
/// Refuses a server on another network (genesis mismatch) or whose tip header
/// fails Litecoin proof of work.
pub fn probe_tip(
    url: &str,
    validate_domain: bool,
    network: WalletNetwork,
) -> Result<(u32, u64), WalletError> {
    let started = std::time::Instant::now();
    let client = connect_with_timeout(url, validate_domain, 15)?;
    handshake(&client).map_err(|e| WalletError::Electrum(e.to_string()))?;
    let sub = client
        .inner
        .block_headers_subscribe()
        .map_err(|e| WalletError::Electrum(e.to_string()))?;
    let tip_height = u32::try_from(sub.height)
        .map_err(|_| WalletError::Electrum(format!("tip height {} overflows u32", sub.height)))?;
    let genesis = client
        .inner
        .block_header(0)
        .map_err(|e| WalletError::Electrum(e.to_string()))?;
    crate::spv::verify_header_pow(&genesis, 0, network)?;
    crate::spv::verify_header_pow(&sub.header, tip_height, network)?;
    let latency_ms = started.elapsed().as_millis() as u64;
    Ok((tip_height, latency_ms))
}

/// Estimate a fee rate in sat/vB via Electrum `blockchain.estimatefee`.
///
/// Electrum returns LTC/kB (same units as Bitcoin Core). Values `<= 0` mean
/// the server has no estimate; we then return the floor rate.
pub fn estimate_fee_rate_sat_vb(client: &ElectrumClient) -> Result<(u64, bool), WalletError> {
    let btc_per_kb = client
        .inner
        .estimate_fee(FEE_ESTIMATE_BLOCKS)
        .map_err(|e| WalletError::Electrum(e.to_string()))?;
    if !btc_per_kb.is_finite() || btc_per_kb <= 0.0 {
        return Ok((MIN_FEE_RATE_SAT_VB, true));
    }
    // LTC/kB → litoshis/vB: * 1e8 / 1000 = * 1e5, clamped to [1, MAX_FEE_RATE_SAT_VB].
    let sat_vb = crate::tx_invariants::clamp_estimated_fee_rate(btc_per_kb * 100_000.0);
    Ok((sat_vb.max(MIN_FEE_RATE_SAT_VB), false))
}

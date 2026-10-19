//! Litview Insights: network pulse and allowlisted metric series.
//!
//! All HTTP goes through `ureq`. Wallet addresses are never uploaded.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::dto::{MetricSeries, NetworkPulse};
use crate::error::WalletError;
use crate::explorer::{self, normalize_base_url};

const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

/// Allowlisted charts shown in Insights (name, day-index series, UI title, unit hint).
/// Order matches the Insights UI slate (price featured first).
pub const CHART_ALLOWLIST: &[(&str, &str, &str, &str)] = &[
    ("price", "day", "Price", "USD"),
    ("mvrv", "day", "MVRV", "ratio"),
    ("price_drawdown", "day", "ATH drawdown", "%"),
    ("fee_median", "day", "Median fee", "sats"),
    ("tx_count_sum_24h", "day", "Tx count (24h)", "count"),
    ("hash_rate", "day", "Hash rate", "H/s"),
    ("mweb_balance", "day", "MWEB balance", "LTC"),
    (
        "mweb_pegin_count_sum_1m",
        "day",
        "MWEB peg-ins (1m)",
        "count",
    ),
];

/// Litview SPA path for a series id (see LRK `website/scripts/options/*` tree).
fn litview_chart_path(id: &str) -> String {
    match id {
        "price" => "/charts/market/price".into(),
        "mvrv" => "/charts/distribution/overview/capitalization/mvrv".into(),
        "price_drawdown" => "/charts/market/all-time-high/drawdown".into(),
        "fee_median" => "/charts/network/transactions/fee/block".into(),
        "tx_count_sum_24h" => "/charts/network/transactions/count/24h".into(),
        "hash_rate" => "/charts/mining/hashrate/current".into(),
        "mweb_balance" => "/charts/network/mweb/balance/combined".into(),
        "mweb_pegin_count_sum_1m" => "/charts/network/mweb/peg-in-count/1m".into(),
        _ => "/charts".into(),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn get_text(url: &str) -> Result<String, WalletError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(HTTP_TIMEOUT)
        .timeout_read(HTTP_TIMEOUT)
        .build();
    let resp = agent.get(url).call().map_err(|e| {
        WalletError::Insights(format!(
            "request failed: {}",
            crate::rpc::redact_userinfo(&e.to_string())
        ))
    })?;
    resp.into_string()
        .map_err(|e| WalletError::Insights(format!("read failed: {e}")))
}

fn get_json<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T, WalletError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(HTTP_TIMEOUT)
        .timeout_read(HTTP_TIMEOUT)
        .build();
    let resp = agent.get(url).call().map_err(|e| {
        WalletError::Insights(format!(
            "request failed: {}",
            crate::rpc::redact_userinfo(&e.to_string())
        ))
    })?;
    resp.into_json::<T>()
        .map_err(|e| WalletError::Insights(format!("invalid JSON: {e}")))
}

#[derive(Debug, Deserialize)]
struct MempoolStats {
    count: u64,
    vsize: u64,
}

#[derive(Debug, Deserialize)]
struct SeriesResponse {
    #[serde(default)]
    #[serde(rename = "type")]
    value_type: Option<String>,
    #[serde(default)]
    data: Vec<Option<f64>>,
}

fn tip_height(base: &str) -> Result<u32, WalletError> {
    let url = format!("{base}/api/blocks/tip/height");
    let body = get_text(&url)?;
    body.trim()
        .parse::<u32>()
        .map_err(|e| WalletError::Insights(format!("invalid tip height: {e}")))
}

fn mempool_stats(base: &str) -> Result<MempoolStats, WalletError> {
    let url = format!("{base}/api/mempool");
    get_json(&url)
}

fn fetch_series_raw(
    base: &str,
    name: &str,
    index: &str,
    start: i64,
) -> Result<SeriesResponse, WalletError> {
    let url = format!("{base}/api/series/{name}/{index}?start={start}");
    get_json(&url)
}

fn values_from_series(raw: &SeriesResponse) -> Vec<f64> {
    raw.data.iter().filter_map(|v| *v).collect()
}

fn pct_change(values: &[f64]) -> Option<f64> {
    let first = values
        .first()
        .copied()
        .filter(|v| v.is_finite() && *v != 0.0)?;
    let last = values.last().copied().filter(|v| v.is_finite())?;
    Some(((last - first) / first) * 100.0)
}

/// Aggregate litview endpoints used by the Balance pulse and Insights header.
/// Independent requests run in parallel.
pub fn fetch_network_pulse(base: &str) -> Result<NetworkPulse, WalletError> {
    let base = normalize_base_url(base)?;

    let tip_h = std::thread::scope(|s| {
        let b = &base;
        let tip = s.spawn(|| tip_height(b));
        let price = s.spawn(|| explorer::fetch_spot_price(b));
        let fees = s.spawn(|| explorer::fetch_fee_ladder(b));
        let mempool = s.spawn(|| mempool_stats(b));
        let change = s.spawn(|| fetch_series_raw(b, "price", "day", -2));

        let tip_height = tip
            .join()
            .map_err(|_| WalletError::Insights("tip height request panicked".into()))??;
        let price_usd = price
            .join()
            .map_err(|_| WalletError::Insights("price request panicked".into()))?
            .map_err(|e| WalletError::Insights(e.to_string()))?;
        let fees = fees
            .join()
            .map_err(|_| WalletError::Insights("fees request panicked".into()))?
            .map_err(|e| WalletError::Insights(e.to_string()))?;
        let mempool = mempool
            .join()
            .map_err(|_| WalletError::Insights("mempool request panicked".into()))??;
        let price_change_pct = change
            .join()
            .ok()
            .and_then(Result::ok)
            .map(|series| values_from_series(&series))
            .and_then(|v| pct_change(&v));

        Ok::<_, WalletError>(NetworkPulse {
            tip_height,
            price_usd,
            price_change_pct,
            fastest_fee_sat_vb: fees.fastest_sat_vb,
            half_hour_fee_sat_vb: fees.half_hour_sat_vb,
            mempool_tx_count: mempool.count,
            mempool_vsize: mempool.vsize,
            fetched_at_unix: now_unix(),
        })
    })?;

    Ok(tip_h)
}

fn series_to_metric(
    id: &str,
    title: &str,
    unit: &str,
    index: &str,
    raw: SeriesResponse,
) -> MetricSeries {
    let values = values_from_series(&raw);
    let latest = values.last().copied();
    let change_pct = pct_change(&values);
    let unit = raw
        .value_type
        .filter(|s| !s.is_empty() && s != "None")
        .unwrap_or_else(|| unit.to_string());
    MetricSeries {
        id: id.to_string(),
        title: title.to_string(),
        unit,
        index: index.to_string(),
        values,
        latest,
        change_pct,
        litview_path: litview_chart_path(id),
    }
}

/// Fetch allowlisted day-series charts in parallel. Soft-skips metrics that fail.
pub fn fetch_insight_charts(base: &str) -> Result<Vec<MetricSeries>, WalletError> {
    let base = normalize_base_url(base)?;
    let out = std::thread::scope(|s| {
        let handles: Vec<_> = CHART_ALLOWLIST
            .iter()
            .map(|&(name, index, title, unit)| {
                let base = &base;
                s.spawn(move || {
                    fetch_series_raw(base, name, index, -30)
                        .map(|raw| series_to_metric(name, title, unit, index, raw))
                })
            })
            .collect();

        let mut series = Vec::with_capacity(CHART_ALLOWLIST.len());
        for handle in handles {
            if let Ok(Ok(metric)) = handle.join() {
                series.push(metric);
            }
        }
        series
    });

    if out.is_empty() {
        return Err(WalletError::Insights(
            "could not load any insight charts from the explorer".into(),
        ));
    }
    Ok(out)
}

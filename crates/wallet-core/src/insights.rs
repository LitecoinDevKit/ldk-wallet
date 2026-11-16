//! Litview Insights: network pulse and allowlisted metric series.
//!
//! All HTTP goes through `ureq`. Wallet addresses are never uploaded.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::dto::{MetricSeries, NetworkPulse};
use crate::error::WalletError;
use crate::explorer::{self, normalize_base_url};

const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

/// Litview daily series index.
const DAY_INDEX: &str = "day1";

/// One allowlisted Insights chart.
pub struct ChartSpec {
    /// Stable id the UI keys ordering and formatting on.
    pub id: &'static str,
    /// Litview series name; may change between LRK releases while `id` stays.
    pub series: &'static str,
    pub title: &'static str,
    pub unit: &'static str,
}

const fn chart(
    id: &'static str,
    series: &'static str,
    title: &'static str,
    unit: &'static str,
) -> ChartSpec {
    ChartSpec {
        id,
        series,
        title,
        unit,
    }
}

/// Allowlisted charts shown in Insights, all read at [`DAY_INDEX`].
/// Order matches the Insights UI slate (price featured first).
pub const CHART_ALLOWLIST: &[ChartSpec] = &[
    chart("price", "price", "Price", "USD"),
    chart("mvrv", "mvrv", "MVRV", "ratio"),
    chart("price_drawdown", "price_drawdown", "ATH drawdown", "%"),
    chart("fee_median", "tx_fee_median", "Median fee", "sats"),
    chart(
        "tx_count_sum_24h",
        "tx_count_sum_24h",
        "Tx count (24h)",
        "count",
    ),
    chart("hash_rate", "hashrate", "Hash rate", "H/s"),
    chart("mweb_balance", "mweb_supply", "MWEB balance", "LTC"),
    chart(
        "mweb_pegin_count_sum_1m",
        "mweb_peg_in_output_count_sum_1m",
        "MWEB peg-ins (1m)",
        "count",
    ),
];

/// Litview Studio link that draws `spec`'s series (`/studio/#chart=` + chart JSON).
fn litview_chart_path(spec: &ChartSpec) -> String {
    let chart = serde_json::json!({
        "title": spec.title,
        "index": DAY_INDEX,
        "layers": [{ "series": spec.series }],
    });
    format!(
        "/studio/#chart={}",
        explorer::percent_encode(&chart.to_string())
    )
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
        let change = s.spawn(|| fetch_series_raw(b, "price", DAY_INDEX, -2));

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

fn series_to_metric(spec: &ChartSpec, raw: SeriesResponse) -> MetricSeries {
    let values = values_from_series(&raw);
    let latest = values.last().copied();
    let change_pct = pct_change(&values);
    MetricSeries {
        id: spec.id.to_string(),
        title: spec.title.to_string(),
        unit: spec.unit.to_string(),
        index: DAY_INDEX.to_string(),
        values,
        latest,
        change_pct,
        litview_path: litview_chart_path(spec),
    }
}

/// Fetch allowlisted day-series charts in parallel. Soft-skips metrics that fail.
pub fn fetch_insight_charts(base: &str) -> Result<Vec<MetricSeries>, WalletError> {
    let base = normalize_base_url(base)?;
    let out = std::thread::scope(|s| {
        let handles: Vec<_> = CHART_ALLOWLIST
            .iter()
            .map(|spec| {
                let base = &base;
                s.spawn(move || {
                    fetch_series_raw(base, spec.series, DAY_INDEX, -30)
                        .map(|raw| series_to_metric(spec, raw))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_ids_map_to_current_litview_series() {
        let pairs: Vec<(&str, &str)> = CHART_ALLOWLIST
            .iter()
            .map(|spec| (spec.id, spec.series))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("price", "price"),
                ("mvrv", "mvrv"),
                ("price_drawdown", "price_drawdown"),
                ("fee_median", "tx_fee_median"),
                ("tx_count_sum_24h", "tx_count_sum_24h"),
                ("hash_rate", "hashrate"),
                ("mweb_balance", "mweb_supply"),
                ("mweb_pegin_count_sum_1m", "mweb_peg_in_output_count_sum_1m"),
            ]
        );
        assert_eq!(DAY_INDEX, "day1");
    }

    #[test]
    fn chart_links_open_their_series_in_studio() {
        let spec = &CHART_ALLOWLIST[0];
        assert_eq!(
            litview_chart_path(spec),
            "/studio/#chart=%7B%22index%22%3A%22day1%22%2C%22layers%22%3A%5B%7B%22series%22%3A%22price%22%7D%5D%2C%22title%22%3A%22Price%22%7D"
        );
        for spec in CHART_ALLOWLIST {
            let path = litview_chart_path(spec);
            assert!(path.starts_with("/studio/#chart="), "{}", spec.id);
            assert!(
                path.contains(&format!("%22series%22%3A%22{}%22", spec.series)),
                "{}",
                spec.id
            );
        }
    }
}

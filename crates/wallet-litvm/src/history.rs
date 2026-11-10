//! Native zkLTC transfers between EOAs do not emit logs, so `eth_getLogs` is
//! blind to them. Activity is Blockscout `txlist` only — never the RPC.

use serde::Deserialize;

use crate::amount::format_zkltc;
use crate::dto::{LitVmHistoryPage, LitVmHistoryTx};
use crate::error::LitVmError;
use crate::network::LitVmNetwork;

#[derive(Debug, Deserialize)]
struct TxListResponse {
    status: Option<String>,
    message: Option<String>,
    result: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TxRow {
    hash: Option<String>,
    from: Option<String>,
    to: Option<String>,
    value: Option<String>,
    nonce: Option<String>,
    #[serde(rename = "timeStamp")]
    time_stamp: Option<String>,
    txreceipt_status: Option<String>,
}

pub fn fetch_txlist(
    network: &LitVmNetwork,
    address: &str,
) -> Result<LitVmHistoryPage, LitVmError> {
    let base = network
        .history_api
        .as_deref()
        .unwrap_or(&network.explorer);
    let url = if base.contains("action=txlist") {
        format!("{base}&address={address}&sort=desc&page=1&offset=50")
    } else {
        format!(
            "{}/api?module=account&action=txlist&address={address}&sort=desc&page=1&offset=50",
            network.explorer.trim_end_matches('/')
        )
    };
    let body = match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
    {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| LitVmError::History(e.to_string()))?,
        Err(e) => {
            return Ok(LitVmHistoryPage {
                txs: Vec::new(),
                warning: Some(history_unavailable(&e.to_string())),
            });
        }
    };
    parse_txlist(&body, address)
}

/// User-facing indexer failure. ureq's Display includes the request URL, which
/// embeds the wallet address and blows out the activity pane.
fn history_unavailable(err: &str) -> String {
    let lower = err.to_ascii_lowercase();
    let reason = if lower.contains("timed out") || lower.contains("timeout") {
        "timed out"
    } else {
        "could not be reached"
    };
    format!("Explorer index {reason}. Open the explorer for this address.")
}

fn parse_txlist(body: &str, address: &str) -> Result<LitVmHistoryPage, LitVmError> {
    let parsed: TxListResponse = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(_) => {
            return Ok(LitVmHistoryPage {
                txs: Vec::new(),
                warning: Some(
                    "Explorer index returned an unexpected response. Open the explorer."
                        .into(),
                ),
            });
        }
    };
    if parsed.status.as_deref() != Some("1") {
        let msg = parsed
            .message
            .unwrap_or_else(|| "history indexer unavailable".into());
        if msg.to_ascii_lowercase().contains("no transaction") {
            return Ok(LitVmHistoryPage {
                txs: Vec::new(),
                warning: None,
            });
        }
        return Ok(LitVmHistoryPage {
            txs: Vec::new(),
            warning: Some(format!(
                "{msg}. Open the explorer if you just sent a transaction."
            )),
        });
    }
    let rows: Vec<TxRow> = match parsed.result {
        Some(serde_json::Value::Array(arr)) => {
            serde_json::from_value(serde_json::Value::Array(arr))
                .map_err(|e| LitVmError::History(e.to_string()))?
        }
        _ => {
            return Ok(LitVmHistoryPage {
                txs: Vec::new(),
                warning: None,
            });
        }
    };
    let mine = address.to_ascii_lowercase();
    let txs = rows
        .into_iter()
        .filter_map(|row| {
            let txid = row.hash?;
            let from = row.from.unwrap_or_default();
            let to = row.to.unwrap_or_default();
            let value = row
                .value
                .as_deref()
                .and_then(|v| alloy::primitives::U256::from_str_radix(v, 10).ok())
                .unwrap_or_default();
            let nonce = row
                .nonce
                .as_deref()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            let timestamp = row.time_stamp.and_then(|t| t.parse().ok());
            let status = row.txreceipt_status.as_deref().map(str::trim);
            let failed = status == Some("0");
            // Pending = no receipt yet. Failed (0) and success (1) are settled.
            let pending = status.map(|s| s.is_empty()).unwrap_or(true) && !failed;
            Some(LitVmHistoryTx {
                incoming: to.to_ascii_lowercase() == mine,
                txid,
                from,
                to,
                amount_zkltc: format_zkltc(value),
                pending,
                failed,
                nonce,
                timestamp,
            })
        })
        .collect();
    Ok(LitVmHistoryPage { txs, warning: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "0xf39Fd6e51aad88F6F6ce6aB8827279cffFb92266";

    fn row(status: &str) -> String {
        format!(
            r#"{{
              "status":"1",
              "message":"OK",
              "result":[{{
                "hash":"0xabc",
                "from":"{ME}",
                "to":"0x1111111111111111111111111111111111111111",
                "value":"1000000000000000000",
                "nonce":"3",
                "timeStamp":"1",
                "txreceipt_status":"{status}"
              }}]
            }}"#
        )
    }

    #[test]
    fn receipt_zero_is_failed_not_pending() {
        let page = parse_txlist(&row("0"), ME).unwrap();
        assert_eq!(page.txs.len(), 1);
        assert!(page.txs[0].failed);
        assert!(!page.txs[0].pending);
    }

    #[test]
    fn empty_status_is_pending() {
        let page = parse_txlist(&row(""), ME).unwrap();
        assert!(page.txs[0].pending);
        assert!(!page.txs[0].failed);
    }

    #[test]
    fn receipt_one_is_confirmed() {
        let page = parse_txlist(&row("1"), ME).unwrap();
        assert!(!page.txs[0].pending);
        assert!(!page.txs[0].failed);
    }

    #[test]
    fn history_unavailable_drops_request_url() {
        let raw = "https://liteforge.explorer.caldera.xyz/api?module=account&action=txlist&address=0xabc Network Error: timed out reading response";
        let msg = history_unavailable(raw);
        assert!(!msg.contains("http"));
        assert!(!msg.contains("0xabc"));
        assert!(msg.contains("timed out"));
        assert!(msg.contains("explorer"));
    }

    #[test]
    fn indexer_miss_is_warning_not_empty_success() {
        let body = r#"{"status":"0","message":"Internal server error","result":null}"#;
        let page = parse_txlist(body, ME).unwrap();
        assert!(page.txs.is_empty());
        assert!(page.warning.as_deref().unwrap().contains("explorer"));
    }

    #[test]
    fn no_transactions_is_empty_without_warning() {
        let body = r#"{"status":"0","message":"No transactions found","result":[]}"#;
        let page = parse_txlist(body, ME).unwrap();
        assert!(page.txs.is_empty());
        assert!(page.warning.is_none());
    }
}

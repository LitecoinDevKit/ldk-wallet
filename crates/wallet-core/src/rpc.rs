use base64::Engine;
use serde_json::json;

use crate::error::WalletError;

/// Broadcast a raw transaction via litecoind `sendrawtransaction`.
/// Returns the node response string (txid or wtxid depending on node/tx type).
///
/// Authentication: credentials embedded in the URL (`http://user:pass@host:port`)
/// take precedence. Without them, falls back to the litecoind `.cookie` file in
/// the default data directory, so a bare `http://127.0.0.1:9332` works with a
/// stock local node even though the cookie rotates on every node restart.
pub fn send_raw_transaction(rpc_url: &str, tx_hex: &str) -> Result<String, WalletError> {
    let value = rpc_call(rpc_url, "sendrawtransaction", json!([tx_hex]))?;
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| WalletError::Rpc("missing result from sendrawtransaction".into()))
}

/// Fetch a raw transaction hex via litecoind `getrawtransaction`.
pub fn get_raw_transaction_hex(rpc_url: &str, txid: &str) -> Result<String, WalletError> {
    raw_transaction_hex(rpc_url, txid, None)
}

/// [`get_raw_transaction_hex`] with a bound on connect and read. Peg-in repair
/// uses this so a dead local node cannot stall a sync for ureq's default.
pub fn get_raw_transaction_hex_within(
    rpc_url: &str,
    txid: &str,
    timeout: std::time::Duration,
) -> Result<String, WalletError> {
    raw_transaction_hex(rpc_url, txid, Some(timeout))
}

fn raw_transaction_hex(
    rpc_url: &str,
    txid: &str,
    timeout: Option<std::time::Duration>,
) -> Result<String, WalletError> {
    let value = rpc_call_timeout(rpc_url, "getrawtransaction", json!([txid, false]), timeout)?;
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| WalletError::Rpc("missing result from getrawtransaction".into()))
}

/// Transaction ids currently in the node mempool.
pub fn get_raw_mempool(rpc_url: &str) -> Result<Vec<String>, WalletError> {
    let value = rpc_call(rpc_url, "getrawmempool", json!([false]))?;
    value
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|id| id.as_str().map(|s| s.to_string()))
                .collect()
        })
        .ok_or_else(|| WalletError::Rpc("missing result from getrawmempool".into()))
}

/// Current chain tip height from litecoind `getblockcount`.
pub fn get_block_count(rpc_url: &str) -> Result<u32, WalletError> {
    let value = rpc_call(rpc_url, "getblockcount", json!([]))?;
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| WalletError::Rpc("missing result from getblockcount".into()))
}

fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, WalletError> {
    rpc_call_timeout(rpc_url, method, params, None)
}

fn rpc_call_timeout(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
    timeout: Option<std::time::Duration>,
) -> Result<serde_json::Value, WalletError> {
    let rpc_url = &normalize_rpc_url(rpc_url);
    let body = json!({
        "jsonrpc": "1.0",
        "id": "ltc-wallet",
        "method": method,
        "params": params,
    });
    let mut request = ureq::post(rpc_url).set("Content-Type", "application/json");
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    if !url_has_credentials(rpc_url) {
        if let Some(cookie) = read_default_cookie() {
            let encoded = base64::engine::general_purpose::STANDARD.encode(cookie);
            request = request.set("Authorization", &format!("Basic {encoded}"));
        }
    }
    let value: serde_json::Value = match request.send_json(body) {
        Ok(resp) => resp
            .into_json()
            .map_err(|e| WalletError::Rpc(e.to_string()))?,
        // litecoind reports JSON-RPC failures (e.g. rejected txs) as HTTP 500
        // with the real reason in the body; surface that instead of the status.
        Err(ureq::Error::Status(code, resp)) => match resp.into_json::<serde_json::Value>() {
            Ok(v) => v,
            Err(_) => {
                let hint = if code == 401 {
                    " (authentication failed — set rpcuser/rpcpassword in litecoin.conf or use http://user:pass@host:port)"
                } else {
                    ""
                };
                return Err(WalletError::Rpc(format!("http status {code}{hint}")));
            }
        },
        // ureq errors embed the request URL, which may carry user:pass userinfo.
        Err(e) => return Err(WalletError::Rpc(redact_userinfo(&e.to_string()))),
    };
    if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .map(|m| m.to_string())
            .unwrap_or_else(|| err.to_string());
        let msg = if method == "sendrawtransaction" {
            crate::error::humanize_broadcast_error(&msg)
        } else {
            crate::redact::scrub_log_line(&msg)
        };
        return Err(WalletError::Rpc(msg));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| WalletError::Rpc(format!("missing result from {method}")))
}

/// Prepend `http://` when the URL has no scheme (e.g. a bare `127.0.0.1:9332`),
/// which ureq would otherwise reject as a relative URL.
pub fn normalize_rpc_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

/// Strip `user:pass@` userinfo from any URL embedded in `msg` so RPC
/// credentials never reach logs or UI error text.
pub(crate) fn redact_userinfo(msg: &str) -> String {
    crate::redact::redact_userinfo(msg)
}

/// True when the URL authority contains userinfo (`scheme://user:pass@host`).
fn url_has_credentials(url: &str) -> bool {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority.contains('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_adds_scheme_when_missing() {
        assert_eq!(normalize_rpc_url("127.0.0.1:9332"), "http://127.0.0.1:9332");
        assert_eq!(
            normalize_rpc_url(" 127.0.0.1:9332 "),
            "http://127.0.0.1:9332"
        );
        assert_eq!(
            normalize_rpc_url("http://127.0.0.1:9332"),
            "http://127.0.0.1:9332"
        );
        assert_eq!(
            normalize_rpc_url("https://user:pass@host:9332"),
            "https://user:pass@host:9332"
        );
        assert_eq!(normalize_rpc_url(""), "");
    }

    #[test]
    fn redacts_userinfo_in_error_text() {
        assert_eq!(
            redact_userinfo("http://user:secret@127.0.0.1:9332/: Connection Failed"),
            "http://[redacted]@127.0.0.1:9332/: Connection Failed"
        );
        assert_eq!(
            redact_userinfo("error at https://host:9332/path"),
            "error at https://host:9332/path"
        );
        assert_eq!(redact_userinfo("no url here"), "no url here");
    }

    #[test]
    fn detects_url_credentials() {
        assert!(url_has_credentials("http://user:pass@127.0.0.1:9332"));
        assert!(!url_has_credentials("http://127.0.0.1:9332"));
        assert!(!url_has_credentials("http://127.0.0.1:9332/path?a=b@c"));
    }

    #[test]
    fn audit_f9a_non_loopback_rpc_must_not_attach_local_mainnet_cookie() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::{TcpListener, UdpSocket};

        if let Ok(target_url) = std::env::var("LDK_AUDIT_F9A_RPC_URL") {
            let _ = get_block_count(&target_url);
            return;
        }

        let probe = UdpSocket::bind("0.0.0.0:0").unwrap();
        probe.connect("198.51.100.1:80").unwrap();
        let lan_ip = probe.local_addr().unwrap().ip();
        assert!(
            !lan_ip.is_loopback(),
            "expected non-loopback local interface IP, got {lan_ip}"
        );

        let fake_home = tempfile::tempdir().unwrap();
        for rel in ["Library/Application Support/Litecoin", ".litecoin"] {
            let cookie_dir = fake_home.path().join(rel);
            std::fs::create_dir_all(&cookie_dir).unwrap();
            std::fs::write(
                cookie_dir.join(".cookie"),
                "__cookie__:secret-mainnet-cookie-token\n",
            )
            .unwrap();
        }

        let listener = TcpListener::bind((lan_ip, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
                headers.push_str(&line);
            }
            let body = br#"{"result":100,"error":null,"id":"ltc-wallet"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let mut writer = stream;
            let _ = writer.write_all(resp.as_bytes());
            let _ = writer.write_all(body);
            headers
        });

        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("rpc::tests::audit_f9a_non_loopback_rpc_must_not_attach_local_mainnet_cookie")
            .arg("--nocapture")
            .env("HOME", fake_home.path())
            .env("LDK_AUDIT_F9A_RPC_URL", format!("http://{addr}"))
            .status()
            .unwrap();
        assert!(status.success());

        let captured_headers = handle.join().unwrap();
        assert!(
            !captured_headers
                .to_ascii_lowercase()
                .contains("authorization:"),
            "local Mainnet .cookie Basic auth leaked to non-loopback RPC host {addr}:\n{captured_headers}"
        );
    }
}

/// Read `__cookie__:<token>` from the default litecoind mainnet data directory
/// (macOS Application Support, then Linux `~/.litecoin`).
fn read_default_cookie() -> Option<String> {
    let home = std::env::var_os("HOME")?;
    let home = std::path::PathBuf::from(home);
    let candidates = [
        home.join("Library/Application Support/Litecoin/.cookie"),
        home.join(".litecoin/.cookie"),
    ];
    candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

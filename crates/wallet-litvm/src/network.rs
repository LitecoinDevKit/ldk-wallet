use serde::{Deserialize, Serialize};

pub const LITEFORGE_CHAIN_ID: u64 = 4441;
pub const LITEFORGE_RPC_HTTP: &str = "https://liteforge.rpc.caldera.xyz/http";
pub const LITEFORGE_EXPLORER: &str = "https://liteforge.explorer.caldera.xyz";
pub const LITEFORGE_FAUCET: &str = "https://testnet.litvm.com";
pub const SETTINGS_FILE: &str = "litvm.json";

/// Per-gas headroom for Orbit's L2 + L1-calldata fee. Honest L1 spikes can
/// push the synthesized L2 gas price well above a few gwei.
pub const MAX_FEE_GWEI: u128 = 10_000;
pub const MAX_PRIORITY_GWEI: u128 = 500;
/// Drain brake: `gas_limit * max_fee_per_gas` must stay under 0.05 zkLTC.
pub const MAX_TOTAL_FEE_WEI: u128 = 50_000_000_000_000_000;
pub const MAX_GAS_LIMIT: u64 = 2_000_000;
pub const GAS_PAD_BPS: u64 = 2_000; // +20%

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LitVmNetwork {
    pub id: String,
    pub display_name: String,
    pub chain_id: u64,
    pub rpc_http: String,
    pub rpc_ws: Option<String>,
    pub explorer: String,
    pub history_api: Option<String>,
    pub symbol: String,
    pub decimals: u8,
    pub faucet_url: Option<String>,
}

impl LitVmNetwork {
    pub fn liteforge() -> Self {
        Self {
            id: "liteforge".into(),
            display_name: "LitVM LiteForge".into(),
            chain_id: LITEFORGE_CHAIN_ID,
            rpc_http: LITEFORGE_RPC_HTTP.into(),
            rpc_ws: Some("wss://liteforge.rpc.caldera.xyz/ws".into()),
            explorer: LITEFORGE_EXPLORER.into(),
            history_api: Some(format!(
                "{LITEFORGE_EXPLORER}/api?module=account&action=txlist"
            )),
            symbol: "zkLTC".into(),
            decimals: 18,
            faucet_url: Some(LITEFORGE_FAUCET.into()),
        }
    }

    pub fn by_id(id: &str) -> Option<Self> {
        match id {
            "liteforge" => Some(Self::liteforge()),
            _ => None,
        }
    }
}

/// Strip `user:pass@` userinfo from any URL embedded in `msg`.
pub(crate) fn redact_userinfo(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(idx) = rest.find("://") {
        let (head, tail) = rest.split_at(idx + 3);
        out.push_str(head);
        let authority_end = tail
            .find([
                '/', '?', '#', ' ', '\t', '\n', '\r', ')', ']', '}', '"', '\'', ',', ';',
            ])
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        if let Some(at) = authority.rfind('@') {
            out.push_str("[redacted]@");
            out.push_str(&authority[at + 1..]);
        } else {
            out.push_str(authority);
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LitVmSettingsFile {
    #[serde(default = "default_network_id")]
    pub network_id: String,
    #[serde(default)]
    pub rpc_http_override: Option<String>,
}

impl std::fmt::Debug for LitVmSettingsFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LitVmSettingsFile")
            .field("network_id", &self.network_id)
            .field(
                "rpc_http_override",
                &self.rpc_http_override.as_deref().map(redact_userinfo),
            )
            .finish()
    }
}

fn default_network_id() -> String {
    "liteforge".into()
}

impl Default for LitVmSettingsFile {
    fn default() -> Self {
        Self {
            network_id: default_network_id(),
            rpc_http_override: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LitVmSettings {
    pub network: LitVmNetwork,
    pub rpc_http: String,
    pub rpc_http_override: Option<String>,
    pub signing_enabled: bool,
}

impl std::fmt::Debug for LitVmSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LitVmSettings")
            .field("network", &self.network)
            .field("rpc_http", &redact_userinfo(&self.rpc_http))
            .field(
                "rpc_http_override",
                &self.rpc_http_override.as_deref().map(redact_userinfo),
            )
            .field("signing_enabled", &self.signing_enabled)
            .finish()
    }
}

impl LitVmSettings {
    pub fn from_file(file: &LitVmSettingsFile, signing_enabled: bool) -> Result<Self, String> {
        let network = LitVmNetwork::by_id(&file.network_id)
            .ok_or_else(|| format!("unknown LitVM network {}", file.network_id))?;
        let rpc_http = file
            .rpc_http_override
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| network.rpc_http.clone());
        Ok(Self {
            network,
            rpc_http,
            rpc_http_override: file.rpc_http_override.clone(),
            signing_enabled,
        })
    }
}

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use alloy::consensus::Transaction as _;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use zeroize::Zeroize;

use crate::address::{format_address, parse_evm_address};
use crate::amount::{format_zkltc, parse_zkltc};
use crate::dto::{
    LitVmHistoryPage, LitVmHistoryTx, LitVmProbe, LitVmReplaceRequest, LitVmSendPreview,
    LitVmSendRequest, LitVmSendResult, LitVmSummary, UpdateLitVmSettingsRequest,
};
use crate::error::LitVmError;
use crate::fees::{bump_eip1559, cap_max_fee_gwei, cap_priority_gwei, check_total_fee};
use crate::history::fetch_txlist;
use crate::network::{
    LitVmNetwork, LitVmSettings, LitVmSettingsFile, GAS_PAD_BPS, MAX_GAS_LIMIT,
};
use crate::settings::{load_settings_file, save_settings_file};

const RECEIPT_POLL_MS: u64 = 250;
const RECEIPT_POLL_ATTEMPTS: u32 = 8; // ~2s

pub struct LitVmClient {
    runtime: tokio::runtime::Runtime,
    data_dir: PathBuf,
    signer: PrivateKeySigner,
    address: Address,
    network: LitVmNetwork,
    rpc_http: String,
    rpc_override: Option<String>,
    signing_enabled: bool,
    local_pending: Mutex<Vec<LitVmHistoryTx>>,
}

impl LitVmClient {
    pub fn open(data_dir: &Path, mut secret: [u8; 32]) -> Result<Self, LitVmError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        let file = load_settings_file(data_dir)?;
        let settings = LitVmSettings::from_file(&file, false).map_err(LitVmError::Settings)?;
        let signer = PrivateKeySigner::from_slice(&secret)
            .map_err(|e| LitVmError::Rpc(e.to_string()))?
            .with_chain_id(Some(settings.network.chain_id));
        secret.zeroize();
        let address = signer.address();
        Ok(Self {
            runtime,
            data_dir: data_dir.to_path_buf(),
            signer,
            address,
            rpc_http: settings.rpc_http,
            rpc_override: settings.rpc_http_override,
            network: settings.network,
            signing_enabled: false,
            local_pending: Mutex::new(Vec::new()),
        })
    }

    pub fn address(&self) -> String {
        format_address(self.address)
    }

    pub fn settings(&self) -> LitVmSettings {
        LitVmSettings {
            network: self.network.clone(),
            rpc_http: self.rpc_http.clone(),
            rpc_http_override: self.rpc_override.clone(),
            signing_enabled: self.signing_enabled,
        }
    }

    pub fn update_settings(
        &mut self,
        req: UpdateLitVmSettingsRequest,
    ) -> Result<LitVmSettings, LitVmError> {
        let file = LitVmSettingsFile {
            network_id: self.network.id.clone(),
            rpc_http_override: req
                .rpc_http_override
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        };
        save_settings_file(&self.data_dir, &file)?;
        self.rpc_override = file.rpc_http_override.clone();
        self.rpc_http = self
            .rpc_override
            .clone()
            .unwrap_or_else(|| self.network.rpc_http.clone());
        self.signing_enabled = false;
        Ok(self.settings())
    }

    pub fn explorer_tx_url(&self, txid: &str) -> String {
        format!(
            "{}/tx/{}",
            self.network.explorer.trim_end_matches('/'),
            txid.trim()
        )
    }

    pub fn summary(&mut self) -> Result<LitVmSummary, LitVmError> {
        let _ = self.probe();
        let balance = match self.balance_wei() {
            Ok(wei) => format_zkltc(wei),
            Err(_) => "0".into(),
        };
        Ok(LitVmSummary {
            address: self.address(),
            balance_zkltc: balance,
            network_id: self.network.id.clone(),
            network_name: self.network.display_name.clone(),
            chain_id: self.network.chain_id,
            symbol: self.network.symbol.clone(),
            faucet_url: self.network.faucet_url.clone(),
            explorer: self.network.explorer.clone(),
            rpc_http: self.rpc_http.clone(),
            signing_enabled: self.signing_enabled,
            seed_note: None,
        })
    }

    pub fn probe(&mut self) -> LitVmProbe {
        match self.rpc_chain_id() {
            Ok(id) => {
                let matches = id == self.network.chain_id;
                self.signing_enabled = matches;
                LitVmProbe {
                    expected_chain_id: self.network.chain_id,
                    rpc_chain_id: Some(id),
                    rpc_http: self.rpc_http.clone(),
                    matches,
                    error: if matches {
                        None
                    } else {
                        Some(format!(
                            "RPC chain ID {id} does not match preset {}",
                            self.network.chain_id
                        ))
                    },
                }
            }
            Err(e) => {
                self.signing_enabled = false;
                LitVmProbe {
                    expected_chain_id: self.network.chain_id,
                    rpc_chain_id: None,
                    rpc_http: self.rpc_http.clone(),
                    matches: false,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    pub fn preview_send(&self, req: &LitVmSendRequest) -> Result<LitVmSendPreview, LitVmError> {
        self.ensure_signing()?;
        let to = parse_evm_address(&req.address)?;
        let (value, built) = self.resolve_send(to, req)?;
        Ok(LitVmSendPreview {
            from: self.address(),
            to: format_address(to),
            amount_zkltc: format_zkltc(value),
            fee_zkltc: format_zkltc(built.fee),
            max_fee_zkltc: format_zkltc(built.max_fee),
            nonce: built.nonce,
            gas_limit: built.gas_limit,
        })
    }

    pub fn send(&self, req: &LitVmSendRequest) -> Result<LitVmSendResult, LitVmError> {
        self.ensure_signing()?;
        let to = parse_evm_address(&req.address)?;
        let (value, built) = self.resolve_send(to, req)?;
        let txid = self.runtime.block_on(self.broadcast(built.request))?;
        let pending = !self.runtime.block_on(self.wait_for_receipt(&txid))?;
        if pending {
            self.push_local_pending(LitVmHistoryTx {
                txid: txid.clone(),
                from: self.address(),
                to: format_address(to),
                amount_zkltc: format_zkltc(value),
                incoming: false,
                pending: true,
                failed: false,
                nonce: built.nonce,
                timestamp: None,
            });
        }
        Ok(LitVmSendResult {
            txid,
            fee_zkltc: format_zkltc(built.fee),
            pending,
        })
    }

    pub fn replace_tx(&self, req: &LitVmReplaceRequest) -> Result<LitVmSendResult, LitVmError> {
        self.ensure_signing()?;
        let result = self.runtime.block_on(self.replace_tx_async(req));
        match &result {
            Ok(sent) => {
                self.drop_local_pending(&req.txid);
                if sent.pending {
                    self.push_local_pending(LitVmHistoryTx {
                        txid: sent.txid.clone(),
                        from: self.address(),
                        to: req.address.clone(),
                        amount_zkltc: req.amount_zkltc.clone(),
                        incoming: false,
                        pending: true,
                        failed: false,
                        nonce: req.nonce,
                        timestamp: None,
                    });
                }
            }
            Err(LitVmError::AlreadyConfirmed) => self.drop_local_pending(&req.txid),
            Err(_) => {}
        }
        result
    }

    pub fn history(&self) -> Result<LitVmHistoryPage, LitVmError> {
        let mut page = fetch_txlist(&self.network, &self.address())?;
        let indexed: std::collections::HashSet<String> = page
            .txs
            .iter()
            .map(|t| t.txid.to_ascii_lowercase())
            .collect();
        if let Ok(mut local) = self.local_pending.lock() {
            local.retain(|t| !indexed.contains(&t.txid.to_ascii_lowercase()));
            for tx in local.iter().rev() {
                page.txs.insert(0, tx.clone());
            }
        }
        Ok(page)
    }

    fn ensure_signing(&self) -> Result<(), LitVmError> {
        if self.signing_enabled {
            Ok(())
        } else {
            Err(LitVmError::SigningDisabled(self.network.chain_id))
        }
    }

    fn provider(&self) -> Result<impl Provider + Clone, LitVmError> {
        let url = self
            .rpc_http
            .parse()
            .map_err(|e| LitVmError::Rpc(format!("invalid RPC URL: {e}")))?;
        Ok(ProviderBuilder::new().connect_http(url))
    }

    fn rpc_chain_id(&self) -> Result<u64, LitVmError> {
        let provider = self.provider()?;
        self.runtime.block_on(async move {
            provider
                .get_chain_id()
                .await
                .map_err(|e| LitVmError::Rpc(e.to_string()))
        })
    }

    fn balance_wei(&self) -> Result<U256, LitVmError> {
        let provider = self.provider()?;
        let addr = self.address;
        self.runtime.block_on(async move {
            provider
                .get_balance(addr)
                .await
                .map_err(|e| LitVmError::Rpc(e.to_string()))
        })
    }

    /// Resolve transfer value and a built tx. Drain spends balance minus max fee.
    fn resolve_send(
        &self,
        to: Address,
        req: &LitVmSendRequest,
    ) -> Result<(U256, BuiltTx), LitVmError> {
        if !req.drain {
            let value = parse_zkltc(&req.amount_zkltc)?;
            if value.is_zero() {
                return Err(LitVmError::InvalidAmount(
                    "amount must be greater than 0".into(),
                ));
            }
            let built = self.runtime.block_on(self.build_tx(to, value, None))?;
            return Ok((value, built));
        }

        let balance = self.balance_wei()?;
        if balance.is_zero() {
            return Err(LitVmError::InvalidAmount(
                "no spendable zkLTC balance".into(),
            ));
        }
        // Probe fee with a 1-wei transfer so nodes that require balance ≥ value+gas still work.
        let probe = self
            .runtime
            .block_on(self.build_tx(to, U256::from(1u64), None))?;
        let value = balance.saturating_sub(probe.max_fee);
        if value.is_zero() {
            return Err(LitVmError::InvalidAmount(
                "balance too low to cover the LitVM fee".into(),
            ));
        }
        let built = self
            .runtime
            .block_on(self.build_tx(to, value, Some(probe.nonce)))?;
        if value.saturating_add(built.max_fee) > balance {
            let adjusted = balance.saturating_sub(built.max_fee);
            if adjusted.is_zero() {
                return Err(LitVmError::InvalidAmount(
                    "balance too low to cover the LitVM fee".into(),
                ));
            }
            let rebuilt = self
                .runtime
                .block_on(self.build_tx(to, adjusted, Some(probe.nonce)))?;
            return Ok((adjusted, rebuilt));
        }
        Ok((value, built))
    }

    fn push_local_pending(&self, tx: LitVmHistoryTx) {
        if let Ok(mut local) = self.local_pending.lock() {
            local.retain(|t| t.txid.to_ascii_lowercase() != tx.txid.to_ascii_lowercase());
            local.push(tx);
        }
    }

    fn drop_local_pending(&self, txid: &str) {
        let needle = txid.to_ascii_lowercase();
        if let Ok(mut local) = self.local_pending.lock() {
            local.retain(|t| t.txid.to_ascii_lowercase() != needle);
        }
    }

    async fn wait_for_receipt(&self, txid: &str) -> Result<bool, LitVmError> {
        let hash = parse_tx_hash(txid)?;
        let provider = self.provider()?;
        for _ in 0..RECEIPT_POLL_ATTEMPTS {
            if provider
                .get_transaction_receipt(hash)
                .await
                .map_err(|e| LitVmError::Rpc(e.to_string()))?
                .is_some()
            {
                return Ok(true);
            }
            tokio::time::sleep(Duration::from_millis(RECEIPT_POLL_MS)).await;
        }
        Ok(false)
    }

    async fn replace_tx_async(
        &self,
        req: &LitVmReplaceRequest,
    ) -> Result<LitVmSendResult, LitVmError> {
        let hash = parse_tx_hash(&req.txid)?;
        let provider = self.provider()?;
        if provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?
            .is_some()
        {
            return Err(LitVmError::AlreadyConfirmed);
        }
        let original = provider
            .get_transaction_by_hash(hash)
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?
            .ok_or_else(|| {
                LitVmError::Rpc(
                    "pending transaction not found — it may have dropped from the mempool".into(),
                )
            })?;

        let nonce = original.nonce();
        let to = original
            .to()
            .ok_or_else(|| LitVmError::Rpc("cannot replace a contract-creation tx".into()))?;
        let value = original.value();
        let gas_limit = if original.gas_limit() == 0 {
            21_000
        } else {
            original.gas_limit()
        };

        let old_max = original.max_fee_per_gas();
        let old_tip = original.priority_fee_or_price();

        let market = provider
            .estimate_eip1559_fees()
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        let max_priority = cap_priority_gwei(bump_eip1559(
            old_tip,
            market.max_priority_fee_per_gas,
        ))?;
        let max_fee = cap_max_fee_gwei(bump_eip1559(old_max, market.max_fee_per_gas))?;
        if max_fee < max_priority {
            return Err(LitVmError::FeeCap(
                "bumped max fee is below the priority fee".into(),
            ));
        }
        let total = check_total_fee(gas_limit, max_fee)?;

        let request = TransactionRequest::default()
            .with_from(self.address)
            .with_to(to)
            .with_value(value)
            .with_nonce(nonce)
            .with_chain_id(self.network.chain_id)
            .with_gas_limit(gas_limit)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(max_priority);
        let txid = self.broadcast(request).await?;
        let pending = !self.wait_for_receipt(&txid).await?;
        Ok(LitVmSendResult {
            txid,
            fee_zkltc: format_zkltc(U256::from(total)),
            pending,
        })
    }

    async fn build_tx(
        &self,
        to: Address,
        value: U256,
        nonce_override: Option<u64>,
    ) -> Result<BuiltTx, LitVmError> {
        let provider = self.provider()?;
        let nonce = match nonce_override {
            Some(n) => n,
            None => provider
                .get_transaction_count(self.address)
                .await
                .map_err(|e| LitVmError::Rpc(e.to_string()))?,
        };
        let fees = provider
            .estimate_eip1559_fees()
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        let max_priority = cap_priority_gwei(fees.max_priority_fee_per_gas)?;
        let max_fee = cap_max_fee_gwei(fees.max_fee_per_gas)?;
        if max_fee < max_priority {
            return Err(LitVmError::FeeCap(
                "max fee is below the priority fee".into(),
            ));
        }

        let draft = TransactionRequest::default()
            .with_from(self.address)
            .with_to(to)
            .with_value(value)
            .with_nonce(nonce)
            .with_chain_id(self.network.chain_id)
            .with_max_fee_per_gas(max_fee)
            .with_max_priority_fee_per_gas(max_priority);
        let gas = provider
            .estimate_gas(draft.clone())
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        let gas_limit = std::cmp::min(
            gas.saturating_add(gas.saturating_mul(GAS_PAD_BPS) / 10_000),
            MAX_GAS_LIMIT,
        );
        if gas_limit == 0 {
            return Err(LitVmError::Rpc("gas estimate was 0".into()));
        }
        let total = check_total_fee(gas_limit, max_fee)?;
        let request = draft.with_gas_limit(gas_limit);
        let fee = U256::from(total);
        Ok(BuiltTx {
            request,
            nonce,
            gas_limit,
            fee,
            max_fee: fee,
        })
    }

    async fn broadcast(&self, request: TransactionRequest) -> Result<String, LitVmError> {
        let wallet = EthereumWallet::from(self.signer.clone());
        let tx = request
            .build(&wallet)
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        let provider = self.provider()?;
        let pending = provider
            .send_tx_envelope(tx)
            .await
            .map_err(|e| LitVmError::Rpc(e.to_string()))?;
        Ok(format!("{:#x}", pending.tx_hash()))
    }
}

struct BuiltTx {
    request: TransactionRequest,
    nonce: u64,
    gas_limit: u64,
    fee: U256,
    max_fee: U256,
}

fn parse_tx_hash(txid: &str) -> Result<TxHash, LitVmError> {
    TxHash::from_str(txid.trim()).map_err(|e| LitVmError::Rpc(format!("invalid txid: {e}")))
}

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use wallet_core::{
    CreateWalletRequest, RestoreWalletRequest, SendRequest, UnlockRequest, WalletApp, WalletNetwork,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliNetwork {
    Mainnet,
    Testnet,
}

impl From<CliNetwork> for WalletNetwork {
    fn from(value: CliNetwork) -> Self {
        match value {
            CliNetwork::Mainnet => WalletNetwork::Mainnet,
            CliNetwork::Testnet => WalletNetwork::Testnet,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliMwebScheme {
    /// Litecoin Core and current LIP-0004: m/0'/100'/{0,1}'
    #[default]
    LitecoinCore,
    /// LIP-0004, updated to the implemented Core path: m/0'/100'/{0,1}'
    Lip0004,
    /// Legacy mwebd / Nexus before 2026-06-01: m/1000'/2'/0'/{0,1}'
    Mwebd,
}

impl From<CliMwebScheme> for wallet_core::MwebScheme {
    fn from(value: CliMwebScheme) -> Self {
        match value {
            CliMwebScheme::LitecoinCore => Self::LitecoinCore,
            CliMwebScheme::Lip0004 => Self::Lip0004,
            CliMwebScheme::Mwebd => Self::Mwebd,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "wallet-cli",
    about = "Litecoin wallet-core smoke CLI (Electrum mainnet by default)"
)]
struct Cli {
    /// Wallet data directory (sqlite + meta + encrypted mnemonic).
    #[arg(long, global = true, default_value = ".wallet-data")]
    data_dir: PathBuf,

    /// Passphrase for the encrypted mnemonic (prompted if omitted).
    #[arg(long, global = true)]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create a new BIP84 wallet; prints mnemonic once.
    Create {
        #[arg(long, value_enum, default_value_t = CliNetwork::Mainnet)]
        network: CliNetwork,
        #[arg(long)]
        electrum: Option<String>,
    },
    /// Restore a wallet from a seed (BIP39/aezeed words or a root xprv/zprv).
    Restore {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, value_enum, default_value_t = CliNetwork::Mainnet)]
        network: CliNetwork,
        #[arg(long)]
        electrum: Option<String>,
        /// MWEB key-derivation scheme. The default is Litecoin Core's path
        /// (LIP-0004 follows it). mwebd is only for Nexus seeds created
        /// before 2026-06-01.
        #[arg(long, value_enum, default_value_t = CliMwebScheme::LitecoinCore)]
        mweb_scheme: CliMwebScheme,
        /// aezeed cipher-seed passphrase, if one was set.
        #[arg(long)]
        aezeed_passphrase: Option<String>,
    },
    /// Print wallet summary JSON (transparent only).
    Summary,
    /// Print combined transparent + MWEB summary JSON (no secrets).
    CombinedSummary,
    /// List unspent MWEB coins (amounts, maturity, lock; no secrets).
    MwebUnspent,
    /// Lab-only: write scan/spend hex + ltcmweb1 dest to a chmod 600 env file.
    /// Does not print secrets. For coinswapd Proof A, not a CoinSwap UI.
    MwebCoinswapdEnv {
        /// Output path (created or overwritten, mode 0600).
        #[arg(long)]
        out: PathBuf,
    },
    /// Reveal and print a new receive address.
    Address,
    /// Sync against Electrum (full_scan first, then incremental).
    Sync,
    /// Build, sign, and broadcast a transaction.
    Send {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount_sats: Option<u64>,
        #[arg(long, default_value_t = 1)]
        fee_rate: u64,
        #[arg(long)]
        drain: bool,
    },
    /// List recent transactions.
    History,
    /// Print the addresses a seed would derive (BIP84 + MWEB under every
    /// scheme) without creating a wallet. For cross-wallet parity checks.
    Derive {
        /// Seed input: BIP39 words, aezeed words, or a root xprv/zprv/Ltpv.
        /// Read from stdin when omitted (avoids shell history).
        #[arg(long)]
        input: Option<String>,
        #[arg(long, value_enum, default_value_t = CliNetwork::Mainnet)]
        network: CliNetwork,
        /// Number of addresses to derive per chain.
        #[arg(long, default_value_t = 5)]
        count: u32,
        /// aezeed cipher-seed passphrase, if one was set (Nexus advanced setting).
        #[arg(long)]
        aezeed_passphrase: Option<String>,
    },
    /// Print the LitVM (LiteForge) 0x address derived from this wallet.
    #[cfg(feature = "litvm")]
    LitvmAddress,
    /// Probe LiteForge RPC and print zkLTC balance JSON.
    #[cfg(feature = "litvm")]
    LitvmBalance,
    /// Send native zkLTC on LiteForge.
    #[cfg(feature = "litvm")]
    LitvmSend {
        #[arg(long)]
        address: String,
        #[arg(long)]
        amount: String,
    },
    /// Offline-verify a Grail deposit offer JSON (LiteForge / testnet only).
    #[cfg(feature = "grail")]
    GrailVerify {
        #[arg(long)]
        offer: PathBuf,
    },
    /// Verify then pay a Grail deposit (stubbed until a captured offer verifies).
    #[cfg(feature = "grail")]
    GrailDeposit {
        /// Captured initiate/confirm JSON. Required until GRAIL_API_URL exists.
        #[arg(long)]
        offer: Option<PathBuf>,
        #[arg(long)]
        amount_sats: Option<u64>,
        #[arg(long, default_value_t = 1)]
        fee_rate: u64,
        /// Funding outpoints (`txid:vout`). Repeatable.
        #[arg(long)]
        outpoint: Vec<String>,
    },
}

fn read_passphrase(explicit: &Option<String>) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("WALLET_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let p = rpassword::prompt_password("Passphrase: ").context("read passphrase")?;
    if p.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(p)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone();
    std::fs::create_dir_all(&data_dir).with_context(|| format!("create {}", data_dir.display()))?;
    let app = WalletApp::new(&data_dir);
    let passphrase_opt = cli.passphrase.clone();

    match cli.command {
        Command::Create { network, electrum } => {
            let passphrase = read_passphrase(&passphrase_opt)?;
            let resp = app
                .create(
                    &data_dir,
                    CreateWalletRequest {
                        network: network.into(),
                        electrum_url: electrum,
                    },
                    &passphrase,
                )
                .context("create wallet")?;
            eprintln!("mnemonic (backup once): {}", resp.mnemonic);
            println!("{}", serde_json::to_string_pretty(&resp.summary)?);
        }
        Command::Restore {
            mnemonic,
            network,
            electrum,
            mweb_scheme,
            aezeed_passphrase,
        } => {
            let passphrase = read_passphrase(&passphrase_opt)?;
            let summary = app
                .restore(
                    &data_dir,
                    RestoreWalletRequest {
                        mnemonic,
                        network: network.into(),
                        electrum_url: electrum,
                        mweb_scheme: mweb_scheme.into(),
                        aezeed_passphrase,
                    },
                    &passphrase,
                )
                .context("restore wallet")?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::Summary => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let summary = app.summary().context("summary")?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::CombinedSummary => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let summary = app.combined_summary().context("combined-summary")?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::MwebUnspent => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let coins = app.list_mweb_unspent().context("mweb-unspent")?;
            println!("{}", serde_json::to_string_pretty(&coins)?);
        }
        Command::MwebCoinswapdEnv { out } => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let (scan, spend, dest) = app
                .export_mweb_coinswapd_secrets()
                .context("export mweb coinswapd secrets")?;
            write_coinswapd_env(&out, &scan, &spend, &dest)?;
            let dest_ok = dest.starts_with("ltcmweb1");
            eprintln!(
                "wrote {} (scan/spend omitted); dest_hrp_ok={dest_ok}",
                out.display()
            );
        }
        Command::Address => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let address = app.receive_address().context("receive address")?;
            println!("{address}");
        }
        Command::Sync => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let result = app.sync().context("sync")?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Send {
            address,
            amount_sats,
            fee_rate,
            drain,
        } => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            if !drain && amount_sats.is_none() {
                bail!("--amount-sats required unless --drain");
            }
            let result = app
                .send(SendRequest {
                    address,
                    amount_sats: amount_sats.unwrap_or(0),
                    fee_rate_sat_vb: Some(fee_rate),
                    drain,
                    selected_outpoints: None,
                })
                .context("send")?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::History => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let txs = app.transactions().context("history")?;
            println!("{}", serde_json::to_string_pretty(&txs)?);
        }
        Command::Derive {
            input,
            network,
            count,
            aezeed_passphrase,
        } => {
            let input = match input {
                Some(i) => i,
                None => {
                    eprintln!("Enter seed (words or extended key), then press Enter:");
                    let mut line = String::new();
                    std::io::stdin()
                        .read_line(&mut line)
                        .context("read seed from stdin")?;
                    line
                }
            };
            let preview = wallet_core::derive_preview(
                &input,
                aezeed_passphrase.as_deref(),
                network.into(),
                count,
            )
            .context("derive preview")?;
            println!("{}", serde_json::to_string_pretty(&preview)?);
        }
        #[cfg(feature = "litvm")]
        Command::LitvmAddress => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let mut client = open_litvm(&app, &data_dir)?;
            println!("{}", client.address());
            let _ = client.probe();
        }
        #[cfg(feature = "litvm")]
        Command::LitvmBalance => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let mut client = open_litvm(&app, &data_dir)?;
            println!("{}", serde_json::to_string_pretty(&client.summary()?)?);
        }
        #[cfg(feature = "litvm")]
        Command::LitvmSend { address, amount } => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let mut client = open_litvm(&app, &data_dir)?;
            let _ = client.probe();
            let result = client.send(&wallet_litvm::LitVmSendRequest {
                address,
                amount_zkltc: amount,
            })?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        #[cfg(feature = "grail")]
        Command::GrailVerify { offer } => {
            let verified = grail_verify_file(&offer)?;
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
        #[cfg(feature = "grail")]
        Command::GrailDeposit {
            offer,
            amount_sats,
            fee_rate,
            outpoint,
        } => {
            ensure_loaded(&app, &data_dir, &passphrase_opt)?;
            let result = grail_deposit(&app, &data_dir, offer, amount_sats, fee_rate, outpoint)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}

#[cfg(feature = "litvm")]
fn open_litvm(app: &WalletApp, data_dir: &Path) -> Result<wallet_litvm::LitVmClient> {
    let secret = app.litvm_account_secret().context("derive LitVM account")?;
    wallet_litvm::LitVmClient::open(data_dir, secret).context("open LitVM client")
}

#[cfg(feature = "grail")]
fn grail_verify_file(path: &Path) -> Result<grail::VerifiedDeposit> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let (request, offer) = grail::load_offer_json(&bytes).context("parse offer JSON")?;
    grail::verify_deposit_offer(&offer, &request).context("verify deposit offer")
}

#[cfg(feature = "grail")]
fn grail_deposit(
    app: &WalletApp,
    data_dir: &Path,
    offer_path: Option<PathBuf>,
    amount_sats: Option<u64>,
    fee_rate: u64,
    outpoints: Vec<String>,
) -> Result<wallet_core::SendResult> {
    let summary = app.summary().context("summary")?;
    if summary.network != WalletNetwork::Testnet {
        bail!("grail-deposit is LiteForge / Litecoin testnet only");
    }
    let litvm = open_litvm(app, data_dir)?;
    let dest = litvm.address();

    let (request, offer) = if let Some(path) = offer_path {
        let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let (mut request, offer) = grail::load_offer_json(&bytes).context("parse offer JSON")?;
        request.dest = dest;
        if !outpoints.is_empty() {
            request.funding_outpoints = outpoints;
        }
        if let Some(sats) = amount_sats {
            request.amount_sats = sats;
        }
        (request, offer)
    } else {
        let sats = amount_sats.ok_or_else(|| {
            anyhow::anyhow!("--amount-sats required when initiating without --offer")
        })?;
        if outpoints.is_empty() {
            bail!("--outpoint required when initiating without --offer");
        }
        let request = grail::InitiateRequest {
            funding_outpoints: outpoints,
            amount_sats: sats,
            dest,
            chain_id: grail::LITEFORGE_CHAIN_ID,
        };
        let client = grail::GrailClient::from_env();
        let offer = match client.initiate(&request) {
            Ok(o) => o,
            Err(grail::GrailError::EndpointUnknown) => {
                bail!(
                    "Grail initiate API is not published yet. Capture an offer \
                     (see ../grail-sdk-rust/docs/CAPTURE.md) and pass --offer. \
                     Set GRAIL_API_URL when the endpoint exists."
                );
            }
            Err(e) => return Err(e).context("grail initiate"),
        };
        (request, offer)
    };

    let verified = match grail::verify_deposit_offer(&offer, &request) {
        Ok(v) => v,
        Err(grail::GrailError::UnverifiedTree) => {
            bail!(
                "offer has no tap merkle root; cannot pay until a captured \
                 LiteForge offer verifies (see ../grail-sdk-rust/docs/CAPTURE.md)"
            );
        }
        Err(e) => return Err(e).context("verify deposit offer"),
    };
    let address = grail_bdk::pay_to(&verified);
    app.send(SendRequest {
        address,
        amount_sats: verified.amount_sats,
        fee_rate_sat_vb: Some(fee_rate),
        drain: false,
        selected_outpoints: if verified.funding_outpoints.is_empty() {
            None
        } else {
            Some(verified.funding_outpoints.clone())
        },
    })
    .context("send to verified Grail address")
}

fn write_coinswapd_env(path: &Path, scan: &str, spend: &str, dest: &str) -> Result<()> {
    if scan.len() != 64 || spend.len() != 64 {
        bail!("scan/spend must be 32-byte hex");
    }
    if !dest.starts_with("ltcmweb1") {
        bail!("MWEB dest must be ltcmweb1…");
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let mut lines: Vec<String> = Vec::new();
    if path.exists() {
        let existing =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        for line in existing.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("MWEB_SCAN_SECRET=")
                || trimmed.starts_with("MWEB_SPEND_SECRET=")
                || trimmed.starts_with("E2E_MWEB_DEST=")
            {
                continue;
            }
            lines.push(line.to_string());
        }
        if !lines.is_empty() && !lines.last().map(|s| s.is_empty()).unwrap_or(true) {
            lines.push(String::new());
        }
    }
    lines.push(format!("MWEB_SCAN_SECRET={scan}"));
    lines.push(format!("MWEB_SPEND_SECRET={spend}"));
    lines.push(format!("E2E_MWEB_DEST={dest}"));
    lines.push(String::new());
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    write!(f, "{}", lines.join("\n")).context("write coinswapd env")?;
    f.sync_all().context("sync coinswapd env")?;
    Ok(())
}

fn ensure_loaded(app: &WalletApp, data_dir: &Path, passphrase_opt: &Option<String>) -> Result<()> {
    if !app.exists(data_dir) {
        bail!("no wallet at {}", data_dir.display());
    }
    if app.needs_migration() {
        let passphrase = read_passphrase(passphrase_opt)?;
        app.migrate_encrypt(wallet_core::MigrateEncryptRequest { passphrase })
            .context("migrate encrypt")?;
    } else if app.is_locked() {
        let passphrase = read_passphrase(passphrase_opt)?;
        app.unlock(UnlockRequest { passphrase }).context("unlock")?;
    }
    app.load(data_dir).context("load wallet")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn write_coinswapd_env_merges_without_clobbering_other_keys() {
        let path = std::env::temp_dir().join(format!(
            "mln-coinswapd-env-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "WALLET_PASSPHRASE=keep-me\nMIX_K0=aa\n").unwrap();
        let scan = "11".repeat(32);
        let spend = "22".repeat(32);
        write_coinswapd_env(&path, &scan, &spend, "ltcmweb1qqtestaddress").unwrap();
        let got = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(got.contains("WALLET_PASSPHRASE=keep-me"));
        assert!(got.contains("MIX_K0=aa"));
        assert!(got.contains(&format!("MWEB_SCAN_SECRET={scan}")));
        assert!(got.contains("E2E_MWEB_DEST=ltcmweb1qqtestaddress"));
    }

    #[test]
    fn write_coinswapd_env_mode_is_600() {
        let path = std::env::temp_dir().join(format!(
            "mln-coinswapd-env-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let scan = "11".repeat(32);
        let spend = "22".repeat(32);
        write_coinswapd_env(&path, &scan, &spend, "ltcmweb1qqtestaddress").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        let _ = fs::remove_file(&path);
        assert_eq!(mode & 0o777, 0o600);
    }
}

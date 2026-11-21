//! Unified wallet seed representation: BIP39, aezeed (Nexus/lnd), or a root
//! extended private key (`xprv`/`zprv`/`Ltpv`/…).
//!
//! All three collapse to a BIP32 master `Xpriv` (depth 0), from which BIP84
//! transparent descriptors and MWEB keys derive identically. The secret store
//! persists a short tagged string (`aezeed:…`, `xprv:…`, or untagged BIP39 for
//! backward compatibility with existing wallets).

use std::fmt;
use std::ops::Deref;

use bdk_mweb::keys::MasterKeyScheme;
use bdk_wallet::bitcoin::base58;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{Network, NetworkKind};
use bdk_wallet::keys::bip39::{Language, Mnemonic};
use bdk_wallet::KeychainKind;
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::aezeed::{self, DecodedAezeed};
use crate::error::WalletError;
use crate::network::WalletNetwork;

/// Days-epoch for aezeed birthdays: lnd's `BitcoinGenesisDate`,
/// 2009-01-03T18:15:05Z (`time.Unix(1231006505, 0)`).
const AEZEED_GENESIS_UNIX: u64 = 1_231_006_505;

/// Overwrite an extended private key's secret scalar and chain code in place.
pub(crate) fn wipe_xpriv(xprv: &mut Xpriv) {
    xprv.private_key.non_secure_erase();
    let cc: &mut [u8] = xprv.chain_code.as_mut();
    cc.zeroize();
}

/// Overwrite a `bip39::Mnemonic`'s internal word-index array in place.
pub(crate) fn wipe_mnemonic(m: &mut Mnemonic) {
    if let Ok(blank) = Mnemonic::from_entropy_in(Language::English, &[0u8; 32]) {
        *m = blank;
        std::hint::black_box(m);
    }
}

/// RAII wrapper around `Xpriv` that erases key and chain-code bytes on drop.
pub(crate) struct XprivGuard(Xpriv);

impl XprivGuard {
    pub(crate) fn new(xprv: Xpriv) -> Self {
        Self(xprv)
    }
}

impl Deref for XprivGuard {
    type Target = Xpriv;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for XprivGuard {
    fn drop(&mut self) {
        wipe_xpriv(&mut self.0);
    }
}

impl fmt::Debug for XprivGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XprivGuard(<redacted>)")
    }
}

/// A parsed wallet master secret.
#[derive(Clone)]
pub enum MasterSecret {
    /// BIP39 mnemonic (12–24 words), normalized to single spaces; seed derived with an empty passphrase.
    Bip39(Zeroizing<String>),
    /// aezeed cipher seed (24 words); entropy is the BIP32 seed directly.
    Aezeed {
        /// The original 24 words, normalized to single spaces.
        words: Zeroizing<String>,
        /// Cipher-seed passphrase when it is not the scheme default.
        passphrase: Option<Zeroizing<String>>,
        /// Deciphered entropy and birthday.
        decoded: DecodedAezeed,
    },
    /// A root (depth 0) extended private key.
    Xprv(Xpriv),
}

impl MasterSecret {
    /// Overwrite secret material in place. Called from [`Drop`].
    pub fn wipe(&mut self) {
        match self {
            Self::Bip39(words) => words.zeroize(),
            Self::Aezeed {
                words,
                passphrase,
                decoded,
            } => {
                words.zeroize();
                if let Some(p) = passphrase.as_mut() {
                    p.zeroize();
                }
                *passphrase = None;
                decoded.wipe();
            }
            Self::Xprv(xprv) => wipe_xpriv(xprv),
        }
    }
}

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip39(_) => f.debug_tuple("Bip39").field(&"<redacted>").finish(),
            Self::Aezeed {
                passphrase,
                decoded,
                ..
            } => f
                .debug_struct("Aezeed")
                .field("words", &"<redacted>")
                .field("passphrase", &passphrase.as_ref().map(|_| "<redacted>"))
                .field("decoded", decoded)
                .finish(),
            Self::Xprv(xprv) => f
                .debug_struct("Xprv")
                .field("network", &xprv.network)
                .field("depth", &xprv.depth)
                .field("private_key", &"<redacted>")
                .field("chain_code", &"<redacted>")
                .finish(),
        }
    }
}

impl MasterSecret {
    /// Parse user input: a mnemonic phrase (BIP39 or aezeed) or an extended
    /// private key. `aezeed_passphrase` applies only to 24-word aezeed input.
    pub fn parse(input: &str, aezeed_passphrase: Option<&str>) -> Result<Self, WalletError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(WalletError::InvalidMnemonic("empty seed input".into()));
        }
        let words: Vec<&str> = trimmed.split_whitespace().collect();

        if words.len() == 1 {
            return parse_extended_key(words[0]).map(Self::Xprv);
        }

        let explicit_pass = aezeed_passphrase.filter(|p| !p.is_empty());
        if words.len() == 24 {
            if explicit_pass.is_some() {
                // A cipher-seed passphrase only exists in aezeed; the user has
                // told us what this is.
                return Self::parse_aezeed(&words, explicit_pass);
            }
            match Mnemonic::parse_in(Language::English, trimmed) {
                Ok(mut m) => {
                    let phrase = Zeroizing::new(m.to_string());
                    wipe_mnemonic(&mut m);
                    return Ok(Self::Bip39(phrase));
                }
                Err(bip39_err) => {
                    return Self::parse_aezeed(&words, None).map_err(|aezeed_err| {
                        WalletError::InvalidMnemonic(format!(
                            "not a valid BIP39 mnemonic ({bip39_err}) and not a valid aezeed \
                             seed ({aezeed_err})"
                        ))
                    });
                }
            }
        }

        let mut m = Mnemonic::parse_in(Language::English, trimmed)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        let phrase = Zeroizing::new(m.to_string());
        wipe_mnemonic(&mut m);
        Ok(Self::Bip39(phrase))
    }

    fn parse_aezeed(words: &[&str], passphrase: Option<&str>) -> Result<Self, WalletError> {
        let decoded = aezeed::decode(words, passphrase)?;
        Ok(Self::Aezeed {
            words: Zeroizing::new(words.join(" ")),
            passphrase: passphrase.map(|p| Zeroizing::new(p.to_string())),
            decoded,
        })
    }

    /// Reconstruct from the tagged secret-store payload.
    /// Untagged payloads are legacy BIP39 mnemonics.
    pub fn from_stored(payload: &str) -> Result<Self, WalletError> {
        if let Some(rest) = payload.strip_prefix("aezeed:") {
            let mut lines = rest.splitn(2, '\n');
            let words_line = lines.next().unwrap_or_default();
            let passphrase = lines.next().filter(|p| !p.is_empty());
            let words: Vec<&str> = words_line.split_whitespace().collect();
            return Self::parse_aezeed(&words, passphrase);
        }
        if let Some(rest) = payload.strip_prefix("xprv:") {
            return parse_extended_key(rest.trim()).map(Self::Xprv);
        }
        let phrase = payload.strip_prefix("bip39:").unwrap_or(payload);
        let mut m = Mnemonic::parse_in(Language::English, phrase.trim())
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        let normalized = Zeroizing::new(m.to_string());
        wipe_mnemonic(&mut m);
        Ok(Self::Bip39(normalized))
    }

    /// Serialize for the secret store. BIP39 stays untagged so wallets
    /// created before other seed kinds existed keep loading unchanged.
    pub fn to_stored(&self) -> Zeroizing<String> {
        match self {
            Self::Bip39(words) => words.clone(),
            Self::Aezeed {
                words, passphrase, ..
            } => match passphrase {
                Some(p) => Zeroizing::new(format!("aezeed:{}\n{}", words.as_str(), p.as_str())),
                None => Zeroizing::new(format!("aezeed:{}", words.as_str())),
            },
            Self::Xprv(xprv) => {
                let encoded = Zeroizing::new(xprv.to_string());
                Zeroizing::new(format!("xprv:{}", encoded.as_str()))
            }
        }
    }

    /// The BIP32 master key on `network`. For an imported xprv the key
    /// material is network-independent; only the serialization prefix
    /// changes, so the network kind is overridden to match the wallet.
    pub fn master_xprv(&self, network: Network) -> Result<Xpriv, WalletError> {
        let map_err = |e: bdk_wallet::bitcoin::bip32::Error| WalletError::Descriptor(e.to_string());
        match self {
            Self::Bip39(words) => {
                let mut m = Mnemonic::parse_in(Language::English, words.as_str())
                    .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
                let seed = Zeroizing::new(m.to_seed(""));
                wipe_mnemonic(&mut m);
                Xpriv::new_master(network, &*seed).map_err(map_err)
            }
            Self::Aezeed { decoded, .. } => {
                Xpriv::new_master(network, &decoded.entropy).map_err(map_err)
            }
            Self::Xprv(xprv) => {
                let mut key = *xprv;
                key.network = NetworkKind::from(network);
                Ok(key)
            }
        }
    }

    /// Guarded [`Self::master_xprv`] that wipes the stack `Xpriv` on drop.
    pub(crate) fn master_xprv_guarded(&self, network: Network) -> Result<XprivGuard, WalletError> {
        self.master_xprv(network).map(XprivGuard::new)
    }

    /// Wallet birthday as a unix timestamp, when the seed format carries one.
    pub fn birthday_unix(&self) -> Option<u64> {
        match self {
            Self::Aezeed { decoded, .. } => {
                Some(AEZEED_GENESIS_UNIX + u64::from(decoded.birthday_days) * 86_400)
            }
            _ => None,
        }
    }

    /// Human-readable seed kind for error messages and logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Bip39(_) => "BIP39 mnemonic",
            Self::Aezeed { .. } => "aezeed seed",
            Self::Xprv(_) => "extended private key",
        }
    }

    /// secp256k1 secret for the LitVM sidecar (`m/44'/60'/{account}'/0/0`).
    ///
    /// Account 0 matches MetaMask/Rabby default. Network version bytes on the
    /// master xprv do not change the derived 32-byte key.
    pub fn litvm_account_secret(&self, account: u32) -> Result<Zeroizing<[u8; 32]>, WalletError> {
        let master = self.master_xprv_guarded(Network::Bitcoin)?;
        let secp = Secp256k1::new();
        let path: DerivationPath = format!("m/44'/60'/{account}'/0/0").parse().map_err(
            |e: bdk_wallet::bitcoin::bip32::Error| WalletError::Descriptor(e.to_string()),
        )?;
        let child = XprivGuard::new(
            master
                .derive_priv(&secp, &path)
                .map_err(|e| WalletError::Descriptor(e.to_string()))?,
        );
        Ok(Zeroizing::new(child.private_key.secret_bytes()))
    }

    /// Backup material without storage tags: phrase/key plus optional aezeed cipher passphrase.
    pub fn backup_material(&self) -> (Zeroizing<String>, Option<Zeroizing<String>>) {
        match self {
            Self::Bip39(words) => (words.clone(), None),
            Self::Aezeed {
                words, passphrase, ..
            } => (words.clone(), passphrase.clone()),
            Self::Xprv(xprv) => (Zeroizing::new(xprv.to_string()), None),
        }
    }
}

/// Address-derivation preview for cross-wallet parity checks (e.g. against
/// Nexus): what addresses would this wallet generate from a given seed?
#[derive(Debug, Clone, Serialize)]
pub struct DerivePreview {
    /// What the input parsed as.
    pub kind: String,
    pub network: String,
    pub master_fingerprint: String,
    /// BIP32 depth of the master key (always 0 for accepted extended keys).
    pub depth: u8,
    /// Wallet birthday (unix seconds) when the seed format carries one.
    pub birthday_unix: Option<u64>,
    /// BIP84 receive addresses 0..count, exactly as the wallet derives them.
    pub bip84_external: Vec<String>,
    /// BIP84 change addresses 0..count.
    pub bip84_internal: Vec<String>,
    /// MWEB addresses under every supported derivation scheme.
    pub mweb: Vec<MwebSchemePreview>,
}

/// MWEB addresses derived under one [`MasterKeyScheme`].
#[derive(Debug, Clone, Serialize)]
pub struct MwebSchemePreview {
    pub scheme: String,
    pub scan_path: String,
    pub spend_path: String,
    /// Addresses at indices 0..count. Legacy mwebd treats index 0 as the
    /// change address and hands out indices 1+ for receiving.
    pub addresses: Vec<String>,
}

/// Derive a [`DerivePreview`] from raw seed input without touching any
/// wallet state on disk. `account` selects the BIP84 / MWEB / LitVM account index.
pub fn derive_preview(
    input: &str,
    aezeed_passphrase: Option<&str>,
    network: WalletNetwork,
    count: u32,
    account: u32,
) -> Result<DerivePreview, WalletError> {
    let secret = MasterSecret::parse(input, aezeed_passphrase)?;
    let bdk_net = network.to_bitcoin_network();
    let secp = Secp256k1::new();
    let xprv = secret.master_xprv_guarded(bdk_net)?;

    let wallet = crate::descriptors::create_params(&secret, network, account)?
        .create_wallet_no_persist()
        .map_err(|e| WalletError::Descriptor(e.to_string()))?;

    let peek = |keychain: KeychainKind| -> Vec<String> {
        (0..count)
            .map(|i| wallet.peek_address(keychain, i).address.to_string())
            .collect()
    };

    // LIP-0004 follows the implemented Core path. Both names preview those keys.
    let schemes = [
        ("litecoin-core", MasterKeyScheme::LitecoinCore),
        ("lip-0004", MasterKeyScheme::LitecoinCore),
        ("mwebd", MasterKeyScheme::Mwebd),
    ];
    let mut mweb = Vec::with_capacity(schemes.len());
    for (name, scheme) in schemes {
        let keys = crate::mweb::master_keys_for_account(&xprv, scheme, account, &secp)?;
        let addresses = (0..count)
            .map(|i| {
                keys.address(i, NetworkKind::from(bdk_net), &secp)
                    .map(|a| a.to_string())
                    .map_err(|e| WalletError::Mweb(e.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        mweb.push(MwebSchemePreview {
            scheme: name.to_string(),
            scan_path: format!("m/{}", keys.scan_path),
            spend_path: format!("m/{}", keys.spend_path),
            addresses,
        });
    }

    Ok(DerivePreview {
        kind: secret.kind().to_string(),
        network: format!("{network:?}").to_lowercase(),
        master_fingerprint: xprv.fingerprint(&secp).to_string(),
        depth: xprv.depth,
        birthday_unix: secret.birthday_unix(),
        bip84_external: peek(KeychainKind::External),
        bip84_internal: peek(KeychainKind::Internal),
        mweb,
    })
}

/// SLIP-132 and Litecoin-specific BIP32 version prefixes.
///
/// The 74 bytes after the 4-byte version (`depth || parent_fp || child_num ||
/// chain_code || 0x00 || secret_key`) are identical across every scheme, so
/// rewriting the version bytes to Bitcoin's standard `xprv`/`tprv` lets
/// `bitcoin::bip32::Xpriv::decode` parse any of them.
const PRIVATE_MAINNET: &[(&str, [u8; 4])] = &[
    ("xprv", [0x04, 0x88, 0xAD, 0xE4]), // BIP32 standard
    ("yprv", [0x04, 0x9D, 0x78, 0x78]), // BIP49
    ("zprv", [0x04, 0xB2, 0x43, 0x0C]), // BIP84 (Electrum-LTC, Sparrow, …)
    ("Yprv", [0x02, 0x95, 0xB0, 0x05]), // SLIP-132 multisig P2SH-P2WSH
    ("Zprv", [0x02, 0xAA, 0x7A, 0x99]), // SLIP-132 multisig P2WSH
    ("Ltpv", [0x01, 0x9D, 0x9C, 0xFE]), // Litecoin legacy BIP32
    ("Mtpv", [0x01, 0xB2, 0x67, 0x92]), // Litecoin P2SH-P2WPKH
];

const PRIVATE_TESTNET: &[(&str, [u8; 4])] = &[
    ("tprv", [0x04, 0x35, 0x83, 0x94]), // BIP32 testnet
    ("uprv", [0x04, 0x4A, 0x4E, 0x28]), // BIP49 testnet
    ("vprv", [0x04, 0x5F, 0x18, 0xBC]), // BIP84 testnet
    ("Uprv", [0x02, 0x42, 0x85, 0xB5]),
    ("Vprv", [0x02, 0x57, 0x50, 0x48]),
    ("ttpv", [0x04, 0x36, 0xEF, 0x7D]), // Litecoin testnet
];

/// Public extended-key prefixes — recognized only so we can give a clear
/// "that's a watch-only key, export the private key instead" error.
const PUBLIC_ANY: &[(&str, [u8; 4])] = &[
    ("xpub", [0x04, 0x88, 0xB2, 0x1E]),
    ("ypub", [0x04, 0x9D, 0x7C, 0xB2]),
    ("Ypub", [0x02, 0x95, 0xB4, 0x3F]),
    ("zpub", [0x04, 0xB2, 0x47, 0x46]),
    ("Zpub", [0x02, 0xAA, 0x7E, 0xD3]),
    ("Ltub", [0x01, 0x9D, 0xA4, 0x62]),
    ("Mtub", [0x01, 0xB2, 0x6E, 0xF6]),
    ("tpub", [0x04, 0x35, 0x87, 0xCF]),
    ("upub", [0x04, 0x4A, 0x52, 0x62]),
    ("Upub", [0x02, 0x42, 0x89, 0xEF]),
    ("vpub", [0x04, 0x5F, 0x1C, 0xF6]),
    ("Vpub", [0x02, 0x57, 0x54, 0x83]),
    ("ttub", [0x04, 0x36, 0xF6, 0xE1]),
];

const STANDARD_MAINNET_PRIV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
const STANDARD_TESTNET_PRIV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// Parse any supported extended private key into a *root* `Xpriv`,
/// normalizing SLIP-132/Litecoin version bytes to the standard encoding.
pub fn parse_extended_key(s: &str) -> Result<Xpriv, WalletError> {
    let bad = |msg: String| WalletError::InvalidMnemonic(msg);

    let mut data = Zeroizing::new(
        base58::decode_check(s.trim())
            .map_err(|_| bad("not a valid extended key (base58 check failed)".into()))?,
    );
    if data.len() != 78 {
        return Err(bad(format!(
            "extended key payload is {} bytes, expected 78",
            data.len()
        )));
    }
    let version: [u8; 4] = data[0..4].try_into().expect("4 bytes");

    if let Some((prefix, _)) = PUBLIC_ANY.iter().find(|(_, v)| *v == version) {
        return Err(bad(format!(
            "{prefix} is a *public* extended key — it cannot sign or derive MWEB keys. \
             Export the private key (xprv/zprv) instead"
        )));
    }

    let is_mainnet = PRIVATE_MAINNET.iter().any(|(_, v)| *v == version);
    let is_testnet = PRIVATE_TESTNET.iter().any(|(_, v)| *v == version);
    if !is_mainnet && !is_testnet {
        return Err(bad(format!(
            "unrecognized extended key version bytes {:02x}{:02x}{:02x}{:02x}",
            version[0], version[1], version[2], version[3]
        )));
    }

    data[0..4].copy_from_slice(if is_mainnet {
        &STANDARD_MAINNET_PRIV
    } else {
        &STANDARD_TESTNET_PRIV
    });
    let mut xprv = Xpriv::decode(&data).map_err(|e| bad(format!("invalid extended key: {e}")))?;
    drop(data);

    if xprv.depth != 0 {
        let depth = xprv.depth;
        wipe_xpriv(&mut xprv);
        return Err(bad(format!(
            "this is an account-level extended key (depth {depth}), not the wallet root. \
             MWEB keys branch directly off the master key, so recovery needs the \
             root key (depth 0) — export the HD root / master key instead",
        )));
    }
    Ok(xprv)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP32 test vector 1: root and its m/0' child.
    const ROOT_XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const CHILD_XPRV: &str = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    const ROOT_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn reencode_with_version(key: &str, version: [u8; 4]) -> String {
        let mut data = base58::decode_check(key).unwrap();
        data[0..4].copy_from_slice(&version);
        base58::encode_check(&data)
    }

    #[test]
    fn litvm_path_matches_anvil_account0() {
        // Hardhat/Anvil default mnemonic, MetaMask account 0.
        let secret = MasterSecret::parse(
            "test test test test test test test test test test test junk",
            None,
        )
        .unwrap();
        let got = secret.litvm_account_secret(0).unwrap();
        let expected =
            hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        assert_eq!(got.as_slice(), expected.as_slice());
    }

    #[test]
    fn root_xprv_parses() {
        let xprv = parse_extended_key(ROOT_XPRV).unwrap();
        assert_eq!(xprv.depth, 0);
        assert_eq!(xprv.to_string(), ROOT_XPRV);
    }

    #[test]
    fn zprv_and_ltpv_normalize_to_same_key() {
        let zprv = reencode_with_version(ROOT_XPRV, [0x04, 0xB2, 0x43, 0x0C]);
        assert!(zprv.starts_with("zprv"), "{zprv}");
        let ltpv = reencode_with_version(ROOT_XPRV, [0x01, 0x9D, 0x9C, 0xFE]);
        assert!(ltpv.starts_with("Ltpv"), "{ltpv}");

        let from_x = parse_extended_key(ROOT_XPRV).unwrap();
        assert_eq!(parse_extended_key(&zprv).unwrap(), from_x);
        assert_eq!(parse_extended_key(&ltpv).unwrap(), from_x);
    }

    #[test]
    fn account_level_key_is_rejected_with_depth_message() {
        let zprv_child = reencode_with_version(CHILD_XPRV, [0x04, 0xB2, 0x43, 0x0C]);
        let err = parse_extended_key(&zprv_child).unwrap_err().to_string();
        assert!(err.contains("depth 1"), "{err}");
        assert!(err.contains("root"), "{err}");
        assert!(!err.contains(&zprv_child), "{err}");
    }

    #[test]
    fn xpub_is_rejected_as_public() {
        let err = parse_extended_key(ROOT_XPUB).unwrap_err().to_string();
        assert!(err.contains("public"), "{err}");
    }

    #[test]
    fn parse_dispatches_bip39_12_words() {
        let secret = MasterSecret::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
        )
        .unwrap();
        assert!(matches!(secret, MasterSecret::Bip39(_)));
    }

    #[test]
    fn parse_dispatches_valid_24_word_bip39() {
        let phrase = format!("{}art", "abandon ".repeat(23));
        let secret = MasterSecret::parse(&phrase, None).unwrap();
        assert!(matches!(secret, MasterSecret::Bip39(_)));
    }

    #[test]
    fn parse_dispatches_aezeed_and_round_trips_storage() {
        let phrase = "above judge emerge veteran reform crunch system all snap please shoulder \
                      vault hurt city quarter cover enlist swear success suggest drink wagon \
                      enrich body";
        let secret = MasterSecret::parse(phrase, None).unwrap();
        let MasterSecret::Aezeed { ref decoded, .. } = secret else {
            panic!("expected aezeed, got {}", secret.kind());
        };
        assert_eq!(decoded.birthday_days, 0);
        assert_eq!(secret.birthday_unix(), Some(AEZEED_GENESIS_UNIX));

        let stored = secret.to_stored();
        assert!(stored.starts_with("aezeed:"));
        let reloaded = MasterSecret::from_stored(&stored).unwrap();
        assert_eq!(
            reloaded.master_xprv(Network::Bitcoin).unwrap(),
            secret.master_xprv(Network::Bitcoin).unwrap()
        );
    }

    #[test]
    fn aezeed_with_passphrase_round_trips_storage() {
        let phrase = "absorb century submit father path glove gloom super divert garden ice \
                      mirror wisdom grass dice kit ugly castle success suggest drink monster \
                      congress flight";
        let secret = MasterSecret::parse(phrase, Some("!very_safe_55345_password*")).unwrap();
        let stored = secret.to_stored();
        assert!(stored.contains('\n'), "passphrase must be persisted");
        let reloaded = MasterSecret::from_stored(&stored).unwrap();
        assert_eq!(
            reloaded.master_xprv(Network::Bitcoin).unwrap(),
            secret.master_xprv(Network::Bitcoin).unwrap()
        );
    }

    #[test]
    fn untagged_stored_payload_is_bip39() {
        let stored =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let secret = MasterSecret::from_stored(stored).unwrap();
        assert!(matches!(secret, MasterSecret::Bip39(_)));
        assert_eq!(secret.to_stored().as_str(), stored);
    }

    #[test]
    fn imported_xprv_network_kind_follows_wallet() {
        let secret = MasterSecret::parse(ROOT_XPRV, None).unwrap();
        let on_testnet = secret.master_xprv(Network::Testnet4).unwrap();
        assert_eq!(on_testnet.network, NetworkKind::Test);
        let stored = secret.to_stored();
        assert!(stored.starts_with("xprv:"));
        let reloaded = MasterSecret::from_stored(&stored).unwrap();
        assert_eq!(
            reloaded.master_xprv(Network::Bitcoin).unwrap(),
            secret.master_xprv(Network::Bitcoin).unwrap()
        );
    }

    #[test]
    fn wipe_erases_all_master_secret_variants() {
        let mut s1 = MasterSecret::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
        )
        .unwrap();
        s1.wipe();
        if let MasterSecret::Bip39(ref w) = s1 {
            assert!(w.is_empty());
        } else {
            panic!("expected Bip39");
        }

        let phrase = "absorb century submit father path glove gloom super divert garden ice \
                      mirror wisdom grass dice kit ugly castle success suggest drink monster \
                      congress flight";
        let mut s2 = MasterSecret::parse(phrase, Some("!very_safe_55345_password*")).unwrap();
        s2.wipe();
        if let MasterSecret::Aezeed {
            ref words,
            ref passphrase,
            ref decoded,
        } = s2
        {
            assert!(words.is_empty());
            assert!(passphrase.is_none());
            assert_eq!(decoded.entropy, [0u8; 16]);
        } else {
            panic!("expected Aezeed");
        }

        let mut s3 = MasterSecret::parse(ROOT_XPRV, None).unwrap();
        let before = match s3 {
            MasterSecret::Xprv(ref x) => x.private_key.secret_bytes(),
            _ => unreachable!(),
        };
        s3.wipe();
        if let MasterSecret::Xprv(ref x) = s3 {
            assert_ne!(x.private_key.secret_bytes(), before);
            assert_eq!(x.chain_code.to_bytes(), [0u8; 32]);
        } else {
            panic!("expected Xprv");
        }
    }
}

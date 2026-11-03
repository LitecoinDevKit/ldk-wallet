use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath};
use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::{NetworkKind, Psbt};
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::{GeneratableKey, GeneratedKey};
use bdk_wallet::miniscript::descriptor::KeyMapWrapper;
use bdk_wallet::miniscript::Segwitv0;
use bdk_wallet::template::P2Wpkh;
use bdk_wallet::{CreateParams, KeychainKind, LoadParams, SignOptions, Wallet};

use crate::error::WalletError;
use crate::network::WalletNetwork;
use crate::seed::MasterSecret;

/// Generate a new 12-word English mnemonic.
pub fn generate_mnemonic() -> Result<String, WalletError> {
    let generated: GeneratedKey<_, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English))
            .map_err(|e| WalletError::InvalidMnemonic(format!("{e:?}")))?;
    Ok(generated.into_key().to_string())
}

/// BIP84 path `m/84'/coin'/account'/{0|1}` (without the wildcard).
pub fn bip84_keychain_path(
    network: WalletNetwork,
    account: u32,
    keychain: KeychainKind,
) -> Result<DerivationPath, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let network_kind = NetworkKind::from(bdk_network);
    let coin = match network_kind {
        NetworkKind::Main => 2u32,
        _ => 1u32,
    };
    let chain = match keychain {
        KeychainKind::External => 0u32,
        KeychainKind::Internal => 1u32,
    };
    let map = |e: bdk_wallet::bitcoin::bip32::Error| WalletError::Descriptor(e.to_string());
    Ok(DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(84).map_err(map)?,
        ChildNumber::from_hardened_idx(coin).map_err(map)?,
        ChildNumber::from_hardened_idx(account).map_err(map)?,
        ChildNumber::from_normal_idx(chain).map_err(map)?,
    ]))
}

/// Build [`CreateParams`] for a BIP84 wallet at `account` from a master secret.
pub fn create_params(
    secret: &MasterSecret,
    network: WalletNetwork,
    account: u32,
) -> Result<CreateParams, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    let external = bip84_keychain_path(network, account, KeychainKind::External)?;
    let internal = bip84_keychain_path(network, account, KeychainKind::Internal)?;
    Ok(Wallet::create(
        P2Wpkh((xprv, external)),
        P2Wpkh((xprv, internal)),
    )
    .network(bdk_network))
}

/// Build [`LoadParams`] that check the BIP84 descriptors for `account`.
pub fn load_params(
    secret: &MasterSecret,
    network: WalletNetwork,
    account: u32,
) -> Result<LoadParams, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    let external = bip84_keychain_path(network, account, KeychainKind::External)?;
    let internal = bip84_keychain_path(network, account, KeychainKind::Internal)?;
    Ok(Wallet::load()
        .descriptor(KeychainKind::External, Some(P2Wpkh((xprv, external))))
        .descriptor(KeychainKind::Internal, Some(P2Wpkh((xprv, internal))))
        .check_network(bdk_network))
}

/// Caller-owned signer for the BIP84 wallet at `account`.
pub fn signer(
    secret: &MasterSecret,
    network: WalletNetwork,
    account: u32,
) -> Result<KeyMapWrapper, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    let secp = Secp256k1::new();
    let map_err =
        |e: bdk_wallet::descriptor::DescriptorError| WalletError::Descriptor(e.to_string());
    let external = bip84_keychain_path(network, account, KeychainKind::External)?;
    let internal = bip84_keychain_path(network, account, KeychainKind::Internal)?;
    let (_, mut keymap) = P2Wpkh((xprv, external))
        .into_wallet_descriptor(&secp, bdk_network.into())
        .map_err(map_err)?;
    let (_, change_keymap) = P2Wpkh((xprv, internal))
        .into_wallet_descriptor(&secp, bdk_network.into())
        .map_err(map_err)?;
    keymap.extend(change_keymap);
    Ok(KeyMapWrapper::from(keymap))
}

/// Sign the transparent inputs of `psbt` with `signer` and finalize them through the wallet.
pub fn sign_and_finalize(
    wallet: &Wallet,
    signer: &KeyMapWrapper,
    psbt: &mut Psbt,
) -> Result<(), WalletError> {
    psbt.sign(signer, wallet.secp_ctx())
        .map_err(|(_, errors)| WalletError::Sign(format!("{errors:?}")))?;
    let finalized = wallet
        .finalize_psbt(psbt, SignOptions::default())
        .map_err(|e| WalletError::Sign(e.to_string()))?;
    if !finalized {
        return Err(WalletError::Sign("transaction not fully signed".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::Network;
    use bdk_wallet::keys::bip39::Mnemonic;
    use bdk_wallet::template::Bip84;

    fn abandon_secret() -> MasterSecret {
        let m = Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        MasterSecret::Bip39(m)
    }

    #[test]
    fn account_zero_matches_stock_bip84() {
        let secret = abandon_secret();
        let network = WalletNetwork::Testnet;
        let xprv = secret.master_xprv(Network::Testnet4).unwrap();

        let stock = Wallet::create(
            Bip84(xprv, KeychainKind::External),
            Bip84(xprv, KeychainKind::Internal),
        )
        .network(Network::Testnet4)
        .create_wallet_no_persist()
        .unwrap();

        let ours = create_params(&secret, network, 0)
            .unwrap()
            .create_wallet_no_persist()
            .unwrap();

        assert_eq!(
            stock.peek_address(KeychainKind::External, 0).to_string(),
            ours.peek_address(KeychainKind::External, 0).to_string()
        );
        assert_eq!(
            stock.public_descriptor(KeychainKind::External).to_string(),
            ours.public_descriptor(KeychainKind::External).to_string()
        );
    }

    #[test]
    fn account_one_diverges_from_zero() {
        let secret = abandon_secret();
        let network = WalletNetwork::Testnet;
        let a0 = create_params(&secret, network, 0)
            .unwrap()
            .create_wallet_no_persist()
            .unwrap();
        let a1 = create_params(&secret, network, 1)
            .unwrap()
            .create_wallet_no_persist()
            .unwrap();
        assert_ne!(
            a0.peek_address(KeychainKind::External, 0).to_string(),
            a1.peek_address(KeychainKind::External, 0).to_string()
        );
    }
}

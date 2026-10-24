use bdk_wallet::bitcoin::key::Secp256k1;
use bdk_wallet::bitcoin::Psbt;
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
use bdk_wallet::keys::{GeneratableKey, GeneratedKey};
use bdk_wallet::miniscript::descriptor::KeyMapWrapper;
use bdk_wallet::miniscript::Segwitv0;
use bdk_wallet::template::Bip84;
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

/// Build [`CreateParams`] for a BIP84 wallet from a master secret.
pub fn create_params(
    secret: &MasterSecret,
    network: WalletNetwork,
) -> Result<CreateParams, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    Ok(Wallet::create(
        Bip84(xprv, KeychainKind::External),
        Bip84(xprv, KeychainKind::Internal),
    )
    .network(bdk_network))
}

/// Build [`LoadParams`] that check the BIP84 descriptors. Signing keys are not loaded into
/// the wallet; see [`signer`].
pub fn load_params(
    secret: &MasterSecret,
    network: WalletNetwork,
) -> Result<LoadParams, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    Ok(Wallet::load()
        .descriptor(
            KeychainKind::External,
            Some(Bip84(xprv, KeychainKind::External)),
        )
        .descriptor(
            KeychainKind::Internal,
            Some(Bip84(xprv, KeychainKind::Internal)),
        )
        .check_network(bdk_network))
}

/// Caller-owned signer for the BIP84 wallet: the key map of both keychains' descriptors,
/// used with `Psbt::sign(&signer, wallet.secp_ctx())` followed by `Wallet::finalize_psbt`.
///
/// This is the same key material the wallet used to hold internally before `bdk_wallet` 3.2.0
/// deprecated wallet-owned signing (`Wallet::sign` / `extract_keys`).
pub fn signer(secret: &MasterSecret, network: WalletNetwork) -> Result<KeyMapWrapper, WalletError> {
    let bdk_network = network.to_bitcoin_network();
    let xprv = secret.master_xprv(bdk_network)?;
    let secp = Secp256k1::new();
    let map_err =
        |e: bdk_wallet::descriptor::DescriptorError| WalletError::Descriptor(e.to_string());
    let (_, mut keymap) = Bip84(xprv, KeychainKind::External)
        .into_wallet_descriptor(&secp, bdk_network.into())
        .map_err(map_err)?;
    let (_, change_keymap) = Bip84(xprv, KeychainKind::Internal)
        .into_wallet_descriptor(&secp, bdk_network.into())
        .map_err(map_err)?;
    keymap.extend(change_keymap);
    Ok(KeyMapWrapper::from(keymap))
}

/// Sign the transparent inputs of `psbt` with `signer` and finalize them through the wallet.
///
/// Errors if any key fails to sign or if the PSBT is not fully signed afterwards. MWEB maps on
/// the PSBT are untouched (they are signed by the MWEB facade before this step).
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

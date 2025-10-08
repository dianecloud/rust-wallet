//! Private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides a wrapper around secp256k1 private keys for use in
//! BIP32 extended key derivation.

use secp256k1::SecretKey;

/// A 32-byte secp256k1 private key used in BIP32 hierarchical deterministic wallets.
///
/// Private keys are scalar values on the secp256k1 elliptic curve. They must be
/// non-zero and less than the curve order to be valid.
///
/// # Security
///
/// Private keys must be kept secret. Anyone with access to a private key can
/// spend funds and derive child keys. Always store private keys securely and
/// never expose them in logs or error messages.
///
/// # Examples
///
/// ```rust,ignore
/// use bip32::PrivateKey;
///
/// // Create from raw bytes
/// let bytes = [1u8; 32];
/// let private_key = PrivateKey::from_bytes(&bytes)?;
///
/// // Derive the corresponding public key
/// let public_key = private_key.public_key();
/// ```
#[derive(Clone)]
pub struct PrivateKey {
    /// The underlying secp256k1 secret key
    #[allow(dead_code)]
    inner: SecretKey,
}

impl PrivateKey {
    /// The length of a private key in bytes.
    pub const LENGTH: usize = 32;
}

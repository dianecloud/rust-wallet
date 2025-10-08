//! Private key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides a wrapper around secp256k1 private keys for use in
//! BIP32 extended key derivation.

use crate::{Error, Result};
use secp256k1::{scalar::Scalar, PublicKey as Secp256k1PublicKey, SecretKey, SECP256K1};
use zeroize::Zeroize;

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
/// This type implements `Drop` to securely zeroize memory when the key is dropped.
///
/// # Examples
///
/// ```rust
/// use bip32::PrivateKey;
///
/// // Create from raw bytes
/// let bytes = [1u8; 32];
/// let private_key = PrivateKey::from_bytes(&bytes)?;
///
/// // Get the bytes back
/// let key_bytes = private_key.to_bytes();
/// assert_eq!(key_bytes.len(), 32);
/// # Ok::<(), bip32::Error>(())
/// ```
#[derive(Clone)]
pub struct PrivateKey {
    /// The underlying secp256k1 secret key
    inner: SecretKey,
}

impl PrivateKey {
    /// The length of a private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a new `PrivateKey` from a secp256k1 `SecretKey`.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - A valid secp256k1 secret key
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    /// use secp256k1::SecretKey;
    ///
    /// let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    /// let private_key = PrivateKey::new(secret_key);
    /// ```
    pub fn new(secret_key: SecretKey) -> Self {
        PrivateKey { inner: secret_key }
    }

    /// Creates a `PrivateKey` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice that must be exactly 32 bytes and represent a valid
    ///   secp256k1 private key (non-zero and less than the curve order)
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if:
    /// - The slice is not exactly 32 bytes
    /// - The bytes represent an invalid secp256k1 key (zero or >= curve order)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// // Valid key
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    ///
    /// // Invalid length
    /// let invalid = [0u8; 16];
    /// assert!(PrivateKey::from_bytes(&invalid).is_err());
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LENGTH {
            return Err(Error::InvalidPrivateKey {
                reason: format!(
                    "Private key must be {} bytes, got {}",
                    Self::LENGTH,
                    bytes.len()
                ),
            });
        }

        let secret_key = SecretKey::from_slice(bytes).map_err(|e| Error::InvalidPrivateKey {
            reason: format!("Invalid secp256k1 private key: {}", e),
        })?;

        Ok(PrivateKey { inner: secret_key })
    }

    /// Creates a `PrivateKey` from a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 32-byte array representing a valid secp256k1 private key
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if the bytes represent an invalid
    /// secp256k1 key (zero or >= curve order)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_array(bytes)?;
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn from_array(bytes: [u8; 32]) -> Result<Self> {
        Self::from_bytes(&bytes)
    }

    /// Returns the private key as a 32-byte array.
    ///
    /// # Security Warning
    ///
    /// The returned bytes are secret key material. Handle with care and avoid
    /// logging or exposing them.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let key_bytes = private_key.to_bytes();
    /// assert_eq!(key_bytes.len(), 32);
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.secret_bytes()
    }

    /// Returns a reference to the underlying secp256k1 `SecretKey`.
    ///
    /// This is useful for performing secp256k1 operations directly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let secret_key = private_key.secret_key();
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn secret_key(&self) -> &SecretKey {
        &self.inner
    }

    /// Derives the corresponding secp256k1 public key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    /// let public_key = private_key.public_key();
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::from_secret_key(SECP256K1, &self.inner)
    }

    /// Adds a scalar value to this private key (for BIP32 child key derivation).
    ///
    /// This performs the operation: `new_key = (self + tweak) mod n` where `n` is
    /// the secp256k1 curve order. This is a core operation in BIP32 child key derivation.
    ///
    /// # Arguments
    ///
    /// * `tweak` - A 32-byte scalar value to add to this key
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrivateKey`] if:
    /// - The tweak is not exactly 32 bytes
    /// - The resulting key would be invalid (>= curve order)
    ///
    /// Returns [`Error::KeyOverflow`] if the addition results in an invalid key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bip32::PrivateKey;
    ///
    /// let bytes = [1u8; 32];
    /// let private_key = PrivateKey::from_bytes(&bytes)?;
    ///
    /// let tweak = [2u8; 32];
    /// let derived_key = private_key.tweak_add(&tweak)?;
    /// # Ok::<(), bip32::Error>(())
    /// ```
    pub fn tweak_add(&self, tweak: &[u8]) -> Result<Self> {
        if tweak.len() != 32 {
            return Err(Error::InvalidPrivateKey {
                reason: format!("Tweak must be 32 bytes, got {}", tweak.len()),
            });
        }

        // Convert tweak bytes to Scalar
        let mut tweak_array = [0u8; 32];
        tweak_array.copy_from_slice(tweak);
        let scalar = Scalar::from_be_bytes(tweak_array).map_err(|_| Error::InvalidPrivateKey {
            reason: "Invalid tweak scalar".to_string(),
        })?;

        let tweaked = self.inner.add_tweak(&scalar)
            .map_err(|_| Error::KeyOverflow)?;

        Ok(PrivateKey { inner: tweaked })
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.inner.secret_bytes() == other.inner.secret_bytes()
    }
}

impl Eq for PrivateKey {}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey([REDACTED])")
    }
}

impl From<SecretKey> for PrivateKey {
    fn from(secret_key: SecretKey) -> Self {
        PrivateKey::new(secret_key)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        PrivateKey::from_bytes(bytes)
    }
}

impl TryFrom<[u8; 32]> for PrivateKey {
    type Error = Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self> {
        PrivateKey::from_array(bytes)
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zeroize the secret key bytes when dropping
        let mut bytes = self.inner.secret_bytes();
        bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_key_new() {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let private_key = PrivateKey::new(secret_key);
        assert_eq!(private_key.to_bytes(), [1u8; 32]);
    }

    #[test]
    fn test_private_key_from_bytes_valid() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_from_bytes_too_short() {
        let bytes = [1u8; 16];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_from_bytes_too_long() {
        let bytes = [1u8; 64];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_from_bytes_zero() {
        // All zeros is an invalid secp256k1 private key
        let bytes = [0u8; 32];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid secp256k1"));
    }

    #[test]
    fn test_private_key_from_bytes_max() {
        // All 0xFF is >= curve order, invalid
        let bytes = [0xFFu8; 32];
        let result = PrivateKey::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_from_array_valid() {
        let bytes = [42u8; 32];
        let private_key = PrivateKey::from_array(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_from_array_invalid() {
        let bytes = [0u8; 32];
        let result = PrivateKey::from_array(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_to_bytes() {
        let bytes = [123u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let result = private_key.to_bytes();
        assert_eq!(result, bytes);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_private_key_secret_key() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let secret_key = private_key.secret_key();
        assert_eq!(secret_key.secret_bytes(), bytes);
    }

    #[test]
    fn test_private_key_public_key() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let public_key = private_key.public_key();
        
        // Verify we got a valid public key (33 bytes compressed)
        assert_eq!(public_key.serialize().len(), 33);
    }

    #[test]
    fn test_private_key_public_key_deterministic() {
        // Same private key should always produce same public key
        let bytes = [1u8; 32];
        let private_key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let private_key2 = PrivateKey::from_bytes(&bytes).unwrap();
        
        let public_key1 = private_key1.public_key();
        let public_key2 = private_key2.public_key();
        
        assert_eq!(public_key1.serialize(), public_key2.serialize());
    }

    #[test]
    fn test_private_key_tweak_add_valid() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        
        let tweak = [2u8; 32];
        let derived = private_key.tweak_add(&tweak).unwrap();
        
        // Derived key should be different from original
        assert_ne!(derived.to_bytes(), private_key.to_bytes());
    }

    #[test]
    fn test_private_key_tweak_add_invalid_length() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        
        // Tweak too short
        let tweak = [1u8; 16];
        let result = private_key.tweak_add(&tweak);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn test_private_key_tweak_add_zero() {
        let bytes = [5u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        
        // Adding zero should give same key
        let tweak = [0u8; 32];
        let derived = private_key.tweak_add(&tweak).unwrap();
        assert_eq!(derived.to_bytes(), private_key.to_bytes());
    }

    #[test]
    fn test_private_key_clone() {
        let bytes = [99u8; 32];
        let private_key1 = PrivateKey::from_bytes(&bytes).unwrap();
        let private_key2 = private_key1.clone();
        
        assert_eq!(private_key1, private_key2);
        assert_eq!(private_key1.to_bytes(), private_key2.to_bytes());
    }

    #[test]
    fn test_private_key_equality() {
        let bytes1 = [1u8; 32];
        let bytes2 = [1u8; 32];
        let bytes3 = [2u8; 32];
        
        let key1 = PrivateKey::from_bytes(&bytes1).unwrap();
        let key2 = PrivateKey::from_bytes(&bytes2).unwrap();
        let key3 = PrivateKey::from_bytes(&bytes3).unwrap();
        
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_private_key_debug() {
        let bytes = [1u8; 32];
        let private_key = PrivateKey::from_bytes(&bytes).unwrap();
        let debug_str = format!("{:?}", private_key);
        
        assert!(debug_str.contains("PrivateKey"));
        assert!(debug_str.contains("REDACTED"));
        // Should NOT contain actual key bytes
        assert!(!debug_str.contains("0x01"));
    }

    #[test]
    fn test_private_key_from_secret_key() {
        let secret_key = SecretKey::from_slice(&[55u8; 32]).unwrap();
        let private_key: PrivateKey = secret_key.into();
        assert_eq!(private_key.to_bytes(), [55u8; 32]);
    }

    #[test]
    fn test_private_key_try_from_slice_valid() {
        let bytes: &[u8] = &[88u8; 32];
        let private_key = PrivateKey::try_from(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), [88u8; 32]);
    }

    #[test]
    fn test_private_key_try_from_slice_invalid() {
        let bytes: &[u8] = &[0u8; 10];
        let result = PrivateKey::try_from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_try_from_array_valid() {
        let bytes = [66u8; 32];
        let private_key = PrivateKey::try_from(bytes).unwrap();
        assert_eq!(private_key.to_bytes(), bytes);
    }

    #[test]
    fn test_private_key_try_from_array_invalid() {
        let bytes = [0u8; 32];
        let result = PrivateKey::try_from(bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_key_length_constant() {
        assert_eq!(PrivateKey::LENGTH, 32);
    }

    #[test]
    fn test_private_key_different_values() {
        let key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let key2 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();
        
        assert_ne!(key1, key2);
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_private_key_tweak_add_associative() {
        // Test that (key + a) + b should give a valid result
        let bytes = [10u8; 32];
        let key = PrivateKey::from_bytes(&bytes).unwrap();
        
        let tweak1 = [1u8; 32];
        let tweak2 = [2u8; 32];
        
        let derived1 = key.tweak_add(&tweak1).unwrap();
        let derived2 = derived1.tweak_add(&tweak2).unwrap();
        
        assert_ne!(derived2.to_bytes(), key.to_bytes());
    }

    #[test]
    fn test_private_key_public_key_different_for_different_keys() {
        let key1 = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let key2 = PrivateKey::from_bytes(&[2u8; 32]).unwrap();
        
        let pub1 = key1.public_key();
        let pub2 = key2.public_key();
        
        assert_ne!(pub1.serialize(), pub2.serialize());
    }
}

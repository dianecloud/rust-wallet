//! Utility functions and convenience methods for common BIP32 operations.
//!
//! This module provides ergonomic wrappers around common patterns to reduce
//! boilerplate in application code.

use crate::{ExtendedPrivateKey, ExtendedPublicKey, Network, Result};

/// Generates a master keypair (both private and public) from a seed.
///
/// This is a convenience function that combines [`ExtendedPrivateKey::from_seed()`]
/// and [`ExtendedPrivateKey::to_extended_public_key()`] into a single call.
///
/// # Use Case
///
/// Most wallet applications need both the private key (for signing) and public key
/// (for address generation and watch-only mode). This function returns both in one call.
///
/// # Parameters
///
/// * `seed` - A cryptographic seed (typically 512 bits / 64 bytes from BIP39)
/// * `network` - The cryptocurrency network (Bitcoin mainnet, testnet, etc.)
///
/// # Returns
///
/// A tuple containing:
/// - `ExtendedPrivateKey` - Master private key for signing and private key derivation
/// - `ExtendedPublicKey` - Master public key for address generation and watch-only mode
///
/// Both keys have:
/// - `depth` = 0 (master keys)
/// - `parent_fingerprint` = [0, 0, 0, 0]
/// - `child_number` = 0
/// - Same chain code (required for key derivation)
///
/// # Errors
///
/// Returns an error if:
/// - The seed is too short (minimum 16 bytes recommended)
/// - The derived private key is invalid (extremely rare, < 2^-127 probability)
///
/// # Examples
///
/// ## Basic Usage
///
/// ```rust
/// use bip32::{utils::generate_master_keypair, Network};
///
/// let seed = [0x01; 64];
/// let (master_priv, master_pub) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // Both keys are ready to use
/// assert_eq!(master_priv.depth(), 0);
/// assert_eq!(master_pub.depth(), 0);
/// assert_eq!(master_priv.fingerprint(), master_pub.fingerprint());
/// # Ok::<(), bip32::Error>(())
/// ```
///
/// ## Complete Wallet Setup
///
/// ```rust
/// use bip32::{utils::generate_master_keypair, Network, DerivationPath};
/// use bip39::{Mnemonic, WordCount, Language};
/// use std::str::FromStr;
///
/// // 1. Generate mnemonic
/// let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
/// let seed = mnemonic.to_seed("")?;
///
/// // 2. Generate both keys at once
/// let (master_priv, master_pub) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // 3. Export for backup
/// let xprv = master_priv.to_string();  // Store securely
/// let xpub = master_pub.to_string();   // Can share for watch-only
///
/// assert!(xprv.starts_with("xprv"));
/// assert!(xpub.starts_with("xpub"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Equivalent to Manual Approach
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, utils::generate_master_keypair};
///
/// let seed = [0x02; 64];
///
/// // Using utility function
/// let (priv1, pub1) = generate_master_keypair(&seed, Network::BitcoinMainnet)?;
///
/// // Equivalent manual approach
/// let priv2 = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
/// let pub2 = priv2.to_extended_public_key();
///
/// // Results are identical
/// assert_eq!(priv1.private_key().to_bytes(), priv2.private_key().to_bytes());
/// assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
/// # Ok::<(), bip32::Error>(())
/// ```
pub fn generate_master_keypair(
    seed: &[u8],
    network: Network,
) -> Result<(ExtendedPrivateKey, ExtendedPublicKey)> {
    let private_key = ExtendedPrivateKey::from_seed(seed, network)?;
    let public_key = private_key.to_extended_public_key();
    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChildNumber;

    // ========================================================================
    // Task 59: Tests for generate_master_keypair()
    // ========================================================================

    #[test]
    fn test_generate_master_keypair_basic() {
        let seed = [0x01; 64];
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
        let (priv_key, pub_key) = result.unwrap();

        // Both should be master keys
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.parent_fingerprint(), &[0, 0, 0, 0]);
        assert_eq!(pub_key.parent_fingerprint(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_generate_master_keypair_fingerprints_match() {
        let seed = [0x02; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Private and public keys should have the same fingerprint
        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_generate_master_keypair_chain_codes_match() {
        let seed = [0x03; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Chain codes MUST be identical for derivation to work
        assert_eq!(priv_key.chain_code().as_bytes(), pub_key.chain_code().as_bytes());
    }

    #[test]
    fn test_generate_master_keypair_public_key_derives_from_private() {
        let seed = [0x04; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Public key should match private key's public key
        assert_eq!(
            pub_key.public_key().to_bytes(),
            priv_key.private_key().public_key().serialize()
        );
    }

    #[test]
    fn test_generate_master_keypair_mainnet() {
        let seed = [0x05; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(priv_key.network(), Network::BitcoinMainnet);
        assert_eq!(pub_key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_generate_master_keypair_testnet() {
        let seed = [0x06; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinTestnet).unwrap();

        assert_eq!(priv_key.network(), Network::BitcoinTestnet);
        assert_eq!(pub_key.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_generate_master_keypair_deterministic() {
        let seed = [0x07; 64];
        
        let (priv1, pub1) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();
        let (priv2, pub2) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Same seed should produce same keys
        assert_eq!(priv1.private_key().to_bytes(), priv2.private_key().to_bytes());
        assert_eq!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
    }

    #[test]
    fn test_generate_master_keypair_different_seeds() {
        let seed1 = [0x08; 64];
        let seed2 = [0x09; 64];
        
        let (priv1, pub1) = generate_master_keypair(&seed1, Network::BitcoinMainnet).unwrap();
        let (priv2, pub2) = generate_master_keypair(&seed2, Network::BitcoinMainnet).unwrap();

        // Different seeds should produce different keys
        assert_ne!(priv1.private_key().to_bytes(), priv2.private_key().to_bytes());
        assert_ne!(pub1.public_key().to_bytes(), pub2.public_key().to_bytes());
    }

    #[test]
    fn test_generate_master_keypair_equivalent_to_manual() {
        let seed = [0x0A; 64];
        
        // Using utility function
        let (util_priv, util_pub) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();
        
        // Manual approach
        let manual_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let manual_pub = manual_priv.to_extended_public_key();

        // Should be identical
        assert_eq!(util_priv.private_key().to_bytes(), manual_priv.private_key().to_bytes());
        assert_eq!(util_pub.public_key().to_bytes(), manual_pub.public_key().to_bytes());
        assert_eq!(util_priv.chain_code().as_bytes(), manual_priv.chain_code().as_bytes());
        assert_eq!(util_pub.chain_code().as_bytes(), manual_pub.chain_code().as_bytes());
    }

    #[test]
    fn test_generate_master_keypair_child_derivation_works() {
        let seed = [0x0B; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should be able to derive children from both keys
        let priv_child = priv_key.derive_child(ChildNumber::Normal(0)).unwrap();
        let pub_child = pub_key.derive_child(ChildNumber::Normal(0)).unwrap();

        // Children should have matching public keys
        assert_eq!(
            priv_child.private_key().public_key().serialize(),
            pub_child.public_key().to_bytes()
        );
    }

    #[test]
    fn test_generate_master_keypair_serialization() {
        let seed = [0x0C; 64];
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should be able to serialize both keys
        let xprv = priv_key.to_string();
        let xpub = pub_key.to_string();

        assert!(xprv.starts_with("xprv"));
        assert!(xpub.starts_with("xpub"));
    }

    #[test]
    fn test_generate_master_keypair_bip32_test_vector() {
        // BIP-32 Test Vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should produce valid master keys
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.child_number(), ChildNumber::Normal(0));
        assert_eq!(pub_key.child_number(), ChildNumber::Normal(0));
    }

    #[test]
    fn test_generate_master_keypair_with_mnemonic() {
        use bip39::{Language, Mnemonic};

        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English
        ).unwrap();
        
        let seed = mnemonic.to_seed("").unwrap();
        let (priv_key, pub_key) = generate_master_keypair(&seed, Network::BitcoinMainnet).unwrap();

        // Should work with BIP39-derived seeds
        assert_eq!(priv_key.depth(), 0);
        assert_eq!(pub_key.depth(), 0);
        assert_eq!(priv_key.fingerprint(), pub_key.fingerprint());
    }

    #[test]
    fn test_generate_master_keypair_min_seed_length() {
        let seed = [0x01; 16]; // Minimum recommended seed length
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_master_keypair_standard_seed_length() {
        let seed = [0x02; 64]; // Standard BIP39 seed length
        let result = generate_master_keypair(&seed, Network::BitcoinMainnet);

        assert!(result.is_ok());
    }
}

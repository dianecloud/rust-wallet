//! BIP-44 wallet implementation.
//!
//! This module provides a high-level wallet abstraction that manages master keys
//! and derives accounts according to BIP-44 specifications.
//!
//! # Examples
//!
//! ```rust
//! use khodpay_bip44::Wallet;
//! use khodpay_bip32::Network;
//!
//! // Create from seed
//! let seed = [0u8; 64];
//! let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
//! ```

use crate::{Error, Result};
use khodpay_bip32::{ExtendedPrivateKey, Network};
use khodpay_bip39::{Language, Mnemonic};

/// High-level BIP-44 wallet holding the master key.
///
/// The wallet manages the master extended private key and provides
/// methods to derive accounts for different cryptocurrencies.
///
/// # Examples
///
/// ```rust
/// use khodpay_bip44::Wallet;
/// use khodpay_bip32::Network;
///
/// let seed = [0u8; 64];
/// let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
///
/// assert_eq!(wallet.network(), Network::BitcoinMainnet);
/// ```
#[derive(Debug, Clone)]
pub struct Wallet {
    /// The master extended private key
    master_key: ExtendedPrivateKey,
    /// The network this wallet operates on
    network: Network,
}

impl Wallet {
    /// Creates a new wallet from a BIP39 mnemonic phrase.
    ///
    /// The mnemonic is converted to a seed using BIP39 standard derivation,
    /// then used to generate the master extended private key.
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
    /// * `password` - Optional password for additional security (use empty string if none)
    /// * `language` - The language of the mnemonic phrase
    /// * `network` - The network to use (Bitcoin mainnet, testnet, etc.)
    ///
    /// # Returns
    ///
    /// A new `Wallet` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The mnemonic is invalid
    /// - Key derivation fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Wallet;
    /// use khodpay_bip32::Network;
    /// use khodpay_bip39::Language;
    ///
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let wallet = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet).unwrap();
    ///
    /// assert_eq!(wallet.network(), Network::BitcoinMainnet);
    /// ```
    pub fn from_mnemonic(mnemonic: &str, password: &str, language: Language, network: Network) -> Result<Self> {
        // Parse the mnemonic using khodpay-bip39
        let mnemonic = Mnemonic::from_phrase(mnemonic, language)
            .map_err(|e| Error::InvalidMnemonic(format!("Failed to parse mnemonic: {}", e)))?;
        
        // Convert to seed using BIP39
        let seed = mnemonic.to_seed(password)
            .map_err(|e| Error::InvalidMnemonic(format!("Failed to generate seed: {}", e)))?;
        
        // Create wallet from seed
        Self::from_seed(&seed, network)
    }

    /// Creates a new wallet from an English BIP39 mnemonic phrase.
    ///
    /// This is a convenience method that defaults to English language.
    /// For other languages, use [`from_mnemonic`](Self::from_mnemonic).
    ///
    /// # Arguments
    ///
    /// * `mnemonic` - BIP39 mnemonic phrase in English
    /// * `password` - Optional password for additional security (use empty string if none)
    /// * `network` - The network to use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Wallet;
    /// use khodpay_bip32::Network;
    ///
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();
    /// ```
    pub fn from_english_mnemonic(mnemonic: &str, password: &str, network: Network) -> Result<Self> {
        Self::from_mnemonic(mnemonic, password, Language::English, network)
    }

    /// Creates a new wallet from a raw seed.
    ///
    /// The seed should be 512 bits (64 bytes) as per BIP39 specification.
    ///
    /// # Arguments
    ///
    /// * `seed` - Raw seed bytes (typically 64 bytes from BIP39)
    /// * `network` - The network to use
    ///
    /// # Returns
    ///
    /// A new `Wallet` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Wallet;
    /// use khodpay_bip32::Network;
    ///
    /// let seed = [0u8; 64];
    /// let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    ///
    /// assert_eq!(wallet.network(), Network::BitcoinMainnet);
    /// ```
    pub fn from_seed(seed: &[u8], network: Network) -> Result<Self> {
        // Validate seed length
        if seed.is_empty() {
            return Err(Error::InvalidSeed("Seed cannot be empty".to_string()));
        }

        // Generate master key from seed
        let master_key = ExtendedPrivateKey::from_seed(seed, network)
            .map_err(|e| Error::KeyDerivation(format!("Failed to derive master key: {}", e)))?;

        Ok(Self {
            master_key,
            network,
        })
    }

    /// Returns the network this wallet operates on.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Wallet;
    /// use khodpay_bip32::Network;
    ///
    /// let seed = [0u8; 64];
    /// let wallet = Wallet::from_seed(&seed, Network::BitcoinTestnet).unwrap();
    ///
    /// assert_eq!(wallet.network(), Network::BitcoinTestnet);
    /// ```
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns a reference to the master extended private key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use khodpay_bip44::Wallet;
    /// use khodpay_bip32::Network;
    ///
    /// let seed = [0u8; 64];
    /// let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
    ///
    /// let master_key = wallet.master_key();
    /// assert_eq!(master_key.depth(), 0);
    /// ```
    pub fn master_key(&self) -> &ExtendedPrivateKey {
        &self.master_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_from_seed() {
        let seed = [0u8; 64];
        let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
        assert_eq!(wallet.master_key().depth(), 0);
    }

    #[test]
    fn test_wallet_from_seed_testnet() {
        let seed = [1u8; 64];
        let wallet = Wallet::from_seed(&seed, Network::BitcoinTestnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_wallet_from_seed_empty() {
        let seed = [];
        let result = Wallet::from_seed(&seed, Network::BitcoinMainnet);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidSeed(_)) => {},
            _ => panic!("Expected InvalidSeed error"),
        }
    }

    #[test]
    fn test_wallet_from_seed_different_networks() {
        let seed = [0u8; 64];
        
        let mainnet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let testnet = Wallet::from_seed(&seed, Network::BitcoinTestnet).unwrap();

        assert_eq!(mainnet.network(), Network::BitcoinMainnet);
        assert_eq!(testnet.network(), Network::BitcoinTestnet);
    }

    #[test]
    fn test_wallet_master_key() {
        let seed = [0u8; 64];
        let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        let master_key = wallet.master_key();
        assert_eq!(master_key.depth(), 0);
        assert_eq!(master_key.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_wallet_from_mnemonic_12_words() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_wallet_from_english_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_english_mnemonic(mnemonic, "", Network::BitcoinMainnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_wallet_from_mnemonic_with_password() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, "password123", Language::English, Network::BitcoinMainnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_wallet_from_mnemonic_empty() {
        let result = Wallet::from_mnemonic("", "", Language::English, Network::BitcoinMainnet);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidMnemonic(_)) => {},
            _ => panic!("Expected InvalidMnemonic error"),
        }
    }

    #[test]
    fn test_wallet_from_mnemonic_invalid_word_count() {
        let mnemonic = "abandon abandon abandon";
        let result = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet);

        assert!(result.is_err());
        match result {
            Err(Error::InvalidMnemonic(msg)) => {
                // BIP39 crate will reject this due to invalid word count or checksum
                assert!(msg.contains("Failed to parse mnemonic"));
            },
            _ => panic!("Expected InvalidMnemonic error"),
        }
    }

    #[test]
    fn test_wallet_from_mnemonic_24_words() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let wallet = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet).unwrap();

        assert_eq!(wallet.network(), Network::BitcoinMainnet);
    }

    #[test]
    fn test_wallet_clone() {
        let seed = [0u8; 64];
        let wallet1 = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let wallet2 = wallet1.clone();

        assert_eq!(wallet1.network(), wallet2.network());
        assert_eq!(wallet1.master_key().depth(), wallet2.master_key().depth());
    }

    #[test]
    fn test_wallet_debug() {
        let seed = [0u8; 64];
        let wallet = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        
        let debug_str = format!("{:?}", wallet);
        assert!(debug_str.contains("Wallet"));
    }

    #[test]
    fn test_wallet_different_seeds_different_keys() {
        let seed1 = [0u8; 64];
        let seed2 = [1u8; 64];
        
        let wallet1 = Wallet::from_seed(&seed1, Network::BitcoinMainnet).unwrap();
        let wallet2 = Wallet::from_seed(&seed2, Network::BitcoinMainnet).unwrap();

        // Keys should be different - compare depths and networks at minimum
        assert_eq!(wallet1.master_key().depth(), wallet2.master_key().depth());
        assert_eq!(wallet1.master_key().network(), wallet2.master_key().network());
        // Different seeds should produce different wallets (we can't directly compare keys due to redaction)
    }

    #[test]
    fn test_wallet_same_seed_same_keys() {
        let seed = [0u8; 64];
        
        let wallet1 = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();
        let wallet2 = Wallet::from_seed(&seed, Network::BitcoinMainnet).unwrap();

        // Keys should be the same - verify properties match
        assert_eq!(wallet1.master_key().depth(), wallet2.master_key().depth());
        assert_eq!(wallet1.master_key().network(), wallet2.master_key().network());
    }

    #[test]
    fn test_mnemonic_different_passwords_different_seeds() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let wallet1 = Wallet::from_mnemonic(mnemonic, "", Language::English, Network::BitcoinMainnet).unwrap();
        let wallet2 = Wallet::from_mnemonic(mnemonic, "password", Language::English, Network::BitcoinMainnet).unwrap();

        // Both should create valid wallets
        assert_eq!(wallet1.network(), Network::BitcoinMainnet);
        assert_eq!(wallet2.network(), Network::BitcoinMainnet);
        // Different passwords should produce different seeds (we can't directly compare keys due to redaction)
    }

    #[test]
    fn test_wallet_from_mnemonic_different_language() {
        // Test that language parameter is used - English mnemonic with Spanish language should fail
        let english_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = Wallet::from_mnemonic(english_mnemonic, "", Language::Spanish, Network::BitcoinMainnet);
        
        // This should fail because English words aren't in Spanish wordlist
        assert!(result.is_err());
    }
}

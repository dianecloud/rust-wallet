//! # BIP32 - Hierarchical Deterministic Wallets
//!
//! A production-ready Rust implementation of the BIP32 standard for hierarchical deterministic
//! wallets in cryptocurrency applications.
//!
//! ## Overview
//!
//! BIP32 (Bitcoin Improvement Proposal 32) defines the standard for creating hierarchical
//! deterministic (HD) wallets. This allows generating a tree of key pairs from a single seed,
//! enabling backup and recovery of unlimited keys using just the initial seed.
//!
//! ## Features
//!
//! - **Full BIP32 Compliance** - Implements the complete BIP32 specification
//! - **Type-Safe API** - Leverages Rust's type system for safety
//! - **BIP39 Integration** - Seamlessly works with BIP39 mnemonics
//! - **Hardened & Normal Derivation** - Supports both derivation types
//! - **Network Support** - Bitcoin mainnet and testnet
//! - **Zero Unsafe Code** - Pure safe Rust implementation
//!
/// ## Quick Start
///
/// ```rust
/// use bip32::{ExtendedPrivateKey, Network, DerivationPath};
/// use bip39::{Mnemonic, WordCount, Language};
/// use std::str::FromStr;
///
/// // Generate a mnemonic (using BIP39)
/// let mnemonic = Mnemonic::generate(WordCount::Twelve, Language::English)?;
///
/// // Create master extended private key directly from mnemonic
/// let master_key = ExtendedPrivateKey::from_mnemonic(
///     &mnemonic,
///     None,  // Optional passphrase
///     Network::BitcoinMainnet
/// )?;
///
/// // Derive child keys using a BIP-44 path
/// let path = DerivationPath::from_str("m/44'/0'/0'")?;
/// let account_key = master_key.derive_path(&path)?;
///
/// assert_eq!(account_key.depth(), 3);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```

// Module declarations
mod chain_code;
mod child_number;
mod derivation_path;
mod error;
mod extended_private_key;
mod extended_public_key;
mod network;
mod private_key;
mod public_key;

/// Utility functions and convenience methods for common BIP32 operations.
///
/// This module provides ergonomic wrappers around common patterns to reduce
/// boilerplate in application code.
pub mod utils;

// Public re-exports
pub use chain_code::ChainCode;
pub use child_number::ChildNumber;
pub use derivation_path::DerivationPath;
pub use error::{Error, Result};
pub use extended_private_key::ExtendedPrivateKey;
pub use extended_public_key::ExtendedPublicKey;
pub use network::{KeyType, Network};
pub use private_key::PrivateKey;
pub use public_key::PublicKey;

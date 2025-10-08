//! Extended public key implementation for BIP32 hierarchical deterministic wallets.
//!
//! This module provides the ExtendedPublicKey type which combines a public key
//! with metadata necessary for hierarchical key derivation according to BIP-32.

use crate::{ChainCode, Network, PublicKey};

/// An extended public key for BIP32 hierarchical deterministic wallets.
///
/// Extended public keys combine a public key with additional metadata required for
/// hierarchical key derivation. Unlike extended private keys, extended public keys
/// can only derive non-hardened (normal) child keys.
///
/// # Structure
///
/// An extended public key contains:
/// - **Public Key**: The 33-byte compressed secp256k1 public key
/// - **Chain Code**: 32 bytes of entropy used in child key derivation
/// - **Depth**: The depth in the derivation tree (0 for master, 1 for level-1, etc.)
/// - **Parent Fingerprint**: First 4 bytes of parent public key hash (for identification)
/// - **Child Number**: The index of this key in its parent's children
/// - **Network**: The network this key is for (mainnet, testnet, etc.)
///
/// # Serialization Format
///
/// Extended public keys serialize to 78 bytes before Base58Check encoding:
/// ```text
/// [4 bytes]  version        (network-dependent, e.g., 0x0488B21E for mainnet)
/// [1 byte]   depth          (0x00 for master)
/// [4 bytes]  fingerprint    (0x00000000 for master)
/// [4 bytes]  child_number   (0x00000000 for master)
/// [32 bytes] chain_code     (entropy for derivation)
/// [33 bytes] key_data       (33-byte compressed public key)
/// ```
///
/// After Base58Check encoding, this becomes the familiar `xpub...` or `tpub...` string.
///
/// # Limitations
///
/// Extended public keys can only derive **normal (non-hardened)** child keys.
/// Hardened derivation requires the private key and cannot be performed with
/// only the public key. This is a security feature of BIP-32.
///
/// # Use Cases
///
/// Extended public keys are useful for:
/// - **Watch-only wallets**: Monitor balances without signing capability
/// - **Receiving addresses**: Generate new addresses without exposing private keys
/// - **Audit purposes**: Allow third parties to view transaction history
/// - **Point-of-sale systems**: Generate payment addresses without security risk
///
/// # Examples
///
/// ```rust,ignore
/// use bip32::{ExtendedPrivateKey, ExtendedPublicKey, Network};
///
/// // Generate master private key from seed
/// let seed = [0u8; 64];
/// let master_priv = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)?;
///
/// // Derive extended public key
/// let master_pub = master_priv.to_extended_public_key();
///
/// // Extended public key can derive normal children
/// let child_pub = master_pub.derive_child(0)?;  // OK - normal derivation
/// let hardened = master_pub.derive_child(0x80000000)?;  // ERROR - hardened not allowed
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    /// The network this key belongs to (Bitcoin mainnet, testnet, etc.)
    network: Network,

    /// Depth in the derivation tree.
    /// - 0 = master key
    /// - 1 = first-level child
    /// - 2 = second-level child
    /// - etc.
    ///
    /// Maximum depth is 255 according to BIP-32.
    depth: u8,

    /// The first 4 bytes of the parent key's public key hash (HASH160).
    /// Used to quickly identify the parent key.
    /// Set to [0, 0, 0, 0] for the master key.
    parent_fingerprint: [u8; 4],

    /// The child index used to derive this key from its parent.
    /// - Values 0 to 2^31-1 (0x7FFFFFFF): normal derivation (allowed)
    /// - Values 2^31 to 2^32-1 (0x80000000+): hardened derivation (NOT allowed)
    ///
    /// Set to 0 for the master key.
    ///
    /// **Important**: Extended public keys cannot derive hardened children.
    /// Attempting to derive a hardened child will result in an error.
    child_number: u32,

    /// The chain code used for deriving child keys.
    /// This provides additional entropy beyond the public key itself,
    /// enabling secure hierarchical key derivation.
    ///
    /// The chain code is the same for corresponding extended private and
    /// public key pairs.
    chain_code: ChainCode,

    /// The compressed secp256k1 public key (33 bytes).
    /// This is used for verification and deriving child public keys.
    public_key: PublicKey,
}

impl ExtendedPublicKey {
    /// The maximum allowed depth in the derivation tree.
    /// This is a BIP-32 specification limit.
    pub const MAX_DEPTH: u8 = 255;

    /// The threshold for hardened derivation.
    /// Child numbers >= this value are considered hardened.
    ///
    /// **Note**: Extended public keys cannot derive hardened children.
    pub const HARDENED_BIT: u32 = 0x80000000; // 2^31

    /// Creates a new `ExtendedPublicKey`.
    ///
    /// # Arguments
    ///
    /// * `network` - The network this key belongs to
    /// * `depth` - Depth in the derivation tree (0 for master)
    /// * `parent_fingerprint` - First 4 bytes of parent public key hash
    /// * `child_number` - Index of this child
    /// * `chain_code` - Chain code for derivation
    /// * `public_key` - The public key
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use bip32::{ExtendedPublicKey, PublicKey, ChainCode, Network};
    ///
    /// let public_key = PublicKey::from_bytes(&[/* ... */])?;
    /// let chain_code = ChainCode::from_bytes(&[/* ... */])?;
    ///
    /// let ext_pub = ExtendedPublicKey::new(
    ///     Network::BitcoinMainnet,
    ///     0,
    ///     [0, 0, 0, 0],
    ///     0,
    ///     chain_code,
    ///     public_key,
    /// );
    /// ```
    pub fn new(
        network: Network,
        depth: u8,
        parent_fingerprint: [u8; 4],
        child_number: u32,
        chain_code: ChainCode,
        public_key: PublicKey,
    ) -> Self {
        ExtendedPublicKey {
            network,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        }
    }

    /// Returns the network this key belongs to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the depth of this key in the derivation tree.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Returns the parent fingerprint.
    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    /// Returns the child number.
    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    /// Returns a reference to the chain code.
    pub fn chain_code(&self) -> &ChainCode {
        &self.chain_code
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl std::fmt::Debug for ExtendedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedPublicKey")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &hex::encode(self.chain_code.as_bytes()))
            .field("public_key", &self.public_key)
            .finish()
    }
}

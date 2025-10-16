# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-10-16

### Added

#### BIP39
- ✨ Full BIP39 specification implementation
- ✨ Support for 12, 15, 18, 21, and 24-word mnemonics
- ✨ Multi-language support (9 languages: English, Japanese, Korean, Spanish, French, Italian, Czech, Portuguese, Chinese Simplified)
- ✨ Cryptographically secure mnemonic generation using system CSPRNG
- ✨ PBKDF2-HMAC-SHA512 seed derivation with passphrase support
- ✨ Type-safe API with `WordCount` and `Language` enums
- ✨ Comprehensive error handling with descriptive error types
- ✨ Utility functions for common operations
- ✨ 184+ tests including unit, doc, and integration tests
- ✨ Performance benchmarks
- ✨ Complete documentation with examples

#### BIP32
- ✨ Full BIP32 hierarchical deterministic wallet implementation
- ✨ Master key generation from seed
- ✨ Extended private and public key support
- ✨ Hardened and normal child key derivation
- ✨ Derivation path parsing (e.g., "m/44'/0'/0'")
- ✨ Bitcoin mainnet and testnet network support
- ✨ Base58Check serialization (xprv/xpub format)
- ✨ Fingerprint calculation (HASH160)
- ✨ Watch-only wallet support via public key derivation
- ✨ Integration with BIP39 for mnemonic-based key generation
- ✨ Memory safety with zeroization of sensitive data
- ✨ Comprehensive test coverage including official BIP32 test vectors
- ✨ Performance benchmarks
- ✨ Full API documentation

#### Project
- 📄 Dual MIT/Apache-2.0 licensing
- 📚 Comprehensive README files for repository and each crate
- 📖 Integration guide with usage examples
- 🔧 Workspace configuration for multi-crate project
- 🧪 Extensive test coverage across all modules
- ⚡ Performance benchmarks
- 📝 API documentation
- 🔐 Security best practices documentation

### Security
- ✅ Zero unsafe code - pure safe Rust implementation
- ✅ Cryptographically secure random number generation
- ✅ Memory zeroization for sensitive data
- ✅ Type-safe API preventing common errors
- ✅ Validated against official BIP39 and BIP32 test vectors

### Performance
- ⚡ Optimized key derivation using secp256k1
- ⚡ Efficient PBKDF2 implementation
- ⚡ Minimal allocations
- ⚡ Zero-copy operations where possible

[Unreleased]: https://github.com/khodpay/khodpay-wallet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/khodpay/khodpay-wallet/releases/tag/v0.1.0

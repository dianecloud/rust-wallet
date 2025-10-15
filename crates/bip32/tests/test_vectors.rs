//! # BIP32 Official Test Vectors
//!
//! This module contains the official test vectors from the BIP32 specification.
//! These test vectors are used to verify compliance with the BIP32 standard.
//!
//! Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//!
//! ## Test Vectors Included:
//! - **Test Vector 1**: Basic derivation paths
//! - **Test Vector 2**: Maximum hardened derivation values
//! - **Test Vector 3**: Retention of leading zeros (bitpay/bitcore-lib#47)
//! - **Test Vector 4**: Retention of leading zeros (btcsuite/btcutil#172)
//! - **Test Vector 5**: Invalid extended keys (for error handling tests)

use bip32::{DerivationPath, ExtendedPrivateKey, Network};
use std::str::FromStr;

/// Represents a single derivation step in a test vector
#[derive(Debug, Clone)]
pub struct DerivationStep {
    /// The derivation path (e.g., "m", "m/0H", "m/0H/1")
    pub path: &'static str,
    /// Expected extended public key (xpub format)
    pub ext_pub: &'static str,
    /// Expected extended private key (xprv format)
    pub ext_prv: &'static str,
}

/// Represents a complete test vector with seed and derivation steps
#[derive(Debug, Clone)]
pub struct TestVector {
    /// Description of the test vector
    pub description: &'static str,
    /// The seed in hexadecimal format
    pub seed_hex: &'static str,
    /// All derivation steps for this test vector
    pub derivations: &'static [DerivationStep],
}

/// Test Vector 1 - Basic derivation paths
///
/// Seed: 000102030405060708090a0b0c0d0e0f
pub const TEST_VECTOR_1: TestVector = TestVector {
    description: "Test Vector 1: Basic derivation paths",
    seed_hex: "000102030405060708090a0b0c0d0e0f",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ext_prv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ext_prv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        },
        DerivationStep {
            path: "m/0H/1",
            ext_pub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            ext_prv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        },
        DerivationStep {
            path: "m/0H/1/2H",
            ext_pub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ext_prv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        },
        DerivationStep {
            path: "m/0H/1/2H/2",
            ext_pub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ext_prv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        },
        DerivationStep {
            path: "m/0H/1/2H/2/1000000000",
            ext_pub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ext_prv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        },
    ],
};

/// Test Vector 2 - Maximum hardened derivation values
///
/// Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
pub const TEST_VECTOR_2: TestVector = TestVector {
    description: "Test Vector 2: Maximum hardened derivation values",
    seed_hex: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            ext_prv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        },
        DerivationStep {
            path: "m/0",
            ext_pub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            ext_prv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        },
        DerivationStep {
            path: "m/0/2147483647H",
            ext_pub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            ext_prv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        },
        DerivationStep {
            path: "m/0/2147483647H/1",
            ext_pub: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            ext_prv: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        },
        DerivationStep {
            path: "m/0/2147483647H/1/2147483646H",
            ext_pub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            ext_prv: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        },
        DerivationStep {
            path: "m/0/2147483647H/1/2147483646H/2",
            ext_pub: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            ext_prv: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        },
    ],
};

/// Test Vector 3 - Retention of leading zeros
///
/// These vectors test for the retention of leading zeros.
/// See: https://github.com/bitpay/bitcore-lib/issues/47
/// See: https://github.com/iancoleman/bip39/issues/58
///
/// Seed: 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be
pub const TEST_VECTOR_3: TestVector = TestVector {
    description: "Test Vector 3: Retention of leading zeros (bitpay/bitcore-lib#47)",
    seed_hex: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            ext_prv: "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            ext_prv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
        },
    ],
};

/// Test Vector 4 - Retention of leading zeros (btcsuite)
///
/// These vectors test for the retention of leading zeros.
/// See: https://github.com/btcsuite/btcutil/issues/172
///
/// Seed: 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678
pub const TEST_VECTOR_4: TestVector = TestVector {
    description: "Test Vector 4: Retention of leading zeros (btcsuite/btcutil#172)",
    seed_hex: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    derivations: &[
        DerivationStep {
            path: "m",
            ext_pub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            ext_prv: "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
        },
        DerivationStep {
            path: "m/0H",
            ext_pub: "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            ext_prv: "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
        },
        DerivationStep {
            path: "m/0H/1H",
            ext_pub: "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            ext_prv: "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
        },
    ],
};

/// Invalid extended keys for error handling tests (Test Vector 5)
///
/// These test vectors contain invalid extended keys that should be rejected.
pub const INVALID_EXTENDED_KEYS: &[(&str, &str)] = &[
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        "pubkey version / prvkey mismatch"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        "prvkey version / pubkey mismatch"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        "invalid pubkey prefix 04"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        "invalid prvkey prefix 04"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        "invalid pubkey prefix 01"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        "invalid prvkey prefix 01"
    ),
    (
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        "zero depth with non-zero parent fingerprint"
    ),
    (
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        "zero depth with non-zero parent fingerprint"
    ),
    (
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        "zero depth with non-zero index"
    ),
    (
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        "zero depth with non-zero index"
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        "unknown extended key version"
    ),
    (
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        "unknown extended key version"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        "private key 0 not in 1..n-1"
    ),
    (
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        "private key n not in 1..n-1"
    ),
    (
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007"
    ),
    (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        "invalid checksum"
    ),
];

/// Returns all valid test vectors (1-4)
pub fn all_test_vectors() -> Vec<&'static TestVector> {
    vec![&TEST_VECTOR_1, &TEST_VECTOR_2, &TEST_VECTOR_3, &TEST_VECTOR_4]
}

/// Helper function to convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_1_accessibility() {
        assert_eq!(TEST_VECTOR_1.description, "Test Vector 1: Basic derivation paths");
        assert_eq!(TEST_VECTOR_1.seed_hex, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(TEST_VECTOR_1.derivations.len(), 6);
    }

    #[test]
    fn test_vector_2_accessibility() {
        assert_eq!(TEST_VECTOR_2.description, "Test Vector 2: Maximum hardened derivation values");
        assert_eq!(TEST_VECTOR_2.derivations.len(), 6);
    }

    #[test]
    fn test_vector_3_accessibility() {
        assert_eq!(TEST_VECTOR_3.description, "Test Vector 3: Retention of leading zeros (bitpay/bitcore-lib#47)");
        assert_eq!(TEST_VECTOR_3.derivations.len(), 2);
    }

    #[test]
    fn test_vector_4_accessibility() {
        assert_eq!(TEST_VECTOR_4.description, "Test Vector 4: Retention of leading zeros (btcsuite/btcutil#172)");
        assert_eq!(TEST_VECTOR_4.derivations.len(), 3);
    }

    #[test]
    fn test_invalid_keys_count() {
        assert_eq!(INVALID_EXTENDED_KEYS.len(), 16);
    }

    #[test]
    fn test_all_test_vectors_count() {
        assert_eq!(all_test_vectors().len(), 4);
    }

    #[test]
    fn test_hex_to_bytes_conversion() {
        let result = hex_to_bytes("000102030405060708090a0b0c0d0e0f");
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[15], 0x0f);
    }

    // ============================================================================
    // Test Vector 1 - Basic derivation paths
    // ============================================================================

    /// Helper function to validate a single derivation step
    fn validate_derivation_step(
        master_key: &ExtendedPrivateKey,
        step: &DerivationStep,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Parse the path
        let path = DerivationPath::from_str(step.path)?;

        // Derive the private key
        let derived_prv = master_key.derive_path(&path)?;
        let derived_prv_str = derived_prv.to_string();

        // Derive the public key
        let derived_pub = derived_prv.to_extended_public_key();
        let derived_pub_str = derived_pub.to_string();

        // Validate against expected values
        assert_eq!(
            derived_prv_str, step.ext_prv,
            "Private key mismatch for path {}\nExpected: {}\nGot:      {}",
            step.path, step.ext_prv, derived_prv_str
        );

        assert_eq!(
            derived_pub_str, step.ext_pub,
            "Public key mismatch for path {}\nExpected: {}\nGot:      {}",
            step.path, step.ext_pub, derived_pub_str
        );

        Ok(())
    }

    #[test]
    fn test_vector_1_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_1.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_1_derivation_m_0h() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H
        let step = &TEST_VECTOR_1.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1
        let step = &TEST_VECTOR_1.derivations[2];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1 derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H
        let step = &TEST_VECTOR_1.derivations[3];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h_2() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H/2
        let step = &TEST_VECTOR_1.derivations[4];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H/2 derivation");
    }

    #[test]
    fn test_vector_1_derivation_m_0h_1_2h_2_1000000000() {
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H/1/2H/2/1000000000
        let step = &TEST_VECTOR_1.derivations[5];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H/1/2H/2/1000000000 derivation");
    }

    #[test]
    fn test_vector_1_complete() {
        // Test all derivations in Test Vector 1 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_1.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_1.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 2 - Maximum hardened derivation values
    // ============================================================================

    #[test]
    fn test_vector_2_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_2.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_2_derivation_m_0() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0
        let step = &TEST_VECTOR_2.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0 derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H
        let step = &TEST_VECTOR_2.derivations[2];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1
        let step = &TEST_VECTOR_2.derivations[3];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1 derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1_2147483646h() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1/2147483646H
        let step = &TEST_VECTOR_2.derivations[4];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1/2147483646H derivation");
    }

    #[test]
    fn test_vector_2_derivation_m_0_2147483647h_1_2147483646h_2() {
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0/2147483647H/1/2147483646H/2
        let step = &TEST_VECTOR_2.derivations[5];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0/2147483647H/1/2147483646H/2 derivation");
    }

    #[test]
    fn test_vector_2_complete() {
        // Test all derivations in Test Vector 2 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_2.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_2.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 3 - Retention of leading zeros
    // ============================================================================

    #[test]
    fn test_vector_3_master_key() {
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test the master key (m)
        let master_step = &TEST_VECTOR_3.derivations[0];
        assert_eq!(master_step.path, "m");

        let master_prv_str = master_key.to_string();
        let master_pub_str = master_key.to_extended_public_key().to_string();

        assert_eq!(
            master_prv_str, master_step.ext_prv,
            "Master private key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_prv, master_prv_str
        );

        assert_eq!(
            master_pub_str, master_step.ext_pub,
            "Master public key mismatch\nExpected: {}\nGot:      {}",
            master_step.ext_pub, master_pub_str
        );
    }

    #[test]
    fn test_vector_3_derivation_m_0h() {
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        // Test m/0H
        let step = &TEST_VECTOR_3.derivations[1];
        validate_derivation_step(&master_key, step)
            .expect("Failed to validate m/0H derivation");
    }

    #[test]
    fn test_vector_3_complete() {
        // Test all derivations in Test Vector 3 in one comprehensive test
        let seed = hex_to_bytes(TEST_VECTOR_3.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_3.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }

    // ============================================================================
    // Test Vector 4 - Additional leading zeros tests
    // ============================================================================

    #[test]
    fn test_vector_4_complete() {
        // Test all derivations in Test Vector 4
        let seed = hex_to_bytes(TEST_VECTOR_4.seed_hex).expect("Failed to decode seed");
        let master_key = ExtendedPrivateKey::from_seed(&seed, Network::BitcoinMainnet)
            .expect("Failed to create master key");

        for step in TEST_VECTOR_4.derivations {
            validate_derivation_step(&master_key, step)
                .unwrap_or_else(|e| panic!("Failed to validate path {}: {}", step.path, e));
        }
    }
}

# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@khodpay.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Security Best Practices

### For Users of This Library

1. **Keep Dependencies Updated**
   - Regularly update to the latest version
   - Monitor security advisories
   - Run `cargo audit` regularly

2. **Protect Sensitive Data**
   - Never log or print mnemonics, seeds, or private keys
   - Store sensitive data encrypted at rest
   - Use secure memory practices (this library uses `zeroize`)
   - Never transmit sensitive data over insecure channels

3. **Validate Inputs**
   - Always validate user-provided mnemonics
   - Check derivation paths for validity
   - Handle errors appropriately

4. **Environment Security**
   - Use this library only in secure environments
   - Ensure your system's RNG is properly seeded
   - Keep your operating system and dependencies updated

### For Contributors

1. **Code Security**
   - Never use `unsafe` code without thorough review
   - Follow Rust security best practices
   - Use cryptographically secure primitives
   - Validate all inputs and handle errors properly

2. **Testing**
   - Write security-focused test cases
   - Test edge cases and error conditions
   - Use fuzzing for cryptographic code
   - Validate against official test vectors

3. **Dependencies**
   - Minimize dependencies
   - Use well-audited cryptographic libraries
   - Keep dependencies updated
   - Review dependency code for security issues

4. **Review Process**
   - All changes require code review
   - Security-sensitive changes require extra scrutiny
   - Run security audits before releases

## Known Security Considerations

### BIP39 Implementation

1. **Entropy Source**
   - Uses system CSPRNG (`rand::thread_rng()`)
   - Ensure your system has sufficient entropy
   - Consider using hardware RNG for production

2. **Mnemonic Storage**
   - Never store mnemonics in plain text
   - Use encrypted storage with strong passwords
   - Consider hardware wallets for key storage

3. **Passphrase Protection**
   - Passphrases provide additional security
   - Lost passphrases cannot be recovered
   - Use strong, memorable passphrases

### BIP32 Implementation

1. **Private Key Protection**
   - Private keys are zeroized after use
   - Never expose private keys in logs or errors
   - Use hardened derivation for account-level keys

2. **Path Derivation**
   - Validate derivation paths before use
   - Use standard paths (BIP44/49/84) when possible
   - Understand hardened vs. normal derivation

3. **Serialization**
   - Extended private keys (xprv) contain sensitive data
   - Only share extended public keys (xpub) when necessary
   - Never transmit xprv over insecure channels

## Cryptographic Primitives

This library uses the following cryptographic primitives:

- **PBKDF2-HMAC-SHA512**: Seed derivation (BIP39)
- **HMAC-SHA512**: Key derivation (BIP32)
- **secp256k1**: Elliptic curve operations
- **SHA-256**: Hashing
- **RIPEMD-160**: Address generation

All primitives are provided by well-audited Rust crates.

## Audit History

- **v0.1.0** (2024-10-16): Initial release, no external audit yet

We plan to commission professional security audits for future releases.

## Responsible Disclosure

We follow the principle of responsible disclosure:

1. Reporter submits vulnerability privately
2. We confirm and investigate the issue
3. We develop and test a fix
4. We release a security patch
5. We publicly disclose the vulnerability after users have had time to update

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. We will:

- Release a patch version with the fix
- Update the security advisory
- Notify users through GitHub releases and security advisories
- Update documentation with mitigation steps

## Additional Resources

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [BIP39 Security Considerations](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#security-considerations)
- [BIP32 Security Considerations](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#security)

## Contact

- **Security Email**: security@khodpay.com
- **General Support**: support@khodpay.com
- **GitHub Issues**: For non-security bugs only

Thank you for helping keep KhodPay Wallet Libraries secure!

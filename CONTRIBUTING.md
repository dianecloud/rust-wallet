# Contributing to KhodPay Wallet Libraries

Thank you for your interest in contributing to the KhodPay Wallet Libraries! We welcome contributions from the community.

## 🚀 Getting Started

### Prerequisites

- Rust 1.70 or higher
- Git
- Familiarity with cryptocurrency wallet concepts (BIP32, BIP39)

### Setting Up Your Development Environment

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/khodpay-wallet.git
   cd khodpay-wallet
   ```

2. **Build the project:**
   ```bash
   cargo build
   ```

3. **Run the tests:**
   ```bash
   cargo test
   ```

4. **Run the benchmarks:**
   ```bash
   cargo bench
   ```

## 📝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- A clear, descriptive title
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Your environment (OS, Rust version, etc.)
- Any relevant code snippets or error messages

### Suggesting Enhancements

We welcome feature requests! Please create an issue with:
- A clear, descriptive title
- Detailed description of the proposed feature
- Use cases and benefits
- Any relevant examples or mockups

### Pull Requests

1. **Create a new branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes:**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Ensure all tests pass

3. **Commit your changes:**
   ```bash
   git commit -m "Add feature: description of your changes"
   ```
   
   Follow conventional commit format:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test additions or changes
   - `refactor:` for code refactoring
   - `perf:` for performance improvements
   - `chore:` for maintenance tasks

4. **Push to your fork:**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** on GitHub

## ✅ Code Standards

### Code Style

- Follow Rust's official style guidelines
- Run `cargo fmt` before committing
- Run `cargo clippy` and address all warnings
- Keep functions focused and well-documented

### Testing

- Write unit tests for all new functionality
- Ensure existing tests still pass
- Add integration tests for complex features
- Update doc tests in code documentation
- Aim for high test coverage

### Documentation

- Add doc comments for all public APIs
- Include usage examples in doc comments
- Update README files when adding features
- Keep documentation clear and concise

## 🔒 Security

### Reporting Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Instead, please email security@khodpay.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Considerations

When contributing code that handles sensitive data:
- Never log or print sensitive information (seeds, private keys, mnemonics)
- Use `zeroize` for sensitive data in memory
- Avoid unsafe code
- Follow cryptographic best practices
- Validate all inputs
- Handle errors appropriately

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific crate tests
cargo test -p khodpay-bip39
cargo test -p khodpay-bip32

# Run doc tests
cargo test --doc

# Run integration tests
cargo test --test '*'
```

### Writing Tests

- Test both success and error cases
- Use descriptive test names
- Test edge cases
- Validate against official test vectors when available
- Keep tests focused and isolated

## 📊 Performance

### Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench benchmarks
```

### Performance Guidelines

- Profile before optimizing
- Benchmark significant changes
- Document performance characteristics
- Avoid premature optimization
- Consider both speed and memory usage

## 📚 Documentation

### Building Documentation

```bash
# Build and open documentation
cargo doc --open --no-deps

# Build documentation for all crates
cargo doc --workspace
```

### Documentation Standards

- Use clear, concise language
- Include code examples
- Document all public APIs
- Explain complex algorithms
- Link to relevant specifications (BIP32, BIP39, etc.)

## 🔄 Review Process

1. **Automated Checks:** All PRs must pass CI/CD checks:
   - Tests must pass
   - Code must compile without warnings
   - Formatting must be correct
   - Clippy must pass

2. **Code Review:** Maintainers will review your PR:
   - Code quality and style
   - Test coverage
   - Documentation
   - Security considerations

3. **Feedback:** Address any requested changes

4. **Merge:** Once approved, your PR will be merged

## 📋 Checklist

Before submitting a PR, ensure:

- [ ] Code builds without errors or warnings
- [ ] All tests pass (`cargo test`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Clippy passes without warnings (`cargo clippy`)
- [ ] New functionality has tests
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated (if applicable)
- [ ] Commit messages follow conventions
- [ ] PR description explains changes clearly

## 🎯 Areas for Contribution

We especially welcome contributions in these areas:

- Additional language support for BIP39
- Performance improvements
- Additional test coverage
- Documentation improvements
- Bug fixes
- Examples and tutorials
- Integration with other standards (BIP44, BIP49, BIP84)
- WASM support
- Hardware wallet integration examples

## 💬 Communication

- **Issues:** Use GitHub issues for bugs and feature requests
- **Discussions:** Use GitHub discussions for questions and general discussion
- **Email:** contact@khodpay.com for other inquiries

## 📜 License

By contributing to this project, you agree that your contributions will be dual-licensed under MIT and Apache-2.0, matching the project's license.

## 🙏 Recognition

Contributors will be recognized in:
- CHANGELOG.md for significant contributions
- Release notes
- Project documentation

Thank you for contributing to the KhodPay Wallet Libraries! 🚀

# Publishing Guide

This guide explains how to publish the KhodPay Wallet Libraries to crates.io.

## Prerequisites

1. **Crates.io Account**
   - Create an account at [crates.io](https://crates.io/)
   - Get your API token from [Account Settings](https://crates.io/settings/tokens)

2. **Login to Cargo**
   ```bash
   cargo login <your-api-token>
   ```

3. **Verify Metadata**
   - Ensure all `Cargo.toml` files have correct metadata
   - Verify repository URLs
   - Check license information
   - Confirm description and keywords

## Pre-Publication Checklist

Before publishing, ensure:

- [ ] All tests pass: `cargo test --workspace`
- [ ] Code is formatted: `cargo fmt --all`
- [ ] Clippy passes: `cargo clippy --all-targets -- -D warnings`
- [ ] Documentation builds: `cargo doc --workspace --no-deps`
- [ ] Benchmarks run: `cargo bench --workspace`
- [ ] CHANGELOG.md is updated
- [ ] Version numbers are correct
- [ ] README files are up to date
- [ ] All examples work
- [ ] Git repository is clean
- [ ] All changes are committed

## Version Numbers

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: Backwards-compatible functionality
- **PATCH** version: Backwards-compatible bug fixes

Update version in:
- `crates/bip39/Cargo.toml` (package name: `khodpay-bip39`)
- `crates/bip32/Cargo.toml` (package name: `khodpay-bip32`)
- `CHANGELOG.md`

## Publishing Steps

### Step 1: Verify Package Contents

Check what will be published:

```bash
# For bip39
cd crates/bip39
cargo package --list

# For bip32
cd crates/bip32
cargo package --list
```

Ensure all necessary files are included and no sensitive files are accidentally included.

### Step 2: Dry Run

Perform a dry run to catch any issues:

```bash
# For bip39
cd crates/bip39
cargo publish --dry-run

# For bip32
cd crates/bip32
cargo publish --dry-run
```

Fix any warnings or errors that appear.

### Step 3: Publish khodpay-bip39 First

Since khodpay-bip32 depends on khodpay-bip39, publish khodpay-bip39 first:

```bash
cd crates/bip39
cargo publish
```

Wait for the crate to be available on crates.io (usually takes a few minutes).

### Step 4: Verify Dependency

Ensure `crates/bip32/Cargo.toml` has the correct dependency:

```toml
[dependencies]
khodpay-bip39 = { version = "0.1.0", path = "../bip39" }
```

This will automatically resolve to the published version when users install from crates.io.

### Step 5: Publish khodpay-bip32

```bash
cd crates/bip32
cargo publish
```

### Step 6: Create Git Tag

After successful publication:

```bash
git tag -a v0.1.0 -m "Release version 0.1.0"
git push origin v0.1.0
```

### Step 7: Create GitHub Release

1. Go to GitHub repository
2. Click "Releases" → "Create a new release"
3. Select the tag you just created
4. Add release notes from CHANGELOG.md
5. Publish the release

## Post-Publication

1. **Verify Installation**
   ```bash
   cargo add khodpay-bip39 --dry-run
   cargo add khodpay-bip32 --dry-run
   ```

2. **Test Documentation**
   - Visit https://docs.rs/khodpay-bip39
   - Visit https://docs.rs/khodpay-bip32
   - Verify documentation is correct

3. **Update README Badges**
   - Verify crates.io badges work
   - Verify docs.rs badges work

4. **Announce Release**
   - Twitter/X
   - Reddit (r/rust, r/cryptocurrency)
   - Rust community forums
   - Project blog or website

## Troubleshooting

### Issue: "crate name already taken"

**Note:** This repository already uses the names `khodpay-bip39` and `khodpay-bip32` to avoid conflicts with existing crates on crates.io.

### Issue: "failed to verify package"

Common causes:
- Missing files in package
- Path dependencies not resolved
- Tests failing during verification

Solution: Use `--no-verify` flag (not recommended) or fix the underlying issue.

### Issue: "documentation failed to build"

- Check `cargo doc` builds locally
- Fix any documentation warnings
- Ensure all dependencies have docs

### Issue: "version already published"

- You cannot overwrite a published version
- Increment the version number
- Publish the new version

## Best Practices

1. **Test Thoroughly**
   - Run full test suite before publishing
   - Test on multiple platforms if possible
   - Verify examples work

2. **Documentation**
   - Ensure all public APIs are documented
   - Include usage examples
   - Add doc tests where appropriate

3. **Changelog**
   - Keep CHANGELOG.md updated
   - Follow "Keep a Changelog" format
   - List all breaking changes clearly

4. **Versioning**
   - Follow semantic versioning strictly
   - Document breaking changes
   - Consider deprecation warnings before breaking changes

5. **Dependencies**
   - Keep dependencies minimal
   - Use specific version ranges
   - Audit dependencies regularly

## Yanking a Release

If you need to yank a published version (doesn't delete it, but warns users):

```bash
cargo yank --version 0.1.0 khodpay-bip39
```

To un-yank:

```bash
cargo yank --undo --version 0.1.0 khodpay-bip39
```

**Note:** Only yank if there's a critical security issue or major bug. Prefer publishing a patch version instead.

## Continuous Publishing

For automated publishing via CI/CD:

1. Store `CARGO_REGISTRY_TOKEN` in GitHub Secrets
2. Update `.github/workflows/publish.yml`
3. Trigger on version tags

Example workflow snippet:

```yaml
name: Publish

on:
  push:
    tags:
      - 'v*'

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo publish --token ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

## Support

If you encounter issues during publication:

- Check [Cargo documentation](https://doc.rust-lang.org/cargo/reference/publishing.html)
- Visit [Rust Users Forum](https://users.rust-lang.org/)
- Ask in [Rust Discord](https://discord.gg/rust-lang)
- Email: support@khodpay.com

## References

- [Publishing on crates.io](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [Semantic Versioning](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

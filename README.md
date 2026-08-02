# soroban-drift

[![CI](https://github.com/Hollujay/soroban-drift/actions/workflows/ci.yml/badge.svg)](https://github.com/Hollujay/soroban-drift/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A static-analysis CLI that detects breaking changes between two versions of a Soroban smart contract's Rust source — storage layout drift, dropped or weakened require_auth() checks, and function signature changes — before you deploy an upgrade.

## What this is (and isn't)

soroban-drift is a drift/diff checker, not a security auditor. It does not:

- Provide any security guarantee or audit certification
- Perform semantic or logic analysis
- Detect all possible breaking changes

It checks three things, precisely:

- **Storage layout drift** — changed, removed, or type-changed storage keys
- **Auth requirement regressions** — functions that dropped or weakened a require_auth() / require_auth_for_args() call between versions
- **Signature changes** — informational diff of function signatures, read from the compiled WASM's contractspecv0 section

## Quick start

Requires Rust (stable, edition 2021) and the Stellar CLI if you want to build the example fixtures yourself.

```bash
git clone https://github.com/Hollujay/soroban-drift.git
cd soroban-drift
cargo build --release
```

Run it against the included example fixtures:

```bash
./target/release/soroban-drift-cli examples/breaking-upgrade/old examples/breaking-upgrade/new
# Soroban Drift Report
#
# - **Old version**: `examples/breaking-upgrade/old`
# - **New version**: `examples/breaking-upgrade/new`
# - **Status**: BREAKING CHANGES DETECTED
#
# ## Breaking Changes
#
# - **storage**
#   - Storage key 'Balance' has field type changes
#   - Old: `amount: i128, owner: Address`
#   - New: `amount: u32, owner: Address`
#
# - **auth**
#   - Function 'transfer' dropped require_auth()
#   - Old: `require_auth`
#   - New: `(none)`
#
# ## Warnings
#
# - **auth**
#   - Function 'admin_op' changed from require_auth() to require_auth_for_args()
#   - Old: `require_auth`
#   - New: `require_auth_for_args`
```

`--format json|markdown` and `--fail-on breaking|warning|none` are both supported — the latter is useful for wiring this into CI, exiting non-zero when breaking changes are found.

Not yet published to crates.io; build from source for now.

## Architecture

```
rust-parser  → parses contract source into an AST
  ├─ storage-extractor  → extracts storage key/type schema
  └─ auth-extractor     → extracts require_auth() call sites
spec-extractor           → reads function signatures from compiled WASM
  ↓
diff-engine  → compares old vs. new, classifies each change by severity
  ↓
report-generator → JSON / Markdown / CI exit code
```

Storage and auth analysis operate on Rust source, not the compiled WASM — the WASM's contractspecv0 section only exposes function/type signatures, not storage key usage, so source-level analysis is what makes the storage and auth checks possible at all.

## Contributing

See CONTRIBUTING.md for development setup, code style, and how to submit a PR. Security issues should be reported privately — see SECURITY.md.

## Maintainers

| Name | GitHub |
|---|---|
| Hollujay | [@Hollujay](https://github.com/Hollujay) |

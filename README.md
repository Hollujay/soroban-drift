# soroban-drift

Static-analysis CLI tool that detects breaking changes between two versions of a Soroban smart contract's Rust source.

## What it checks

- **Storage layout drift** — changed, removed, or type-changed storage keys (extracted from `#[contracttype]` definitions and `env.storage()` call sites)
- **Auth requirement regressions** — public functions that dropped or weakened a `require_auth()` / `require_auth_for_args()` call
- **Signature changes** — informational diff of function signatures, extracted from the compiled WASM's `contractspecv0` custom section

## What it does NOT do

- General security auditing
- Semantic or logic diffing
- Gas or fee regression analysis

## Usage

```bash
# Compare two source directories
cargo run -- examples/safe-upgrade/old examples/safe-upgrade/new

# With WASM spec files
cargo run -- --old-wasm old.wasm --new-wasm new.wasm path/to/old path/to/new

# JSON output, fail only on breaking changes
cargo run -- --format json --fail-on breaking path/to/old path/to/new
```

### Options

- `old`, `new` — paths to contract crate source directories (positional, required)
- `--old-wasm`, `--new-wasm` — paths to compiled WASM files (optional, enables signature analysis)
- `--format <json|markdown>` — output format (default: markdown)
- `--fail-on <breaking|warning|none>` — exit code behavior (default: breaking)

### Exit codes

- `0` — no findings at the configured severity level
- `1` — findings found at or above the configured severity level

## Project structure

```
soroban-drift/
├── Cargo.toml              # workspace root
├── packages/
│   ├── core/               # analysis library
│   └── cli/                # CLI binary
└── examples/
    ├── safe-upgrade/        # contract with no breaking changes
    └── breaking-upgrade/    # contract with storage + auth regressions
```

## Building

```bash
cargo build
cargo test
```

## License

MIT OR Apache-2.0

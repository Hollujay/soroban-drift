# Contributing

## Development

```bash
cargo build
cargo test
```

### Code style

- `cargo fmt` before committing
- `cargo clippy` — no warnings
- No `unwrap()` outside `#[cfg(test)]` blocks
- No floating point types
- `snake_case` for functions/modules, `PascalCase` for types

### Adding a fixture

1. Create a directory under `examples/<name>/old/` and `examples/<name>/new/`
2. Add Soroban contract source files to each
3. Add integration tests in `packages/core/tests/`

## Commit conventions

```
<type>(<scope>): <description>

types: feat, fix, test, refactor, docs, chore
scopes: core, cli, ci, examples
```

One commit per logical unit of work. Every commit builds and passes tests.

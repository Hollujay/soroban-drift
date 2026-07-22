use std::path::Path;

/// Test that the safe-upgrade old version parses without errors.
#[test]
fn safe_upgrade_old_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/safe-upgrade/old");
    let ast = soroban_drift_core::rust_parser::parse_crate(&path).unwrap();
    assert_eq!(
        ast.storage_keys.len(),
        2,
        "safe-upgrade old should have 2 storage keys"
    );
    assert_eq!(
        ast.functions.len(),
        3,
        "safe-upgrade old should have 3 public functions (init, transfer, balance)"
    );
}

/// Test that the safe-upgrade new version parses without errors.
#[test]
fn safe_upgrade_new_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/safe-upgrade/new");
    let ast = soroban_drift_core::rust_parser::parse_crate(&path).unwrap();
    assert_eq!(
        ast.storage_keys.len(),
        2,
        "safe-upgrade new should have 2 storage keys"
    );
    assert_eq!(
        ast.functions.len(),
        4,
        "safe-upgrade new should have 4 public functions (init, transfer, transfer_from, balance)"
    );
}

/// Test that the breaking-upgrade old version parses without errors.
#[test]
fn breaking_upgrade_old_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/breaking-upgrade/old");
    let ast = soroban_drift_core::rust_parser::parse_crate(&path).unwrap();
    assert_eq!(
        ast.storage_keys.len(),
        2,
        "breaking-upgrade old should have 2 storage keys"
    );
    assert_eq!(
        ast.functions.len(),
        4,
        "breaking-upgrade old should have 4 public functions"
    );
}

/// Test that the breaking-upgrade new version parses without errors.
#[test]
fn breaking_upgrade_new_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/breaking-upgrade/new");
    let ast = soroban_drift_core::rust_parser::parse_crate(&path).unwrap();
    assert_eq!(
        ast.storage_keys.len(),
        2,
        "breaking-upgrade new should have 2 storage keys"
    );
    assert_eq!(
        ast.functions.len(),
        4,
        "breaking-upgrade new should have 4 public functions"
    );
}

/// Full diff: safe-upgrade should have no breaking changes.
#[test]
fn safe_upgrade_no_breaking_changes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/safe-upgrade");

    let old_ast = soroban_drift_core::rust_parser::parse_crate(&base.join("old")).unwrap();
    let new_ast = soroban_drift_core::rust_parser::parse_crate(&base.join("new")).unwrap();

    let findings = soroban_drift_core::diff_engine::diff(
        &old_ast.storage_keys,
        &new_ast.storage_keys,
        &old_ast.functions,
        &new_ast.functions,
        &soroban_drift_core::types::ContractSpec::default(),
        &soroban_drift_core::types::ContractSpec::default(),
    );

    let breaking: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == soroban_drift_core::types::Severity::Breaking)
        .collect();
    assert!(
        breaking.is_empty(),
        "safe-upgrade should have no breaking changes, found: {:?}",
        breaking
    );
}

/// Full diff: breaking-upgrade should have breaking changes.
#[test]
fn breaking_upgrade_has_breaking_changes() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/breaking-upgrade");

    let old_ast = soroban_drift_core::rust_parser::parse_crate(&base.join("old")).unwrap();
    let new_ast = soroban_drift_core::rust_parser::parse_crate(&base.join("new")).unwrap();

    let findings = soroban_drift_core::diff_engine::diff(
        &old_ast.storage_keys,
        &new_ast.storage_keys,
        &old_ast.functions,
        &new_ast.functions,
        &soroban_drift_core::types::ContractSpec::default(),
        &soroban_drift_core::types::ContractSpec::default(),
    );

    let breaking: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == soroban_drift_core::types::Severity::Breaking)
        .collect();
    assert_eq!(
        breaking.len(),
        2,
        "breaking-upgrade should have 2 breaking changes (storage field type + dropped auth)"
    );
}

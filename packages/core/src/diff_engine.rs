use crate::types::*;
use std::collections::HashMap;

/// Compare two contract versions and produce a list of findings.
///
/// This is the core diff logic. It compares:
/// - Storage schema: added/removed/changed storage keys
/// - Auth requirements: added/removed/weakened auth calls per function
/// - Function signatures: added/removed/changed functions
///
/// Storage changes are classified as:
///   - Breaking: removed key, changed field type
///   - Warning: added key (new keys don't break old readers but may indicate drift)
///   - Info: field name change detection when type unchanged
///
/// Auth changes are classified as:
///   - Breaking: function dropped require_auth() entirely
///   - Warning: function changed from require_auth() to require_auth_for_args()
///   (weakening but not fully removing auth)
///
/// Signature changes are classified as Info.
pub fn diff(
    old_storage: &[StorageKey],
    new_storage: &[StorageKey],
    old_auth: &[FunctionAuth],
    new_auth: &[FunctionAuth],
    old_spec: &ContractSpec,
    new_spec: &ContractSpec,
) -> Vec<DriftFinding> {
    let mut findings = Vec::new();

    diff_storage(old_storage, new_storage, &mut findings);
    diff_auth(old_auth, new_auth, &mut findings);
    diff_spec(old_spec, new_spec, &mut findings);

    findings
}

fn diff_storage(
    old: &[StorageKey],
    new: &[StorageKey],
    findings: &mut Vec<DriftFinding>,
) {
    let old_map: HashMap<&str, &StorageKey> = old.iter().map(|k| (k.name.as_str(), k)).collect();
    let new_map: HashMap<&str, &StorageKey> = new.iter().map(|k| (k.name.as_str(), k)).collect();

    // Check for removed keys
    for (name, old_key) in &old_map {
        match new_map.get(name) {
            None => {
                findings.push(DriftFinding {
                    severity: Severity::Breaking,
                    category: "storage".to_string(),
                    message: format!("Storage key '{}' was removed", name),
                    old_value: Some(format!("{:?}", old_key)),
                    new_value: None,
                });
            }
            Some(new_key) => {
                // Same name, check for type changes
                if old_key.kind != new_key.kind {
                    findings.push(DriftFinding {
                        severity: Severity::Breaking,
                        category: "storage".to_string(),
                        message: format!(
                            "Storage key '{}' changed from {:?} to {:?}",
                            name, old_key.kind, new_key.kind
                        ),
                        old_value: Some(format!("{:?}", old_key.kind)),
                        new_value: Some(format!("{:?}", new_key.kind)),
                    });
                }
                // Check field changes
                if old_key.fields != new_key.fields {
                    let old_fields: Vec<String> = old_key
                        .fields
                        .iter()
                        .map(|f| format!("{}: {}", f.name, f.ty))
                        .collect();
                    let new_fields: Vec<String> = new_key
                        .fields
                        .iter()
                        .map(|f| format!("{}: {}", f.name, f.ty))
                        .collect();

                    if old_fields != new_fields {
                        // Check if any field types changed (breaking)
                        let has_type_change = old_key.fields.iter().zip(&new_key.fields).any(
                            |(old_f, new_f)| old_f.name == new_f.name && old_f.ty != new_f.ty,
                        );

                        if has_type_change {
                            findings.push(DriftFinding {
                                severity: Severity::Breaking,
                                category: "storage".to_string(),
                                message: format!(
                                    "Storage key '{}' has field type changes",
                                    name
                                ),
                                old_value: Some(old_fields.join(", ")),
                                new_value: Some(new_fields.join(", ")),
                            });
                        } else {
                            findings.push(DriftFinding {
                                severity: Severity::Info,
                                category: "storage".to_string(),
                                message: format!(
                                    "Storage key '{}' fields changed (names/layout)",
                                    name
                                ),
                                old_value: Some(old_fields.join(", ")),
                                new_value: Some(new_fields.join(", ")),
                            });
                        }
                    }
                }
            }
        }
    }

    // Check for added keys (Warning level — new keys don't break old readers)
    for (name, new_key) in &new_map {
        if !old_map.contains_key(name) {
            findings.push(DriftFinding {
                severity: Severity::Warning,
                category: "storage".to_string(),
                message: format!("Storage key '{}' was added", name),
                old_value: None,
                new_value: Some(format!("{:?}", new_key)),
            });
        }
    }
}

fn diff_auth(
    old: &[FunctionAuth],
    new: &[FunctionAuth],
    findings: &mut Vec<DriftFinding>,
) {
    let old_map: HashMap<&str, &FunctionAuth> =
        old.iter().map(|f| (f.function_name.as_str(), f)).collect();
    let new_map: HashMap<&str, &FunctionAuth> =
        new.iter().map(|f| (f.function_name.as_str(), f)).collect();

    for (name, old_fn) in &old_map {
        match new_map.get(name) {
            None => {
                findings.push(DriftFinding {
                    severity: Severity::Info,
                    category: "auth".to_string(),
                    message: format!("Function '{}' was removed", name),
                    old_value: Some(format!("{:?}", old_fn)),
                    new_value: None,
                });
            }
            Some(new_fn) => {
                // Check if auth was dropped (Breaking)
                if old_fn.has_require_auth && !new_fn.has_require_auth {
                    if new_fn.has_require_auth_for_args {
                        findings.push(DriftFinding {
                            severity: Severity::Warning,
                            category: "auth".to_string(),
                            message: format!(
                                "Function '{}' changed from require_auth() to require_auth_for_args()",
                                name
                            ),
                            old_value: Some("require_auth".to_string()),
                            new_value: Some("require_auth_for_args".to_string()),
                        });
                    } else {
                        findings.push(DriftFinding {
                            severity: Severity::Breaking,
                            category: "auth".to_string(),
                            message: format!(
                                "Function '{}' dropped require_auth()",
                                name
                            ),
                            old_value: Some("require_auth".to_string()),
                            new_value: Some("(none)".to_string()),
                        });
                    }
                }
                if old_fn.has_require_auth_for_args && !new_fn.has_require_auth_for_args
                    && !new_fn.has_require_auth
                {
                    findings.push(DriftFinding {
                        severity: Severity::Breaking,
                        category: "auth".to_string(),
                        message: format!(
                            "Function '{}' dropped require_auth_for_args()",
                            name
                        ),
                        old_value: Some("require_auth_for_args".to_string()),
                        new_value: Some("(none)".to_string()),
                    });
                }
            }
        }
    }

    // Check for new functions
    for (name, new_fn) in &new_map {
        if !old_map.contains_key(name) {
            findings.push(DriftFinding {
                severity: Severity::Info,
                category: "auth".to_string(),
                message: format!("Function '{}' was added", name),
                old_value: None,
                new_value: Some(format!("{:?}", new_fn)),
            });
        }
    }
}

fn diff_spec(
    old: &ContractSpec,
    new: &ContractSpec,
    findings: &mut Vec<DriftFinding>,
) {
    let old_map: HashMap<&str, &FunctionSpec> =
        old.functions.iter().map(|f| (f.name.as_str(), f)).collect();
    let new_map: HashMap<&str, &FunctionSpec> =
        new.functions.iter().map(|f| (f.name.as_str(), f)).collect();

    for (name, old_fn) in &old_map {
        match new_map.get(name) {
            None => {
                findings.push(DriftFinding {
                    severity: Severity::Info,
                    category: "signature".to_string(),
                    message: format!("Function '{}' was removed from spec", name),
                    old_value: None,
                    new_value: None,
                });
            }
            Some(new_fn) => {
                if old_fn.inputs != new_fn.inputs || old_fn.outputs != new_fn.outputs {
                    findings.push(DriftFinding {
                        severity: Severity::Info,
                        category: "signature".to_string(),
                        message: format!("Function '{}' signature changed", name),
                        old_value: Some(format!(
                            "({:?}) -> ({:?})",
                            old_fn.inputs, old_fn.outputs
                        )),
                        new_value: Some(format!(
                            "({:?}) -> ({:?})",
                            new_fn.inputs, new_fn.outputs
                        )),
                    });
                }
            }
        }
    }

    for (name, _) in &new_map {
        if !old_map.contains_key(name) {
            findings.push(DriftFinding {
                severity: Severity::Info,
                category: "signature".to_string(),
                message: format!("Function '{}' was added to spec", name),
                old_value: None,
                new_value: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_storage_key(name: &str, kind: StorageKeyKind, fields: Vec<(&str, &str)>) -> StorageKey {
        StorageKey {
            name: name.to_string(),
            kind,
            fields: fields
                .into_iter()
                .map(|(n, t)| FieldInfo {
                    name: n.to_string(),
                    ty: t.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn removed_storage_key_is_breaking() {
        let old = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "i128")])];
        let new = vec![];
        let findings = diff(&old, &new, &[], &[], &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Breaking && f.category == "storage"));
    }

    #[test]
    fn added_storage_key_is_warning() {
        let old = vec![];
        let new = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "i128")])];
        let findings = diff(&old, &new, &[], &[], &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Warning && f.category == "storage"));
    }

    #[test]
    fn changed_field_type_is_breaking() {
        let old = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "i128")])];
        let new = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "u32")])];
        let findings = diff(&old, &new, &[], &[], &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Breaking && f.category == "storage"));
    }

    #[test]
    fn unchanged_storage_no_findings() {
        let old = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "i128")])];
        let new = vec![make_storage_key("Balance", StorageKeyKind::Struct, vec![("amount", "i128")])];
        let findings = diff(&old, &new, &[], &[], &ContractSpec::default(), &ContractSpec::default());
        assert!(!findings.iter().any(|f| f.category == "storage"));
    }

    #[test]
    fn dropped_require_auth_is_breaking() {
        let old = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let new = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: false,
            has_require_auth_for_args: false,
        }];
        let findings = diff(&[], &[], &old, &new, &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Breaking && f.category == "auth"));
    }

    #[test]
    fn auth_to_auth_for_args_is_warning() {
        let old = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let new = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: false,
            has_require_auth_for_args: true,
        }];
        let findings = diff(&[], &[], &old, &new, &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Warning && f.category == "auth"));
    }

    #[test]
    fn dropped_auth_for_args_is_breaking() {
        let old = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: false,
            has_require_auth_for_args: true,
        }];
        let new = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: false,
            has_require_auth_for_args: false,
        }];
        let findings = diff(&[], &[], &old, &new, &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Breaking && f.category == "auth"));
    }

    #[test]
    fn unchanged_auth_no_findings() {
        let old = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let new = vec![FunctionAuth {
            function_name: "transfer".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let findings = diff(&[], &[], &old, &new, &ContractSpec::default(), &ContractSpec::default());
        assert!(!findings.iter().any(|f| f.category == "auth"));
    }

    #[test]
    fn key_kind_change_is_breaking() {
        let old = vec![StorageKey {
            name: "DataKey".to_string(),
            kind: StorageKeyKind::Enum,
            fields: vec![],
        }];
        let new = vec![StorageKey {
            name: "DataKey".to_string(),
            kind: StorageKeyKind::Struct,
            fields: vec![],
        }];
        let findings = diff(&old, &new, &[], &[], &ContractSpec::default(), &ContractSpec::default());
        assert!(findings.iter().any(|f| f.severity == Severity::Breaking && f.category == "storage"));
    }

    #[test]
    fn signature_changes_are_info() {
        let old_spec = ContractSpec {
            functions: vec![FunctionSpec {
                name: "transfer".to_string(),
                inputs: vec![ParamInfo { name: "to".to_string(), ty: "Address".to_string() }],
                outputs: vec![],
            }],
        };
        let new_spec = ContractSpec {
            functions: vec![FunctionSpec {
                name: "transfer".to_string(),
                inputs: vec![ParamInfo { name: "to".to_string(), ty: "i128".to_string() }],
                outputs: vec![],
            }],
        };
        let findings = diff(&[], &[], &[], &[], &old_spec, &new_spec);
        assert!(findings.iter().any(|f| f.severity == Severity::Info && f.category == "signature"));
    }

    #[test]
    fn no_changes_yields_empty_findings() {
        let old_s = vec![make_storage_key("K", StorageKeyKind::Struct, vec![("x", "u32")])];
        let new_s = vec![make_storage_key("K", StorageKeyKind::Struct, vec![("x", "u32")])];
        let old_a = vec![FunctionAuth {
            function_name: "f".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let new_a = vec![FunctionAuth {
            function_name: "f".to_string(),
            has_require_auth: true,
            has_require_auth_for_args: false,
        }];
        let spec = ContractSpec::default();
        let findings = diff(&old_s, &new_s, &old_a, &new_a, &spec, &spec);
        assert!(findings.is_empty());
    }
}

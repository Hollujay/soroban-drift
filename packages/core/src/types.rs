use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Breaking,
    Warning,
    Info,
}

/// A storage key extracted from a contract's source code.
/// This represents a `#[contracttype]`-annotated type used
/// as a storage key in the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageKey {
    pub name: String,
    pub kind: StorageKeyKind,
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageKeyKind {
    Struct,
    Enum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub ty: String,
}

/// A set of storage keys found in a contract version.
pub type StorageSchema = HashMap<String, StorageKey>;

/// Auth call information extracted for each public function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAuth {
    pub function_name: String,
    pub has_require_auth: bool,
    pub has_require_auth_for_args: bool,
}

/// Function signature parsed from the WASM contract spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub name: String,
    pub inputs: Vec<ParamInfo>,
    pub outputs: Vec<ParamInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamInfo {
    pub name: String,
    pub ty: String,
}

/// Full contract spec parsed from the WASM contractspecv0 section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ContractSpec {
    pub functions: Vec<FunctionSpec>,
}

/// A single diff finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftFinding {
    pub severity: Severity,
    pub category: String,
    pub message: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Full drift report comparing two contract versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftReport {
    pub old_path: String,
    pub new_path: String,
    pub findings: Vec<DriftFinding>,
    pub has_breaking_changes: bool,
}

/// AST representation of a contract crate.
#[derive(Debug, Clone)]
pub struct ContractAst {
    pub storage_keys: Vec<StorageKey>,
    pub functions: Vec<FunctionAuth>,
}

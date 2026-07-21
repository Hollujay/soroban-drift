use crate::types::StorageKey;
use std::fs;
use std::path::Path;
use syn::{Expr, ExprMethodCall};
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum StorageExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error in {path}: {message}")]
    Parse { path: String, message: String },
    #[error("Walk error: {0}")]
    Walk(#[from] walkdir::Error),
}

/// Storage access type detected in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageAccess {
    Persistent,
    Instance,
    Temporary,
}

/// A detected storage write call (e.g., env.storage().persistent().set(&key, &value)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageWrite {
    pub key_expr: String,
    pub access: StorageAccess,
}

/// Extract storage schema (contracttype definitions) from the given crate directory.
///
/// Storage writes are detected by matching the method chain pattern:
/// `env.storage().<access>().set(&key, ...)`.
/// Complex key expressions (e.g., keys built via macro or function call)
/// will be reported as the raw expression string, not resolved to a name.
pub fn extract_storage_schema(path: &Path) -> Result<Vec<StorageKey>, StorageExtractError> {
    let mut keys = Vec::new();

    for entry in WalkDir::new(path).into_iter() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }

        let content = fs::read_to_string(p)?;
        let syntax = syn::parse_file(&content).map_err(|e| StorageExtractError::Parse {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;

        for item in &syntax.items {
            if let syn::Item::Struct(s) = item {
                if has_contracttype_attr(&s.attrs) {
                    keys.push(crate::rust_parser::extract_struct_key(s));
                }
            }
            if let syn::Item::Enum(e) = item {
                if has_contracttype_attr(&e.attrs) {
                    keys.push(crate::rust_parser::extract_enum_key(e));
                }
            }
        }
    }

    Ok(keys)
}

fn has_contracttype_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .map(|seg| seg.ident == "contracttype")
            .unwrap_or(false)
    })
}

/// Extract storage write call sites from a crate.
/// Returns a list of storage writes found in all source files.
pub fn extract_storage_writes(path: &Path) -> Result<Vec<StorageWrite>, StorageExtractError> {
    let mut writes = Vec::new();

    for entry in WalkDir::new(path).into_iter() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }

        let content = fs::read_to_string(p)?;
        let syntax = syn::parse_file(&content).map_err(|e| StorageExtractError::Parse {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;

        find_storage_writes_in_file(&syntax, &mut writes);
    }

    Ok(writes)
}

fn find_storage_writes_in_file(file: &syn::File, writes: &mut Vec<StorageWrite>) {
    for item in &file.items {
        match item {
            syn::Item::Fn(f) => {
                find_storage_writes_in_block(&f.block, writes);
            }
            syn::Item::Impl(impl_item) => {
                for inner in &impl_item.items {
                    if let syn::ImplItem::Fn(method) = inner {
                        find_storage_writes_in_block(&method.block, writes);
                    }
                }
            }
            _ => {}
        }
    }
}

fn find_storage_writes_in_block(block: &syn::Block, writes: &mut Vec<StorageWrite>) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                find_storage_writes_in_expr(expr, writes);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    find_storage_writes_in_expr(&init.expr, writes);
                }
            }
            _ => {}
        }
    }
}

fn find_storage_writes_in_expr(expr: &Expr, writes: &mut Vec<StorageWrite>) {
    match expr {
        Expr::MethodCall(call) => {
            check_storage_method_call(call, writes);
        }
        Expr::Block(e) => {
            for stmt in &e.block.stmts {
                match stmt {
                    syn::Stmt::Expr(expr, _) => {
                        find_storage_writes_in_expr(expr, writes);
                    }
                    syn::Stmt::Local(local) => {
                        if let Some(init) = &local.init {
                            find_storage_writes_in_expr(&init.expr, writes);
                        }
                    }
                    _ => {}
                }
            }
        }
        Expr::If(if_expr) => {
            for stmt in &if_expr.then_branch.stmts {
                match stmt {
                    syn::Stmt::Expr(expr, _) => {
                        find_storage_writes_in_expr(expr, writes);
                    }
                    syn::Stmt::Local(local) => {
                        if let Some(init) = &local.init {
                            find_storage_writes_in_expr(&init.expr, writes);
                        }
                    }
                    _ => {}
                }
            }
            if let Some((_, else_branch)) = &if_expr.else_branch {
                find_storage_writes_in_expr(else_branch, writes);
            }
        }
        Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                find_storage_writes_in_expr(&arm.body, writes);
            }
        }
        _ => {}
    }
}

fn check_storage_method_call(call: &ExprMethodCall, writes: &mut Vec<StorageWrite>) {
    let method_name = call.method.to_string();

    if method_name == "set" {
        if let Expr::MethodCall(inner) = &*call.receiver {
            let access_str = inner.method.to_string();
            let access = match access_str.as_str() {
                "persistent" => Some(StorageAccess::Persistent),
                "instance" => Some(StorageAccess::Instance),
                "temporary" => Some(StorageAccess::Temporary),
                _ => None,
            };

            if let Some(access) = access {
                if let Some(key_arg) = call.args.first() {
                    writes.push(StorageWrite {
                        key_expr: quote::quote!(#key_arg).to_string(),
                        access,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_rs(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("lib.rs");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", content).unwrap();
        (dir, path)
    }

    #[test]
    fn detect_persistent_storage_write() {
        let content = r#"
pub fn set_data(env: Env) {
    env.storage().persistent().set(&DataKey::Admin, &"value");
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let writes = extract_storage_writes(path.parent().unwrap()).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].access, StorageAccess::Persistent);
    }

    #[test]
    fn detect_instance_storage_write() {
        let content = r#"
pub fn set_data(env: Env) {
    env.storage().instance().set(&DataKey::Admin, &"value");
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let writes = extract_storage_writes(path.parent().unwrap()).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].access, StorageAccess::Instance);
    }

    #[test]
    fn detect_temporary_storage_write() {
        let content = r#"
pub fn set_data(env: Env) {
    env.storage().temporary().set(&key, &val);
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let writes = extract_storage_writes(path.parent().unwrap()).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].access, StorageAccess::Temporary);
    }

    #[test]
    fn extract_schema_from_crate() {
        let content = r#"
#[contracttype]
pub struct Balance {
    pub amount: i128,
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let keys = extract_storage_schema(path.parent().unwrap()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "Balance");
    }
}

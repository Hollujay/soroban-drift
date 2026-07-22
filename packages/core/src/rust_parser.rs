use crate::types::{ContractAst, FieldInfo, FunctionAuth, StorageKey, StorageKeyKind};
use std::fs;
use std::path::Path;
use syn::{Attribute, File, ItemEnum, ItemStruct};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("Syntax error in {path} at line {line}: {message}")]
    Syntax {
        path: String,
        line: usize,
        message: String,
    },
    #[error("Walk error: {0}")]
    Walk(#[from] walkdir::Error),
}

/// Parse all Rust source files in the given crate directory.
///
/// Returns a `ContractAst` containing storage key definitions and
/// function auth information found in the source.
///
/// This does NOT guarantee completeness on macro-generated code.
/// Storage keys produced by proc macros (e.g., `#[contractimport]`)
/// are not visible to syn and will be missed.
pub fn parse_crate(path: &Path) -> Result<ContractAst, ParseError> {
    let mut storage_keys = Vec::new();
    let mut functions = Vec::new();

    for entry in walkdir::WalkDir::new(path).into_iter() {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().map(|e| e != "rs").unwrap_or(true) {
            continue;
        }

        let content = fs::read_to_string(p).map_err(|e| ParseError::Io {
            path: p.display().to_string(),
            source: e,
        })?;

        let syntax = syn::parse_file(&content).map_err(|e| ParseError::Syntax {
            path: p.display().to_string(),
            line: 0,
            message: e.to_string(),
        })?;

        extract_from_file(&syntax, &mut storage_keys, &mut functions);
    }

    Ok(ContractAst {
        storage_keys,
        functions,
    })
}

fn extract_from_file(
    file: &File,
    storage_keys: &mut Vec<StorageKey>,
    functions: &mut Vec<FunctionAuth>,
) {
    for item in &file.items {
        match item {
            syn::Item::Struct(s) => {
                if has_contracttype_attr(&s.attrs) {
                    storage_keys.push(extract_struct_key(s));
                }
            }
            syn::Item::Enum(e) => {
                if has_contracttype_attr(&e.attrs) {
                    storage_keys.push(extract_enum_key(e));
                }
            }
            syn::Item::Fn(f) => {
                let fn_name = f.sig.ident.to_string();
                if matches!(f.vis, syn::Visibility::Public(_)) {
                    let (has_auth, has_auth_for_args) = extract_auth_from_fn(f);
                    functions.push(FunctionAuth {
                        function_name: fn_name,
                        has_require_auth: has_auth,
                        has_require_auth_for_args: has_auth_for_args,
                    });
                }
            }
            syn::Item::Impl(impl_item) => {
                for inner in &impl_item.items {
                    if let syn::ImplItem::Fn(method) = inner {
                        let fn_name = method.sig.ident.to_string();
                        if matches!(method.vis, syn::Visibility::Public(_)) {
                            let (has_auth, has_auth_for_args) =
                                extract_auth_from_sig_and_block(&method.sig, &method.block);
                            functions.push(FunctionAuth {
                                function_name: fn_name,
                                has_require_auth: has_auth,
                                has_require_auth_for_args: has_auth_for_args,
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_auth_from_sig_and_block(_sig: &syn::Signature, block: &syn::Block) -> (bool, bool) {
    let mut has_auth = false;
    let mut has_auth_for_args = false;
    check_block_for_auth(block, &mut has_auth, &mut has_auth_for_args);
    (has_auth, has_auth_for_args)
}

fn has_contracttype_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .map(|seg| seg.ident == "contracttype")
            .unwrap_or(false)
    })
}

fn field_type_to_string(ty: &syn::Type) -> String {
    format_type(ty)
}

fn format_type(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(tp) => {
            let segments: Vec<String> = tp
                .path
                .segments
                .iter()
                .map(|seg| {
                    let base = seg.ident.to_string();
                    match &seg.arguments {
                        syn::PathArguments::None => base,
                        syn::PathArguments::AngleBracketed(generic) => {
                            let args: Vec<String> = generic
                                .args
                                .iter()
                                .map(|arg| match arg {
                                    syn::GenericArgument::Type(t) => format_type(t),
                                    syn::GenericArgument::Lifetime(l) => l.ident.to_string(),
                                    _ => "...".to_string(),
                                })
                                .collect();
                            format!("{}<{}>", base, args.join(", "))
                        }
                        _ => base,
                    }
                })
                .collect();
            segments.join("::")
        }
        syn::Type::Reference(r) => {
            let mut s = String::from("&");
            if r.mutability.is_some() {
                s.push_str("mut ");
            }
            s.push_str(&format_type(&r.elem));
            s
        }
        _ => {
            // Fallback: use the Debug representation
            format!("{:?}", ty)
        }
    }
}

pub(crate) fn extract_struct_key(s: &ItemStruct) -> StorageKey {
    let fields = s
        .fields
        .iter()
        .map(|f| {
            let name = f.ident.as_ref().map(|i| i.to_string()).unwrap_or_default();
            let ty = field_type_to_string(&f.ty);
            FieldInfo { name, ty }
        })
        .collect();

    StorageKey {
        name: s.ident.to_string(),
        kind: StorageKeyKind::Struct,
        fields,
    }
}

pub(crate) fn extract_enum_key(e: &ItemEnum) -> StorageKey {
    let fields = e
        .variants
        .iter()
        .map(|v| {
            let name = v.ident.to_string();
            let ty = match &v.fields {
                syn::Fields::Unit => "()".to_string(),
                syn::Fields::Unnamed(f) => {
                    let types: Vec<String> = f
                        .unnamed
                        .iter()
                        .map(|field| field_type_to_string(&field.ty))
                        .collect();
                    types.join(", ")
                }
                syn::Fields::Named(f) => {
                    let types: Vec<String> = f
                        .named
                        .iter()
                        .map(|field| field_type_to_string(&field.ty))
                        .collect();
                    types.join(", ")
                }
            };
            FieldInfo { name, ty }
        })
        .collect();

    StorageKey {
        name: e.ident.to_string(),
        kind: StorageKeyKind::Enum,
        fields,
    }
}

fn extract_auth_from_fn(f: &syn::ItemFn) -> (bool, bool) {
    let mut has_auth = false;
    let mut has_auth_for_args = false;
    check_block_for_auth(&f.block, &mut has_auth, &mut has_auth_for_args);
    (has_auth, has_auth_for_args)
}

fn check_block_for_auth(block: &syn::Block, has_auth: &mut bool, has_auth_for_args: &mut bool) {
    for stmt in &block.stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                check_expr_for_auth(expr, has_auth, has_auth_for_args);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    check_expr_for_auth(&init.expr, has_auth, has_auth_for_args);
                }
            }
            _ => {}
        }
    }
}

fn check_expr_for_auth(expr: &syn::Expr, has_auth: &mut bool, has_auth_for_args: &mut bool) {
    match expr {
        syn::Expr::MethodCall(call) => {
            let method_name = call.method.to_string();
            if method_name == "require_auth" {
                *has_auth = true;
            }
            if method_name == "require_auth_for_args" {
                *has_auth_for_args = true;
            }
        }
        syn::Expr::Block(e) => {
            check_block_for_auth(&e.block, has_auth, has_auth_for_args);
        }
        syn::Expr::If(if_expr) => {
            check_block_for_auth(&if_expr.then_branch, has_auth, has_auth_for_args);
            if let Some((_, else_branch)) = &if_expr.else_branch {
                check_expr_for_auth(else_branch, has_auth, has_auth_for_args);
            }
        }
        syn::Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                check_expr_for_auth(&arm.body, has_auth, has_auth_for_args);
            }
        }
        _ => {}
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
    fn parse_struct_contracttype() {
        let content = r#"
#[contracttype]
pub struct Balance {
    pub amount: i128,
    pub owner: Address,
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.storage_keys.len(), 1);
        assert_eq!(ast.storage_keys[0].name, "Balance");
        assert_eq!(ast.storage_keys[0].kind, StorageKeyKind::Struct);
        assert_eq!(ast.storage_keys[0].fields.len(), 2);
    }

    #[test]
    fn parse_enum_contracttype() {
        let content = r#"
#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.storage_keys.len(), 1);
        assert_eq!(ast.storage_keys[0].name, "DataKey");
        assert_eq!(ast.storage_keys[0].kind, StorageKeyKind::Enum);
        assert_eq!(ast.storage_keys[0].fields.len(), 2);
    }

    #[test]
    fn parse_require_auth() {
        let content = r#"
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.functions.len(), 1);
        assert!(ast.functions[0].has_require_auth);
        assert!(!ast.functions[0].has_require_auth_for_args);
    }

    #[test]
    fn parse_require_auth_for_args() {
        let content = r#"
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth_for_args((&amount,));
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.functions.len(), 1);
        assert!(!ast.functions[0].has_require_auth);
        assert!(ast.functions[0].has_require_auth_for_args);
    }

    #[test]
    fn private_function_not_analyzed() {
        let content = r#"
fn internal_helper(env: Env) {
    env.storage().instance().set(&"key", &"val");
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.functions.len(), 0);
    }

    #[test]
    fn skip_non_contracttype() {
        let content = r#"
pub struct NotContractType {
    pub x: u32,
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let ast = parse_crate(path.parent().unwrap()).unwrap();
        assert_eq!(ast.storage_keys.len(), 0);
    }
}

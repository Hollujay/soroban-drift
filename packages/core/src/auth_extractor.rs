use crate::types::FunctionAuth;
use std::fs;
use std::path::Path;
use syn::Expr;
use thiserror::Error;
use walkdir::WalkDir;

#[derive(Error, Debug)]
pub enum AuthExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error in {path}: {message}")]
    Parse { path: String, message: String },
    #[error("Walk error: {0}")]
    Walk(#[from] walkdir::Error),
}

/// Extract auth requirements from all public functions in the crate.
///
/// Checks for calls to `require_auth()` and `require_auth_for_args()`
/// in public function bodies. Functions without either call are still
/// reported with `has_require_auth: false`.
///
/// This does NOT detect auth calls hidden inside proc macros or
/// cross-function call chains (e.g., a private helper that calls
/// require_auth for the public caller).
pub fn extract_auth(path: &Path) -> Result<Vec<FunctionAuth>, AuthExtractError> {
    let mut functions = Vec::new();

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
        let syntax = syn::parse_file(&content).map_err(|e| AuthExtractError::Parse {
            path: p.display().to_string(),
            message: e.to_string(),
        })?;

        for item in &syntax.items {
            match item {
                syn::Item::Fn(f) => {
                    let fn_name = f.sig.ident.to_string();
                    if matches!(f.vis, syn::Visibility::Public(_)) {
                        let (has_auth, has_auth_for_args) = extract_auth_from_block(&f.block);
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
                                let (has_auth, has_auth_for_args) = extract_auth_from_block(&method.block);
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

    Ok(functions)
}

fn extract_auth_from_block(block: &syn::Block) -> (bool, bool) {
    let mut has_auth = false;
    let mut has_auth_for_args = false;
    check_block_stmts(&block.stmts, &mut has_auth, &mut has_auth_for_args);
    (has_auth, has_auth_for_args)
}

fn check_block_stmts(
    stmts: &[syn::Stmt],
    has_auth: &mut bool,
    has_auth_for_args: &mut bool,
) {
    for stmt in stmts {
        match stmt {
            syn::Stmt::Expr(expr, _) => {
                check_expr(expr, has_auth, has_auth_for_args);
            }
            syn::Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    check_expr(&init.expr, has_auth, has_auth_for_args);
                }
            }
            _ => {}
        }
    }
}

fn check_expr(expr: &Expr, has_auth: &mut bool, has_auth_for_args: &mut bool) {
    match expr {
        Expr::MethodCall(call) => {
            let method = call.method.to_string();
            match method.as_str() {
                "require_auth" => *has_auth = true,
                "require_auth_for_args" => *has_auth_for_args = true,
                _ => {}
            }
        }
        Expr::Block(e) => {
            check_block_stmts(&e.block.stmts, has_auth, has_auth_for_args);
        }
        Expr::If(if_expr) => {
            check_block_stmts(&if_expr.then_branch.stmts, has_auth, has_auth_for_args);
            if let Some((_, else_branch)) = &if_expr.else_branch {
                check_expr(else_branch, has_auth, has_auth_for_args);
            }
        }
        Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                check_expr(&arm.body, has_auth, has_auth_for_args);
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
    fn detect_require_auth() {
        let content = r#"
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let funcs = extract_auth(path.parent().unwrap()).unwrap();
        assert_eq!(funcs.len(), 1);
        assert!(funcs[0].has_require_auth);
        assert!(!funcs[0].has_require_auth_for_args);
    }

    #[test]
    fn detect_require_auth_for_args() {
        let content = r#"
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth_for_args((&amount,));
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let funcs = extract_auth(path.parent().unwrap()).unwrap();
        assert_eq!(funcs.len(), 1);
        assert!(!funcs[0].has_require_auth);
        assert!(funcs[0].has_require_auth_for_args);
    }

    #[test]
    fn no_auth_call() {
        let content = r#"
pub fn read_balance(env: Env) -> i128 {
    env.storage().instance().get(&DataKey::Balance).unwrap_or(0)
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let funcs = extract_auth(path.parent().unwrap()).unwrap();
        assert_eq!(funcs.len(), 1);
        assert!(!funcs[0].has_require_auth);
        assert!(!funcs[0].has_require_auth_for_args);
    }

    #[test]
    fn skip_private_functions() {
        let content = r#"
fn internal(env: Env) {
    from.require_auth();
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let funcs = extract_auth(path.parent().unwrap()).unwrap();
        assert_eq!(funcs.len(), 0);
    }

    #[test]
    fn auth_in_if_branch() {
        let content = r#"
pub fn admin_op(env: Env, admin: Address) {
    if admin != Address::random(&env) {
        admin.require_auth();
    }
}
"#;
        let (_dir, path) = create_temp_rs(content);
        let funcs = extract_auth(path.parent().unwrap()).unwrap();
        assert_eq!(funcs.len(), 1);
        assert!(funcs[0].has_require_auth);
    }
}

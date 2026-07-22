use clap::Parser;
use std::path::PathBuf;

use soroban_drift_core::diff_engine::diff;
use soroban_drift_core::report;
use soroban_drift_core::rust_parser::parse_crate;
use soroban_drift_core::spec_extractor::extract_spec;
use soroban_drift_core::types::*;

#[derive(Parser)]
#[command(
    name = "soroban-drift",
    about = "Detect breaking changes between two versions of a Soroban smart contract"
)]
struct Cli {
    /// Path to the old version of the contract crate (source directory)
    old: PathBuf,

    /// Path to the new version of the contract crate (source directory)
    new: PathBuf,

    /// Path to a compiled WASM file for the old version
    #[arg(long)]
    old_wasm: Option<PathBuf>,

    /// Path to a compiled WASM file for the new version
    #[arg(long)]
    new_wasm: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "markdown", value_parser = ["json", "markdown"])]
    format: String,

    /// Exit code behavior
    #[arg(long, default_value = "breaking", value_parser = ["breaking", "warning", "none"])]
    fail_on: String,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Parse source code
    let old_ast =
        parse_crate(&cli.old).map_err(|e| anyhow::anyhow!("Failed to parse old version: {}", e))?;
    let new_ast =
        parse_crate(&cli.new).map_err(|e| anyhow::anyhow!("Failed to parse new version: {}", e))?;

    // Parse WASM specs (if provided)
    let old_spec = if let Some(ref wasm_path) = cli.old_wasm {
        extract_spec(wasm_path).map_err(|e| anyhow::anyhow!("Failed to parse old WASM: {}", e))?
    } else {
        ContractSpec::default()
    };

    let new_spec = if let Some(ref wasm_path) = cli.new_wasm {
        extract_spec(wasm_path).map_err(|e| anyhow::anyhow!("Failed to parse new WASM: {}", e))?
    } else {
        ContractSpec::default()
    };

    // Compute diff
    let findings = diff(
        &old_ast.storage_keys,
        &new_ast.storage_keys,
        &old_ast.functions,
        &new_ast.functions,
        &old_spec,
        &new_spec,
    );

    let report = DriftReport {
        old_path: cli.old.display().to_string(),
        new_path: cli.new.display().to_string(),
        has_breaking_changes: findings.iter().any(|f| f.severity == Severity::Breaking),
        findings,
    };

    // Output
    match cli.format.as_str() {
        "json" => report::write_json(&report, &mut std::io::stdout())?,
        _ => report::write_markdown(&report, &mut std::io::stdout())?,
    }

    // Exit code
    let code = report::exit_code(&report, &cli.fail_on);
    std::process::exit(code);
}

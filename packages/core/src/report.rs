use crate::types::{DriftFinding, DriftReport, Severity};
use std::io;

/// Write the drift report as JSON to the given writer.
pub fn write_json<W: io::Write>(report: &DriftReport, writer: &mut W) -> serde_json::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, report)?;
    writeln!(writer).ok();
    Ok(())
}

/// Write the drift report as Markdown to the given writer.
pub fn write_markdown<W: io::Write>(report: &DriftReport, writer: &mut W) -> io::Result<()> {
    writeln!(writer, "# Soroban Drift Report")?;
    writeln!(writer)?;
    writeln!(writer, "- **Old version**: `{}`", report.old_path)?;
    writeln!(writer, "- **New version**: `{}`", report.new_path)?;
    writeln!(
        writer,
        "- **Status**: {}",
        if report.has_breaking_changes {
            "BREAKING CHANGES DETECTED"
        } else {
            "No breaking changes"
        }
    )?;
    writeln!(writer)?;

    if report.findings.is_empty() {
        writeln!(writer, "No drift findings.")?;
        return Ok(());
    }

    // Group findings by severity
    let breaking: Vec<&DriftFinding> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Breaking)
        .collect();
    let warnings: Vec<&DriftFinding> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .collect();
    let infos: Vec<&DriftFinding> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .collect();

    if !breaking.is_empty() {
        writeln!(writer, "## Breaking Changes")?;
        writeln!(writer)?;
        for f in &breaking {
            write_finding(writer, f)?;
        }
    }

    if !warnings.is_empty() {
        writeln!(writer, "## Warnings")?;
        writeln!(writer)?;
        for f in &warnings {
            write_finding(writer, f)?;
        }
    }

    if !infos.is_empty() {
        writeln!(writer, "## Info")?;
        writeln!(writer)?;
        for f in &infos {
            write_finding(writer, f)?;
        }
    }

    Ok(())
}

fn write_finding<W: io::Write>(writer: &mut W, f: &DriftFinding) -> io::Result<()> {
    writeln!(writer, "- **{}**", f.category)?;
    writeln!(writer, "  - {}", f.message)?;
    if let Some(old) = &f.old_value {
        writeln!(writer, "  - Old: `{}`", old)?;
    }
    if let Some(new) = &f.new_value {
        writeln!(writer, "  - New: `{}`", new)?;
    }
    writeln!(writer)?;
    Ok(())
}

/// Determine the exit code based on the report and the fail-on level.
/// - "breaking": exit 1 if any breaking changes
/// - "warning": exit 1 if any breaking or warning changes
/// - "none": exit 0 always
pub fn exit_code(report: &DriftReport, fail_on: &str) -> i32 {
    match fail_on {
        "breaking" => {
            if report.has_breaking_changes {
                1
            } else {
                0
            }
        }
        "warning"
            if report.has_breaking_changes
                || report
                    .findings
                    .iter()
                    .any(|f| f.severity == Severity::Warning) =>
        {
            1
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DriftFinding, Severity};

    fn make_report(findings: Vec<DriftFinding>) -> DriftReport {
        DriftReport {
            old_path: "old".to_string(),
            new_path: "new".to_string(),
            has_breaking_changes: findings.iter().any(|f| f.severity == Severity::Breaking),
            findings,
        }
    }

    #[test]
    fn json_output() {
        let report = make_report(vec![DriftFinding {
            severity: Severity::Breaking,
            category: "storage".to_string(),
            message: "key removed".to_string(),
            old_value: None,
            new_value: None,
        }]);
        let mut buf = Vec::new();
        write_json(&report, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("storage"));
        assert!(output.contains("key removed"));
    }

    #[test]
    fn markdown_output() {
        let report = make_report(vec![DriftFinding {
            severity: Severity::Warning,
            category: "auth".to_string(),
            message: "auth weakened".to_string(),
            old_value: Some("require_auth".to_string()),
            new_value: Some("require_auth_for_args".to_string()),
        }]);
        let mut buf = Vec::new();
        write_markdown(&report, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Warnings"));
        assert!(output.contains("auth weakened"));
    }

    #[test]
    fn exit_code_breaking() {
        let r = make_report(vec![DriftFinding {
            severity: Severity::Breaking,
            category: "s".to_string(),
            message: "".to_string(),
            old_value: None,
            new_value: None,
        }]);
        assert_eq!(exit_code(&r, "breaking"), 1);
        assert_eq!(exit_code(&r, "warning"), 1);
        assert_eq!(exit_code(&r, "none"), 0);
    }

    #[test]
    fn exit_code_warning() {
        let r = make_report(vec![DriftFinding {
            severity: Severity::Warning,
            category: "s".to_string(),
            message: "".to_string(),
            old_value: None,
            new_value: None,
        }]);
        assert_eq!(exit_code(&r, "breaking"), 0);
        assert_eq!(exit_code(&r, "warning"), 1);
        assert_eq!(exit_code(&r, "none"), 0);
    }

    #[test]
    fn exit_code_no_findings() {
        let r = make_report(vec![]);
        assert_eq!(exit_code(&r, "breaking"), 0);
        assert_eq!(exit_code(&r, "warning"), 0);
        assert_eq!(exit_code(&r, "none"), 0);
    }
}

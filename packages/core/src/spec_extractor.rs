use crate::types::{ContractSpec, FunctionSpec, ParamInfo};
use std::path::Path;
use std::fs;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpecExtractError {
    #[error("I/O error reading {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("Invalid WASM file {path}: {message}")]
    InvalidWasm { path: String, message: String },
    #[error("WASM parse error: {0}")]
    WasmParse(#[from] wasmparser::BinaryReaderError),
}

/// Extract the contract spec from a compiled WASM binary.
///
/// Reads the `contractspecv0` custom section from the WASM file.
/// This section contains XDR-encoded SCSpecEntry values per SEP-48.
///
/// Note: The contractspecv0 section only contains function/type interface
/// metadata (signatures). It does NOT contain storage key usage info.
/// Storage analysis must come from source-level AST parsing.
///
/// Parsing of the XDR stream within the custom section is partial:
/// we extract function names, input parameter names/types, and output
/// types where the XDR format is recognizable. Complex XDR types may
/// produce incomplete information.
pub fn extract_spec(path: &Path) -> Result<ContractSpec, SpecExtractError> {
    let wasm_bytes = fs::read(path).map_err(|e| SpecExtractError::Io {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut spec = ContractSpec::default();

    let parser = wasmparser::Parser::new(0);
    for payload in parser.parse_all(&wasm_bytes) {
        let payload = payload?;
        if let wasmparser::Payload::CustomSection(section) = &payload {
            if section.name() == "contractspecv0" {
                let data = section.data();
                parse_contractspec_section(data, &mut spec);
                break;
            }
        }
    }

    Ok(spec)
}

/// Parse the raw bytes of a contractspecv0 custom section.
///
/// The section contains a stream of XDR-encoded SCSpecEntry values.
/// We attempt to extract function spec entries by scanning for
/// recognizable patterns. This is a best-effort parser.
fn parse_contractspec_section(data: &[u8], spec: &mut ContractSpec) {
    // XDR format for SCSpecEntry is:
    // - 4 bytes: type discriminant (0 = function, 1 = struct, 2 = union/enum, 3 = error)
    // For function entries (discriminant = 0):
    //   - 4 bytes: doc string length
    //   - N bytes: doc string (UTF-8)
    //   - 4 bytes: name length
    //   - N bytes: name string (UTF-8)
    //   - 4 bytes: input count
    //   - For each input: type info, name (length-prefixed string)
    //   - 4 bytes: output count
    //   - For each output: type info
    //
    // Type info in XDR for SCSpecType is more complex (can be nested).
    // We attempt a simple scan and fall back to reporting unknown types.

    let mut offset = 0;
    while offset + 4 <= data.len() {
        // Read discriminant (u32 LE)
        let disc = u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        );
        offset += 4;

        match disc {
            0 => {
                // Function entry
                if let Some((func, bytes_read)) = parse_function_entry(&data[offset..]) {
                    spec.functions.push(func);
                    offset += bytes_read;
                } else {
                    // Can't parse further, stop
                    break;
                }
            }
            1 | 2 | 3 => {
                // Struct, enum/union, or error type — skip for now
                // We'd need full XDR parsing to skip correctly; for now,
                // break to avoid misaligned reads
                break;
            }
            _ => {
                // Unknown discriminant — stop
                break;
            }
        }
    }
}

/// Try to parse a function entry from the beginning of a byte slice.
/// Returns the FunctionSpec and the number of bytes consumed, or None
/// if parsing fails.
fn parse_function_entry(data: &[u8]) -> Option<(FunctionSpec, usize)> {
    let mut offset = 0;

    // Doc string
    let (doc, read) = read_xdr_string(data, offset)?;
    offset = read;
    let _doc = doc; // Not currently used

    // Function name
    let (name, read) = read_xdr_string(data, offset)?;
    offset = read;

    // Input count (u32)
    if offset + 4 > data.len() {
        return None;
    }
    let input_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    let mut inputs = Vec::new();
    for _ in 0..input_count {
        // Input type: try to read scalar type first
        let (ty_str, read) = read_scalar_type(data, offset)?;
        offset = read;

        // Input name
        let (param_name, read) = read_xdr_string(data, offset)?;
        offset = read;

        inputs.push(ParamInfo {
            name: param_name,
            ty: ty_str,
        });
    }

    // Output count (u32)
    if offset + 4 > data.len() {
        return None;
    }
    let output_count = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
    offset += 4;

    let mut outputs = Vec::new();
    for _ in 0..output_count {
        let (ty_str, read) = read_scalar_type(data, offset)?;
        offset = read;

        outputs.push(ParamInfo {
            name: String::new(),
            ty: ty_str,
        });
    }

    Some((FunctionSpec { name, inputs, outputs }, offset))
}

/// Read an XDR length-prefixed string from the given offset.
/// XDR strings are: 4-byte length (u32 LE) followed by N bytes of UTF-8,
/// padded to 4-byte alignment.
fn read_xdr_string(data: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let len = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
    if offset + 4 + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[offset + 4..offset + 4 + len])
        .ok()?
        .to_string();
    // XDR strings are padded to 4-byte alignment
    let padded_len = 4 + ((len + 3) & !3);
    Some((s, offset + padded_len))
}

/// Try to read a scalar type from the XDR stream.
/// Returns the type string and the number of bytes consumed.
/// This supports basic SCSpecType variants.
fn read_scalar_type(data: &[u8], offset: usize) -> Option<(String, usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let disc = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);

    // SCSpecType discriminants (from soroban-env-common):
    // 0 = Val, 1 = Void, 2 = Bool, 3 = Error, 4 = U32, 5 = I32,
    // 6 = U64, 7 = I64, 8 = Timestamp, 9 = Duration, 10 = U128,
    // 11 = I128, 12 = U256, 13 = I256, 14 = Bytes, 15 = BytesN(N),
    // 16 = Address, 17 = String, 18 = Symbol, 19 = Vec, 20 = Map,
    // 21 = Contract, 22 = Option

    let (ty_str, inner_offset) = match disc {
        0 => ("Val".to_string(), 4),
        1 => ("Void".to_string(), 4),
        2 => ("Bool".to_string(), 4),
        3 => ("Error".to_string(), 4),
        4 => ("u32".to_string(), 4),
        5 => ("i32".to_string(), 4),
        6 => ("u64".to_string(), 4),
        7 => ("i64".to_string(), 4),
        8 => ("Timestamp".to_string(), 4),
        9 => ("Duration".to_string(), 4),
        10 => ("u128".to_string(), 4),
        11 => ("i128".to_string(), 4),
        12 => ("u256".to_string(), 4),
        13 => ("i256".to_string(), 4),
        14 => ("Bytes".to_string(), 4),
        15 => {
            // BytesN(N): read N (u32) after the discriminant
            if offset + 8 > data.len() {
                return None;
            }
            let n = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?);
            (format!("BytesN({})", n), 8)
        }
        16 => ("Address".to_string(), 4),
        17 => ("String".to_string(), 4),
        18 => ("Symbol".to_string(), 4),
        19 | 20 | 21 | 22 => {
            // Vec, Map, Contract, Option — complex types, we skip details
            // For now, return a generic name
            let name = match disc {
                19 => "Vec",
                20 => "Map",
                21 => "Contract",
                22 => "Option",
                _ => unreachable!(),
            };
            (format!("{}<...>", name), 4)
        }
        _ => {
            // Unknown type discriminant
            return None;
        }
    };

    Some((ty_str, offset + inner_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid WASM with a contractspecv0 section
    /// for testing the parser.
    fn build_test_wasm(func_name: &str, inputs: &[(&str, u32)], outputs: &[u32]) -> Vec<u8> {
        let mut section_data = Vec::new();

        // Function entry (discriminant = 0)
        section_data.extend_from_slice(&0u32.to_le_bytes()); // discriminant

        // Doc string (empty)
        section_data.extend_from_slice(&0u32.to_le_bytes());

        // Function name
        section_data.extend_from_slice(&(func_name.len() as u32).to_le_bytes());
        section_data.extend_from_slice(func_name.as_bytes());
        // Pad to 4 bytes
        while section_data.len() % 4 != 0 {
            section_data.push(0);
        }

        // Input count
        section_data.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
        for (name, ty_disc) in inputs {
            // Type discriminant
            section_data.extend_from_slice(&ty_disc.to_le_bytes());
            // Name
            section_data.extend_from_slice(&(name.len() as u32).to_le_bytes());
            section_data.extend_from_slice(name.as_bytes());
            while section_data.len() % 4 != 0 {
                section_data.push(0);
            }
        }

        // Output count
        section_data.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
        for ty_disc in outputs {
            section_data.extend_from_slice(&ty_disc.to_le_bytes());
        }

        // Build a minimal WASM module with a custom section
        let mut wasm = Vec::new();
        // WASM header
        wasm.extend_from_slice(b"\0asm");
        wasm.extend_from_slice(&[1u8, 0, 0, 0]); // version 1

        // Custom section
        let section_name = b"contractspecv0";
        let section_content_len = section_name.len() + section_data.len() + 1; // +1 for name length byte

        // Section ID 0 = custom
        wasm.push(0);
        // Section length (LEB128)
        write_leb128(&mut wasm, section_content_len as u64);
        // Name length (LEB128)
        write_leb128(&mut wasm, section_name.len() as u64);
        wasm.extend_from_slice(section_name);
        wasm.extend_from_slice(&section_data);

        wasm
    }

    fn write_leb128(buf: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn parse_function_with_no_args() {
        let wasm = build_test_wasm("hello", &[], &[]);
        let dir = tempfile::TempDir::new().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, &wasm).unwrap();

        let spec = extract_spec(&wasm_path).unwrap();
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions[0].name, "hello");
        assert!(spec.functions[0].inputs.is_empty());
        assert!(spec.functions[0].outputs.is_empty());
    }

    #[test]
    fn parse_function_with_args() {
        let wasm = build_test_wasm(
            "transfer",
            &[("from", 16u32), ("to", 16u32), ("amount", 11u32)],
            &[1u32], // Void
        );
        let dir = tempfile::TempDir::new().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, &wasm).unwrap();

        let spec = extract_spec(&wasm_path).unwrap();
        assert_eq!(spec.functions.len(), 1);
        assert_eq!(spec.functions[0].name, "transfer");
        assert_eq!(spec.functions[0].inputs.len(), 3);
        assert_eq!(spec.functions[0].inputs[0].name, "from");
        assert_eq!(spec.functions[0].inputs[0].ty, "Address");
        assert_eq!(spec.functions[0].inputs[2].ty, "i128");
        assert_eq!(spec.functions[0].outputs.len(), 1);
        assert_eq!(spec.functions[0].outputs[0].ty, "Void");
    }

    #[test]
    fn empty_wasm_no_spec_section() {
        let wasm = build_test_wasm_without_custom_section();
        let dir = tempfile::TempDir::new().unwrap();
        let wasm_path = dir.path().join("test.wasm");
        std::fs::write(&wasm_path, &wasm).unwrap();

        let spec = extract_spec(&wasm_path).unwrap();
        assert!(spec.functions.is_empty());
    }

    fn build_test_wasm_without_custom_section() -> Vec<u8> {
        let mut wasm = Vec::new();
        wasm.extend_from_slice(b"\0asm");
        wasm.extend_from_slice(&[1u8, 0, 0, 0]);
        wasm
    }

    #[test]
    fn invalid_wasm_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let wasm_path = dir.path().join("not_wasm.bin");
        std::fs::write(&wasm_path, b"not a wasm file").unwrap();

        let result = extract_spec(&wasm_path);
        assert!(result.is_err());
    }
}

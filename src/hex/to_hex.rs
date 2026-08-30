use crate::bytes::Bytes;
use crate::enums::Case;
use crate::operation::Operation;
use crate::types::Result;

/// Encodes bytes into a hexadecimal string with configurable delimiter,
/// per-byte prefix and letter case.
#[derive(Debug, Default)]
pub struct ToHex {
    pub delimiter: String,
    pub prefix: String,
    pub case: Case,
}

impl ToHex {
    /// Creates a hex encoder with the given delimiter, prefix and case.
    pub fn new(delimiter: &str, prefix: &str, case: Case) -> Self {
        Self {
            delimiter: delimiter.to_string(),
            prefix: prefix.to_string(),
            case,
        }
    }
}

impl Operation for ToHex {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let hex_string = input
            .iter()
            .map(|byte| {
                let hex = match self.case {
                    Case::Upper => format!("{byte:02X}"),
                    Case::Lower => format!("{byte:02x}"),
                };
                format!("{}{}", self.prefix, hex)
            })
            .collect::<Vec<String>>()
            .join(&self.delimiter);
        Ok(Bytes::new(hex_string.as_bytes()))
    }
}

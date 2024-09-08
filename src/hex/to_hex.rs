use crate::bytes::Bytes;
use crate::enums::Case;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug, Default)]
pub struct ToHex {
    pub delimiter: String,
    pub prefix: String,
    pub case: Case,
}

impl ToHex {
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
            .to_vec()
            .iter()
            .map(|byte| match self.case {
                Case::Upper => format!("{:02X}", byte),
                Case::Lower => format!("{:02x}", byte),
            })
            .collect::<Vec<String>>()
            .join(&self.delimiter);
        Ok(Bytes::from(hex_string))
    }
}

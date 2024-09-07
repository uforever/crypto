use crate::bytes::Bytes;
use crate::operation::Operation;

#[derive(Debug, Default)]
pub struct ToHex {
    pub delimiter: String,
    pub prefix: String,
    pub upper_case: bool,
}

impl ToHex {
    pub fn new(delimiter: &str, prefix: &str, upper_case: bool) -> Self {
        Self {
            delimiter: delimiter.to_string(),
            prefix: prefix.to_string(),
            upper_case,
        }
    }
}

impl Operation for ToHex {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes> {
        let hex_string = input
            .to_vec()
            .iter()
            .map(|byte| {
                if self.upper_case {
                    format!("{}{:02X}", self.prefix, byte)
                } else {
                    format!("{}{:02x}", self.prefix, byte)
                }
            })
            .collect::<Vec<String>>()
            .join(&self.delimiter);
        Ok(Bytes::from(hex_string))
    }
}

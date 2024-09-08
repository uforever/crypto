use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug, Default)]
pub struct FromHex {
    pub delimiter: String,
    pub prefix: String,
}

impl FromHex {
    pub fn new(delimiter: &str, prefix: &str) -> Self {
        Self {
            delimiter: delimiter.to_string(),
            prefix: prefix.to_string(),
        }
    }
}

impl Operation for FromHex {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let hex_string = String::from_utf8(input.to_vec())?;
        let bytes: Result<Vec<u8>> = hex_string
            .split(&self.delimiter)
            .map(|part| {
                let byte_str = part
                    .strip_prefix(&self.prefix)
                    .ok_or("[FromHex] unexpected prefix")?;
                let byte =
                    u8::from_str_radix(byte_str, 16).map_err(|e| format!("[FromHex] {}", e))?;
                Ok(byte)
            })
            .collect();

        Ok(Bytes::new(bytes?))
    }
}

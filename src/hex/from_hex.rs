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

        let parts: Vec<String> = if self.delimiter.is_empty() {
            let group_length = 2 + self.prefix.len();
            hex_string
                .chars()
                .collect::<Vec<char>>()
                .chunks(group_length)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect()
        } else {
            hex_string
                .split(&self.delimiter)
                .map(|s| s.to_string())
                .collect()
        };

        let bytes: Result<Vec<u8>> = parts
            .into_iter()
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

use crate::bytes::Bytes;
use crate::operation::Operation;

#[derive(Default)]
pub struct FromHex {
    pub delimiter: String,
    pub prefix: String,
}

#[derive(Default)]
pub struct ToHex {
    pub delimiter: String,
    pub prefix: String,
    pub upper_case: bool,
}

impl FromHex {
    pub fn new(delimiter: &str, prefix: &str) -> Self {
        Self {
            delimiter: delimiter.to_string(),
            prefix: prefix.to_string(),
        }
    }
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

impl Operation for FromHex {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
        let hex_string = String::from_utf8(input.to_vec())?;
        let bytes: anyhow::Result<Vec<u8>> = hex_string
            .split(&self.delimiter)
            .map(|part| {
                let byte_str = part
                    .strip_prefix(&self.prefix)
                    .ok_or_else(|| anyhow::anyhow!("[FromHex] unexpected prefix"))?;
                let byte = u8::from_str_radix(byte_str, 16)
                    .map_err(|e| anyhow::anyhow!("[FromHex] {}", e))?;
                Ok(byte)
            })
            .collect();

        Ok(Bytes::new(bytes?))
    }
}

impl Operation for ToHex {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
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

use crate::bytes::Bytes;
use crate::operation::Operation;

#[derive(Default)]
pub enum Case {
    #[default]
    Lower,
    Upper,
}

#[derive(Default)]
pub struct FromHex {
    delimiter: String,
    prefix: String,
}

#[derive(Default)]
pub struct ToHex {
    case: Case,
    delimiter: String,
    prefix: String,
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
    pub fn new(case: Case, delimiter: &str, prefix: &str) -> Self {
        Self {
            case,
            delimiter: delimiter.to_string(),
            prefix: prefix.to_string(),
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
            .map(|byte| match self.case {
                Case::Lower => format!("{}{:02x}", self.prefix, byte),
                Case::Upper => format!("{}{:02X}", self.prefix, byte),
            })
            .collect::<Vec<String>>()
            .join(&self.delimiter);
        Ok(Bytes::from(hex_string))
    }
}

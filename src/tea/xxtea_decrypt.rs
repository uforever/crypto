use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug)]
pub struct XxteaDecrypt {
    pub key: Bytes,
    pub include_length: bool,
}

impl XxteaDecrypt {
    pub fn new(key: Bytes, include_length: bool) -> Self {
        Self {
            key,
            include_length,
        }
    }
}

impl Operation for XxteaDecrypt {
    fn run(&self, _input: &[u8]) -> Result<Bytes> {
        Ok(Bytes::default())
    }
}

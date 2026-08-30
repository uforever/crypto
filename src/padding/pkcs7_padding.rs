use crate::enums::BlockSize;
use crate::padding::Padding;
use crate::types::Result;

/// PKCS#7 padding: appends N bytes each of value N (1..=block_size).
#[derive(Debug)]
pub struct Pkcs7Padding {
    pub block_size: BlockSize,
}

impl Pkcs7Padding {
    /// Creates PKCS#7 padding for the given block size.
    pub fn new(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

impl Padding for Pkcs7Padding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let mut padded_data = data.to_vec();
        let block_size: usize = self.block_size.into();
        let pad_len = block_size - (data.len() % block_size);
        padded_data.extend(vec![pad_len as u8; pad_len]);
        padded_data
    }

    fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_size: usize = self.block_size.into();
        if data.is_empty() || !data.len().is_multiple_of(block_size) {
            return Err("PKCS7 unpadded data length must be a non-zero multiple of the block size".into());
        }
        let pad_len = *data.last().expect("data is not empty") as usize;
        if !(1..=block_size).contains(&pad_len) {
            return Err("invalid PKCS7 padding length".into());
        }
        if data[data.len() - pad_len..].iter().any(|&byte| byte != pad_len as u8) {
            return Err("invalid PKCS7 padding bytes".into());
        }
        Ok(data[..data.len() - pad_len].to_vec())
    }

    fn build(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

use crate::enums::BlockSize;
use crate::padding::Padding;
use crate::types::Result;

/// No padding: passes the data through unchanged.
///
/// The caller must ensure the input length is a multiple of the block size.
#[derive(Debug)]
pub struct NoPadding {
    pub block_size: BlockSize,
}

impl NoPadding {
    /// Creates a no-padding scheme for the given block size.
    pub fn new(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

impl Padding for NoPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn build(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

use crate::enums::BlockSize;
use crate::padding::Padding;

#[derive(Debug)]
pub struct NoPadding {
    pub block_size: BlockSize,
}

impl NoPadding {
    pub fn new(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

impl Padding for NoPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn unpad(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn build(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

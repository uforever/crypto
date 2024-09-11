use crate::enums::BlockSize;
use crate::padding::Padding;

#[derive(Debug)]
pub struct Pkcs7Padding {
    pub block_size: BlockSize,
}

impl Pkcs7Padding {
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

    fn unpad(&self, data: &[u8]) -> Vec<u8> {
        todo!()
    }

    fn build(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

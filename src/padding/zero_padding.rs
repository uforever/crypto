use crate::enums::BlockSize;
use crate::padding::Padding;

#[derive(Debug)]
pub struct ZeroPadding {
    pub block_size: BlockSize,
}

impl ZeroPadding {
    pub fn new(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

impl Padding for ZeroPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let mut padded_data = data.to_vec();
        let block_size: usize = self.block_size.into();
        let pad_len = block_size - (data.len() % block_size);
        padded_data.extend(vec![0; pad_len]);
        padded_data
    }

    // 严格来说是不可逆的
    fn unpad(&self, data: &[u8]) -> Vec<u8> {
        let mut end = data.len();
        while end > 0 && data[end - 1] == 0 {
            end -= 1;
        }
        data[..end].to_vec()
    }

    fn build(block_size: BlockSize) -> Self {
        Self { block_size }
    }
}

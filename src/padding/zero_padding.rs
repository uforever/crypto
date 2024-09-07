use super::Padding;

#[derive(Debug)]
pub struct ZeroPadding {
    pub block_size: usize,
}

impl ZeroPadding {
    pub fn new(block_size: usize) -> Self {
        Self { block_size }
    }
}

impl Padding for ZeroPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let mut padded_data = data.to_vec();
        let pad_len = self.block_size - (data.len() % self.block_size);
        padded_data.extend(vec![0; pad_len]);
        padded_data
    }
}

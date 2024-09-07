use crate::padding::Padding;

#[derive(Debug)]
pub struct PKCSPadding {
    pub block_size: usize,
}

impl PKCSPadding {
    pub fn new(block_size: usize) -> Self {
        Self { block_size }
    }
}

impl Padding for PKCSPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let mut padded_data = data.to_vec();
        let pad_len = self.block_size - (data.len() % self.block_size);
        padded_data.extend(vec![pad_len as u8; pad_len]);
        padded_data
    }
}

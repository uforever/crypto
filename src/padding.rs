use crate::operation::BlockSize;

pub trait Padding {
    fn pad(&self, data: &[u8]) -> Vec<u8>;
}

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

#[derive(Debug)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug)]
pub struct BitPadding {
    pub block_size: BlockSize,
    pub endian: Endian,
}

impl BitPadding {
    pub fn new(block_size: BlockSize, endian: Endian) -> Self {
        Self { block_size, endian }
    }
}

impl Padding for BitPadding {
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let mut padded_data = data.to_vec();
        let block_size: usize = self.block_size.into();
        let length = data.len();
        padded_data.push(0x80);
        while padded_data.len() % block_size != block_size * 7 / 8 {
            padded_data.push(0);
        }
        let length_bytes = match self.block_size {
            BlockSize::Bytes8 => {
                let original_len: u8 = length as u8 * 8;
                vec![original_len]
            }
            BlockSize::Bytes16 => {
                let original_len: u16 = length as u16 * 8;
                match self.endian {
                    Endian::Little => original_len.to_le_bytes(),
                    Endian::Big => original_len.to_be_bytes(),
                }
                .to_vec()
            }
            BlockSize::Bytes32 => {
                let original_len: u32 = length as u32 * 8;
                match self.endian {
                    Endian::Little => original_len.to_le_bytes(),
                    Endian::Big => original_len.to_be_bytes(),
                }
                .to_vec()
            }
            BlockSize::Bytes64 => {
                let original_len: u64 = length as u64 * 8;
                match self.endian {
                    Endian::Little => original_len.to_le_bytes(),
                    Endian::Big => original_len.to_be_bytes(),
                }
                .to_vec()
            }
            BlockSize::Bytes128 => {
                let original_len: u128 = length as u128 * 8;
                match self.endian {
                    Endian::Little => original_len.to_le_bytes(),
                    Endian::Big => original_len.to_be_bytes(),
                }
                .to_vec()
            }
        };
        padded_data.extend(length_bytes);
        padded_data
    }
}

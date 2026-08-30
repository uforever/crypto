use crate::enums::{BlockSize, Endian};
use crate::padding::Padding;
use crate::types::Result;

/// ISO/IEC 7816-4 style bit padding: appends `0x80` then zeros, followed by
/// the original bit length in the chosen byte order.
#[derive(Debug)]
pub struct BitPadding {
    pub block_size: BlockSize,
    pub endian: Endian,
}

impl BitPadding {
    /// Creates bit padding for the given block size and length byte order.
    pub fn new(block_size: BlockSize, endian: Endian) -> Self {
        Self { block_size, endian }
    }
}

// although this is bit padding, the implementation pads at byte granularity,
// which satisfies most use cases
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

    fn unpad(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut unpadded_data = data.to_vec();
        let length = data.len();
        let original_length: usize = match self.block_size {
            BlockSize::Bytes8 => {
                let original_bits_len = unpadded_data[length - 1];
                (original_bits_len / 8) as usize
            }

            BlockSize::Bytes16 => {
                let original_bits_len = match self.endian {
                    Endian::Little => {
                        u16::from_le_bytes([unpadded_data[length - 2], unpadded_data[length - 1]])
                    }
                    Endian::Big => {
                        u16::from_be_bytes([unpadded_data[length - 2], unpadded_data[length - 1]])
                    }
                };
                (original_bits_len / 8) as usize
            }

            BlockSize::Bytes32 => {
                let original_length_bytes: [u8; 4] = [
                    unpadded_data[length - 4],
                    unpadded_data[length - 3],
                    unpadded_data[length - 2],
                    unpadded_data[length - 1],
                ];
                let original_bits_len = match self.endian {
                    Endian::Little => u32::from_le_bytes(original_length_bytes),
                    Endian::Big => u32::from_be_bytes(original_length_bytes),
                };
                (original_bits_len / 8) as usize
            }

            BlockSize::Bytes64 => {
                let original_length_bytes: [u8; 8] = [
                    unpadded_data[length - 8],
                    unpadded_data[length - 7],
                    unpadded_data[length - 6],
                    unpadded_data[length - 5],
                    unpadded_data[length - 4],
                    unpadded_data[length - 3],
                    unpadded_data[length - 2],
                    unpadded_data[length - 1],
                ];
                let original_bits_len = match self.endian {
                    Endian::Little => u64::from_le_bytes(original_length_bytes),
                    Endian::Big => u64::from_be_bytes(original_length_bytes),
                };
                (original_bits_len / 8) as usize
            }

            BlockSize::Bytes128 => {
                let original_length_bytes: [u8; 16] = [
                    unpadded_data[length - 16],
                    unpadded_data[length - 15],
                    unpadded_data[length - 14],
                    unpadded_data[length - 13],
                    unpadded_data[length - 12],
                    unpadded_data[length - 11],
                    unpadded_data[length - 10],
                    unpadded_data[length - 9],
                    unpadded_data[length - 8],
                    unpadded_data[length - 7],
                    unpadded_data[length - 6],
                    unpadded_data[length - 5],
                    unpadded_data[length - 4],
                    unpadded_data[length - 3],
                    unpadded_data[length - 2],
                    unpadded_data[length - 1],
                ];
                let original_bits_len = match self.endian {
                    Endian::Little => u128::from_le_bytes(original_length_bytes),
                    Endian::Big => u128::from_be_bytes(original_length_bytes),
                };
                let original_length = original_bits_len / 8;
                if original_length > usize::MAX as u128 {
                    panic!("length is out of range");
                }
                original_length as usize
            }
        };

        unpadded_data.truncate(original_length);
        Ok(unpadded_data)
    }

    fn build(block_size: BlockSize) -> Self {
        Self::new(block_size, Endian::Big)
    }
}

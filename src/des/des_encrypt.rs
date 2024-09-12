use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule};
use crate::enums::BlockSize;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

#[derive(Debug)]
pub struct DesEncrypt<T: Padding> {
    pub key: Bytes,
    pub padding: T,
}

impl<T: Padding> DesEncrypt<T> {
    pub fn new(key: Bytes) -> Self {
        Self {
            key,
            padding: T::build(BLOCK_SIZE),
        }
    }
}

impl<T: Padding> Operation for DesEncrypt<T> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let sub_keys = key_schedule(&self.key);

        // 分块
        // 输入
        // data: Vec<u8>
        // block_size: usize
        // block_encrypt: fn
        // 输出 Bytes
        let block_encrypt = block_crypt(&sub_keys);

        // 填充
        let padded_data = self.padding.pad(input);

        let mut output: Vec<u8> = vec![];
        for chunk in padded_data.chunks(8) {
            let block: Bits = chunk.into();

            let cipher_block = block_encrypt(block);

            output.extend_from_slice(&Bytes::from(cipher_block));
        }

        Ok(Bytes::new(output))
    }
}

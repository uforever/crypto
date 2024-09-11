use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::des::{block_crypt, generate_sub_keys};
use crate::enums::BlockSize;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

#[derive(Debug)]
pub struct DesDecrypt<T: Padding> {
    pub key: Bytes,
    pub padding: T,
}

impl<T: Padding> DesDecrypt<T> {
    pub fn new(key: Bytes) -> Self {
        Self {
            key,
            padding: T::build(BLOCK_SIZE),
        }
    }
}

impl<T: Padding> Operation for DesDecrypt<T> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let mut sub_keys = generate_sub_keys(&self.key);
        sub_keys.reverse();
        let block_decrypt = block_crypt(&sub_keys);

        let mut output: Vec<u8> = vec![];
        // 分块
        for chunk in input.chunks(8) {
            let block: Bits = chunk.into();

            let cipher_block = block_decrypt(block);

            output.extend_from_slice(&Bytes::from(cipher_block));
        }
        // 去除填充
        let unpadded_data = self.padding.unpad(&output);

        Ok(Bytes::new(unpadded_data))
    }
}

use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

#[derive(Debug)]
pub struct DesEncrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> DesEncrypt<M, P> {
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for DesEncrypt<M, P> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let sub_keys = key_schedule(&self.key);

        // 加密函数
        let block_encrypt = block_crypt(&sub_keys);

        // 填充
        let padded_data = self.padding.pad(input);

        Ok(self
            .mode
            .bits_encrypt(&padded_data, BLOCK_SIZE, block_encrypt))
    }
}

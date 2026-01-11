use crate::bytes::Bytes;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::sm4::{key_schedule, BLOCK_SIZE};
use crate::types::Result;

use super::block_crypt;

#[derive(Debug)]
pub struct Sm4Decrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> Sm4Decrypt<M, P> {
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for Sm4Decrypt<M, P> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // SM4的解密过程用到的轮密钥是加密过程的轮密钥的逆序
        let mut round_keys = key_schedule(&self.key);
        let mode_name = std::any::type_name_of_val(&self.mode);
        if mode_name.contains("Ecb") || mode_name.contains("Cbc") {
            round_keys.reverse();
        }
        let decrypt_func = block_crypt(&round_keys);
        let result = self.mode.bytes_decrypt(input, BLOCK_SIZE, decrypt_func);

        Ok(Bytes::new(self.padding.unpad(&result)))
    }
}

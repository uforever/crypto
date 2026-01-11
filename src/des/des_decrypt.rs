use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

#[derive(Debug)]
pub struct DesDecrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> DesDecrypt<M, P> {
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for DesDecrypt<M, P> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let mut sub_keys = key_schedule(&self.key);

        let mode_name = std::any::type_name_of_val(&self.mode);
        if mode_name.contains("Ecb") || mode_name.contains("Cbc") {
            // 电子密码本和密码分组链接模式需要反转子密钥顺序
            sub_keys.reverse();
        }

        let block_decrypt = block_crypt(&sub_keys);
        let result = self.mode.bits_decrypt(input, BLOCK_SIZE, block_decrypt);
        Ok(Bytes::new(self.padding.unpad(&result)))
    }
}

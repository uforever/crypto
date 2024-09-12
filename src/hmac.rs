use crate::bytes::Bytes;
use crate::operation::{Hashing, Operation};
use crate::types::Result;

#[derive(Debug)]
pub struct Hmac<H: Hashing> {
    key: Bytes,
    hash_function: H,
}

impl<H: Hashing> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: Bytes::new(key),
            hash_function: H::default(),
        }
    }
}

impl<H: Hashing> Operation for Hmac<H> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let key_len = self.key.len();
        let block_size: usize = self.hash_function.block_size().into();

        // 对key进行padding (如果key长度大于block_size，则先hash)
        let mut sized_key = if key_len > block_size {
            self.hash_function.run(&self.key)?.to_vec()
        } else {
            self.key.to_vec()
        };
        sized_key.resize(block_size, 0);

        let mut opad: Vec<u8> = sized_key.iter().map(|b| b ^ 0x5c).collect();
        let mut ipad: Vec<u8> = sized_key.iter().map(|b| b ^ 0x36).collect();

        // 将message拼接到ipad后做一次hash
        ipad.extend_from_slice(input);
        let ipad_hash = self.hash_function.run(&ipad)?;

        // 将计算结果拼接到opad后再做一次hash
        opad.extend_from_slice(&ipad_hash);
        self.hash_function.run(&opad)
    }
}

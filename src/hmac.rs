use crate::bytes::Bytes;
use crate::operation::{Hashing, Operation};
use crate::types::Result;

#[derive(Debug)]
pub struct HMAC<T: Hashing> {
    key: Bytes,
    hash_function: T,
}

impl<T: Hashing> HMAC<T> {
    pub fn new(key: Bytes) -> Self {
        Self {
            key,
            hash_function: T::default(),
        }
    }
}

impl<T: Hashing> Operation for HMAC<T> {
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

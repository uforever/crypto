use crate::bytes::Bytes;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::sm4::{key_schedule, BLOCK_SIZE};
use crate::types::Result;

use super::block_crypt;

/// SM4 decryption, which uses the round keys in reverse order.
#[derive(Debug)]
pub struct Sm4Decrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> Sm4Decrypt<M, P> {
    /// Creates an SM4 decryptor with the given key and mode.
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
        // SM4 decryption uses the round keys of encryption in reverse order
        let mut round_keys = key_schedule(&self.key);
        if self.mode.uses_decrypt_direction() {
            round_keys.reverse();
        }
        let decrypt_func = block_crypt(&round_keys);
        let result = self.mode.bytes_decrypt(input, BLOCK_SIZE, decrypt_func)?;

        Ok(Bytes::new(self.padding.unpad(&result)?))
    }
}

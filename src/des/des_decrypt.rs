use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

/// DES decryption: reverses the sub-key order of the shared Feistel function.
#[derive(Debug)]
pub struct DesDecrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> DesDecrypt<M, P> {
    /// Creates a DES decryptor with the given key and mode.
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

        if self.mode.uses_decrypt_direction() {
            // ECB and CBC modes require reversing the sub-key order
            sub_keys.reverse();
        }

        let block_decrypt = block_crypt(&sub_keys);
        let result = self.mode.bits_decrypt(input, BLOCK_SIZE, block_decrypt)?;
        Ok(Bytes::new(self.padding.unpad(&result)?))
    }
}

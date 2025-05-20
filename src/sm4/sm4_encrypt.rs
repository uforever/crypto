use crate::bytes::Bytes;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::sm4::{key_schedule, BLOCK_SIZE};
use crate::types::Result;

use super::block_crypt;

#[derive(Debug)]
pub struct Sm4Encrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> Sm4Encrypt<M, P> {
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for Sm4Encrypt<M, P> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let round_keys = key_schedule(&self.key);
        let encrypt_func = block_crypt(&round_keys);
        let padded_data = self.padding.pad(input);

        Ok(self
            .mode
            .bytes_encrypt(&padded_data, BLOCK_SIZE, encrypt_func))
    }
}

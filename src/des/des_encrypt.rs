use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

/// DES encryption: expands the key and runs the input through a block cipher mode.
#[derive(Debug)]
pub struct DesEncrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> DesEncrypt<M, P> {
    /// Creates a DES encryptor with the given key and mode.
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

        // the encryption function
        let block_encrypt = block_crypt(&sub_keys);

        // padding
        let padded_data = self.padding.pad(input);

        self.mode
            .bits_encrypt(&padded_data, BLOCK_SIZE, block_encrypt)
    }
}

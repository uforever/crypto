use crate::bytes::Bytes;
use crate::operation::{Hashing, Operation};
use crate::types::Result;

/// Hash-based message authentication code (RFC 2104) over any [`Hashing`].
#[derive(Debug)]
pub struct Hmac<H: Hashing> {
    key: Bytes,
    hash_function: H,
}

impl<H: Hashing> Hmac<H> {
    /// Creates an HMAC instance with the given key and the default hash function.
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

        // pad the key (hash it first if it is longer than the block size)
        let mut sized_key = if key_len > block_size {
            self.hash_function.run(&self.key)?.to_vec()
        } else {
            self.key.to_vec()
        };
        sized_key.resize(block_size, 0);

        let mut opad: Vec<u8> = sized_key.iter().map(|b| b ^ 0x5c).collect();
        let mut ipad: Vec<u8> = sized_key.iter().map(|b| b ^ 0x36).collect();

        // hash the message appended after ipad
        ipad.extend_from_slice(input);
        let ipad_hash = self.hash_function.run(&ipad)?;

        // hash the inner digest appended after opad
        opad.extend_from_slice(&ipad_hash);
        self.hash_function.run(&opad)
    }
}

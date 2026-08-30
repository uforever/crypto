use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::enums::Bit;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

/// Triple-DES (EDE) encryption: applies DES three times with two or three keys.
#[derive(Debug)]
pub struct TripleDesEncrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> TripleDesEncrypt<M, P> {
    /// Creates a 3DES encryptor; a 16-byte key is treated as 2-key 3DES.
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for TripleDesEncrypt<M, P> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let mut key = self.key.to_vec();
        // special handling for 2-key 3DES (also known as 2TDEA)
        let (key1, key2, key3) = if key.len() == 16 {
            (
                Bytes::new(&key[0..8]),
                Bytes::new(&key[8..16]),
                Bytes::new(&key[0..8]),
            )
        } else {
            // handle other cases for compatibility
            key.resize(24, 0);
            (
                Bytes::new(&key[0..8]),
                Bytes::new(&key[8..16]),
                Bytes::new(&key[16..24]),
            )
        };

        // encrypt -> decrypt -> encrypt
        let sub_keys1 = key_schedule(&key1);
        let mut sub_keys2 = key_schedule(&key2);
        sub_keys2.reverse();
        let sub_keys3 = key_schedule(&key3);

        let crypt1 = block_crypt(&sub_keys1);
        let crypt2 = block_crypt(&sub_keys2);
        let crypt3 = block_crypt(&sub_keys3);
        // chain the three operations
        let crypt = |block: &[Bit]| crypt3(&crypt2(&crypt1(block)));

        let padded_data = self.padding.pad(input);

        self.mode.bits_encrypt(&padded_data, BLOCK_SIZE, crypt)
    }
}

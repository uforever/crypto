use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::enums::Bit;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

/// Triple-DES (DED/EDE) decryption, reversing the encryption key order.
#[derive(Debug)]
pub struct TripleDesDecrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> TripleDesDecrypt<M, P> {
    /// Creates a 3DES decryptor; a 16-byte key is treated as 2-key 3DES.
    pub fn new(key: &[u8], mode: M) -> Self {
        Self {
            key: Bytes::new(key),
            mode,
            padding: P::build(BLOCK_SIZE),
        }
    }
}

impl<M: Mode, P: Padding> Operation for TripleDesDecrypt<M, P> {
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

        let mut sub_keys1 = key_schedule(&key1);
        let mut sub_keys2 = key_schedule(&key2);
        let mut sub_keys3 = key_schedule(&key3);

        if self.mode.uses_decrypt_direction() {
            // decrypt -> encrypt -> decrypt
            sub_keys3.reverse();
            sub_keys1.reverse();
            let crypt3 = block_crypt(&sub_keys3);
            let crypt2 = block_crypt(&sub_keys2);
            let crypt1 = block_crypt(&sub_keys1);
            // chain the three operations
            let crypt = |block: &[Bit]| crypt1(&crypt2(&crypt3(block)));
            let result = self.mode.bits_decrypt(input, BLOCK_SIZE, crypt)?;
            Ok(Bytes::new(self.padding.unpad(&result)?))
        } else {
            // encrypt -> decrypt -> encrypt
            sub_keys2.reverse();
            let crypt1 = block_crypt(&sub_keys1);
            let crypt2 = block_crypt(&sub_keys2);
            let crypt3 = block_crypt(&sub_keys3);
            // chain the three operations
            let crypt = |block: &[Bit]| crypt3(&crypt2(&crypt1(block)));
            let result = self.mode.bits_decrypt(input, BLOCK_SIZE, crypt)?;
            Ok(Bytes::new(self.padding.unpad(&result)?))
        }
    }
}

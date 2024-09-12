use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule};
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

#[derive(Debug)]
pub struct TripleDesDecrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> TripleDesDecrypt<M, P> {
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
        // 对 2-key 3DES (也被称为2TDEA) 进行特殊处理
        let (key1, key2, key3) = if key.len() == 16 {
            (
                Bytes::new(&key[0..8]),
                Bytes::new(&key[8..16]),
                Bytes::new(&key[0..8]),
            )
        } else {
            // 其它情况兼容
            key.resize(24, 0);
            (
                Bytes::new(&key[0..8]),
                Bytes::new(&key[8..16]),
                Bytes::new(&key[16..24]),
            )
        };

        // 解密 -> 加密 -> 解密
        let mut sub_keys3 = key_schedule(&key3);
        sub_keys3.reverse();
        let sub_keys2 = key_schedule(&key2);
        let mut sub_keys1 = key_schedule(&key1);
        sub_keys1.reverse();

        let crypt3 = block_crypt(&sub_keys3);
        let crypt2 = block_crypt(&sub_keys2);
        let crypt1 = block_crypt(&sub_keys1);
        // 串联三次操作
        let crypt = |block: &[Bit]| crypt1(&crypt2(&crypt3(block)));

        let result = self.mode.decrypt(input, BLOCK_SIZE, crypt);

        Ok(Bytes::new(self.padding.unpad(&result)))
    }
}

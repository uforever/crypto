use crate::bytes::Bytes;
use crate::des::{block_crypt, key_schedule, BLOCK_SIZE};
use crate::enums::Bit;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

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

        let mut sub_keys1 = key_schedule(&key1);
        let mut sub_keys2 = key_schedule(&key2);
        let mut sub_keys3 = key_schedule(&key3);

        let mode_name = std::any::type_name_of_val(&self.mode);
        if mode_name.contains("Ecb") || mode_name.contains("Cbc") {
            // 解密 -> 加密 -> 解密
            sub_keys3.reverse();
            sub_keys1.reverse();
            let crypt3 = block_crypt(&sub_keys3);
            let crypt2 = block_crypt(&sub_keys2);
            let crypt1 = block_crypt(&sub_keys1);
            // 串联三次操作
            let crypt = |block: &[Bit]| crypt1(&crypt2(&crypt3(block)));
            let result = self.mode.bits_decrypt(input, BLOCK_SIZE, crypt);
            Ok(Bytes::new(self.padding.unpad(&result)))
        } else {
            // 加密 -> 解密 -> 加密
            sub_keys2.reverse();
            let crypt1 = block_crypt(&sub_keys1);
            let crypt2 = block_crypt(&sub_keys2);
            let crypt3 = block_crypt(&sub_keys3);
            // 串联三次操作
            let crypt = |block: &[Bit]| crypt3(&crypt2(&crypt1(block)));
            let result = self.mode.bits_decrypt(input, BLOCK_SIZE, crypt);
            Ok(Bytes::new(self.padding.unpad(&result)))
        }
    }
}

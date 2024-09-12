use crate::bytes::Bytes;
use crate::des::{DesDecrypt, DesEncrypt};
use crate::enums::BlockSize;
use crate::mode::Mode;
use crate::operation::Operation;
use crate::padding::{NoPadding, Padding};
use crate::types::Result;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

#[derive(Debug)]
pub struct TripleDesEncrypt<M: Mode, P: Padding> {
    pub key: Bytes,
    pub mode: M,
    pub padding: P,
}

impl<M: Mode, P: Padding> TripleDesEncrypt<M, P> {
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

        let op1 = DesEncrypt::<M, P>::new(&key1, self.mode.clone());
        let op2 = DesDecrypt::<M, NoPadding>::new(&key2, self.mode.clone());
        let op3 = DesEncrypt::<M, NoPadding>::new(&key3, self.mode.clone());

        op3.run(&op2.run(&op1.run(input)?)?)
    }
}

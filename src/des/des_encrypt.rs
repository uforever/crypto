use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::des::{substitution, E, FP, IP, P, PC1, PC2_ARRAY};
use crate::enums::Bit;
use crate::enums::BlockSize;
use crate::operation::Operation;
use crate::padding::Padding;
use crate::types::Result;

const BLOCK_SIZE: BlockSize = BlockSize::Bytes8;

#[derive(Debug)]
pub struct DesEncrypt<T: Padding> {
    pub key: Bytes,
    pub padding: T,
}

impl<T: Padding> DesEncrypt<T> {
    pub fn new(key: Bytes) -> Self {
        Self {
            key,
            padding: T::build(BLOCK_SIZE),
        }
    }
}

impl<T: Padding> Operation for DesEncrypt<T> {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // 取有效位 56 bit
        // PC1: 64bit -> 56bit
        let original_key: Bits = self.key.as_ref().into();
        let key: Bits = original_key.permutation(&PC1);

        // 通过分成左右两部
        // 分别循环左移 再通过PC2生成16个48bit的key
        // PC2: 56bit -> 48bit * 16
        let mut sub_keys = vec![];
        (0..16).for_each(|i| {
            sub_keys.push(key.permutation(&PC2_ARRAY[i]));
        });

        // 填充
        let padded_data = self.padding.pad(input);

        // 分块
        for chunk in padded_data.chunks(8) {
            let block: Bits = chunk.into();
            let permuted_block = block.permutation(&IP);
            let mut left = Bits::new(&permuted_block[0..32]);
            let mut right = Bits::new(&permuted_block[32..]);

            for i in 0..16 {
                // 32bit -> 48bit
                let expanded_right = right.permutation(&E);
                // xor subkey
                let xor_result = expanded_right.xor(&sub_keys[i]);

                // 48bit -> 32bit
                let sub_result = substitution(&xor_result);

                // 32bit -> 32bit permutation
                let permuted_result = sub_result.permutation(&P);

                let result = permuted_result.xor(&left);
                left = right;
                right = result;
            }

            let final_result: Vec<Bit> = [right.to_vec(), left.to_vec()].concat();
            let final_bits: Bits = Bits::new(final_result);
            let cipher_block = final_bits.permutation(&FP);
            println!("{:?}", cipher_block);
        }

        Ok(Bytes::default())
    }
}

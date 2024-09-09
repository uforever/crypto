use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

const PC1: [usize; 56] = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59,
    51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3,
];

const PC2: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const BIT_SHIFTS: [usize; 16] = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

#[derive(Debug)]
pub struct DesEncrypt {
    pub key: Bytes,
}

impl DesEncrypt {
    pub fn new(key: Bytes) -> Self {
        Self { key }
    }
}

impl Operation for DesEncrypt {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        // PC1: 64bit -> 56bit
        let original_key: Bits = self.key.as_ref().into();
        let key: Bits = original_key.permutation(&PC1);
        println!("{:?}", key.len());
        println!("{:?}", key.as_ref());

        // PC2: 56bit -> 48bit * 16

        Ok(Bytes::default())
    }
}

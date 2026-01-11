use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;

// 密码反馈模式
// 加密过程不支持并行 解密过程支持并行
// 支持无填充
#[derive(Clone, Debug)]
pub struct Cfb {
    pub iv: Bytes,
}

impl Cfb {
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: Bytes::new(iv) }
    }
}

impl Mode for Cfb {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            let plain: Bits = block.xor(&block_encrypt(&vector));
            // 上一组密文作为下一个向量
            vector = block;
            output.extend_from_slice(&plain.to_bytes());
        }

        Bytes::new(output)
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        let block_size: usize = block_size.into();

        // inintialization vector
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv).to_bits();

        let length = input.len();
        let mut output = Vec::with_capacity(length);

        for chunk in input.chunks(block_size) {
            let block: Bits = chunk.into();
            // 密文作为下一个向量
            vector = block.xor(&block_encrypt(&vector));
            output.extend_from_slice(&vector.to_bytes());
        }

        Bytes::new(output)
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            output.extend_from_slice(&block.xor(&block_encrypt(&vector)));
            // 上一组密文作为下一个向量
            vector = block;
        }
        Bytes::new(output)
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            // 密文作为下一个向量
            vector = block.xor(&block_encrypt(&vector));
            output.extend_from_slice(&vector);
        }
        Bytes::new(output)
    }
}

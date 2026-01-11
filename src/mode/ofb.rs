use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;

// 输出反馈模式
// 加解密过程均不支持并行
// 支持无填充
#[derive(Clone, Debug)]
pub struct Ofb {
    pub iv: Bytes,
}

impl Ofb {
    pub fn new(iv: &[u8]) -> Self {
        Self { iv: Bytes::new(iv) }
    }

    fn bits_crypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_crypt: impl Fn(&[Bit]) -> Bits,
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
            // 向量不断更新
            vector = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&vector).to_bytes());
        }

        Bytes::new(output)
    }

    fn bytes_crypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_crypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        iv.resize(block_size, 0);
        let mut vector = Bytes::new(iv);

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            let block = Bytes::new(chunk);
            // 向量不断更新
            vector = block_crypt(&vector);
            output.extend_from_slice(&block.xor(&vector));
        }
        Bytes::new(output)
    }
}

impl Mode for Ofb {
    fn bits_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        self.bits_crypt(input, block_size, block_encrypt)
    }

    fn bits_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        self.bits_crypt(input, block_size, block_encrypt)
    }

    // 加解密过程相同
    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        self.bytes_crypt(input, block_size, block_encrypt)
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        self.bytes_crypt(input, block_size, block_encrypt)
    }
}

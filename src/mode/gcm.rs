use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;

// 计数器模式
// 加解密过程均支持并行
// 支持无填充
#[derive(Clone, Debug)]
pub struct Gcm {
    pub iv: Bytes,
    pub additional_data: Option<Bytes>,
}

fn ghash_u128(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0u128;
    for message in messages {
        let yi = gmul_u128(y ^ message, key);
        y = yi;
    }
    y
}

/// u128版本的Galois域乘法
fn gmul_u128(a: u128, b: u128) -> u128 {
    let mut v = b;
    let mut z = 0u128;

    for i in (0..128).rev() {
        let xi = (a >> i) & 1;
        if xi != 0 {
            z ^= v;
        }

        let lsb_v = v & 1;
        v >>= 1;
        if lsb_v != 0 {
            v ^= 0xe1u128 << 120;
        }
    }
    z
}

// 计数器自增 采用进位方式 不考虑溢出部分
// 有别于CyberChef中的实现(只对最后4个字节进行自增)
impl Gcm {
    pub fn new(iv: &[u8], additional_data: Option<&[u8]>) -> Self {
        Self {
            iv: Bytes::new(iv),
            additional_data: additional_data.map(Bytes::new),
        }
    }

    fn bits_crypt(
        &self,
        _input: &[u8],
        _block_size: BlockSize,
        _block_crypt: impl Fn(&[Bit]) -> Bits,
    ) -> Bytes {
        todo!() // 用不到 暂不实现
    }
}

impl Mode for Gcm {
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

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        match block_size {
            BlockSize::Bytes16 => {}
            _ => panic!("GCM mode only supports 128-bit block size"),
        }
        if input.len() < 16 {
            panic!("GCM decrypt input must include authentication tag");
        }

        let ciphertext = &input[..input.len() - 16];
        let received_tag = &input[input.len() - 16..];

        // 计算h
        let zero_block = vec![0u8; block_size.into()];
        let h = block_encrypt(&zero_block);

        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        let iv_len = iv.len() * 8; // in bits

        let ghash_key: u128 = u128::from_be_bytes(h.to_vec().as_slice().try_into().unwrap());

        let counter0 = if iv_len == 96 {
            iv.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            u128::from_be_bytes(iv.as_slice().try_into().unwrap())
        } else {
            let iv_block_count = iv.len().div_ceil(block_size);
            iv.resize(block_size * iv_block_count, 0);
            let mut iv_blocks = Vec::with_capacity(iv_block_count + 1);
            for chunk in iv.chunks(block_size) {
                iv_blocks.push(u128::from_be_bytes(chunk.try_into().unwrap()));
            }
            iv_blocks.push(iv_len as u128);
            ghash_u128(ghash_key, &iv_blocks)
        };

        let counter0_block = Bytes::new(counter0.to_be_bytes().as_ref());
        let mut vector = Bytes::new(counter0.to_be_bytes().as_ref());

        let mut output = Vec::with_capacity(ciphertext.len());
        for chunk in ciphertext.chunks(block_size) {
            // 向量不断自增
            vector.inc32();
            let block = Bytes::new(chunk);
            let block_key = block_encrypt(&vector);
            output.extend_from_slice(&block.xor(&block_key));
        }

        // 计算认证标签用于验证
        let mut auth_data = Vec::new();

        // 添加附加认证数据（AAD）
        if let Some(aad) = &self.additional_data {
            auth_data.extend_from_slice(aad);
            // 填充至 16 字节边界
            let padding_len = (16 - (aad.len() % 16)) % 16;
            auth_data.extend_from_slice(&vec![0u8; padding_len]);
        }

        // 添加密文
        auth_data.extend_from_slice(ciphertext);
        // 填充至 16 字节边界
        let padding_len = (16 - (ciphertext.len() % 16)) % 16;
        auth_data.extend_from_slice(&vec![0u8; padding_len]);

        // 添加长度块：AAD 长度（比特）+ 密文长度（比特）
        let aad_len_bits = if let Some(aad) = &self.additional_data {
            (aad.len() * 8) as u64
        } else {
            0u64
        };
        let ciphertext_len_bits = (ciphertext.len() * 8) as u64;

        auth_data.extend_from_slice(&aad_len_bits.to_be_bytes());
        auth_data.extend_from_slice(&ciphertext_len_bits.to_be_bytes());

        // GHASH 计算
        let auth_blocks: Vec<u128> = auth_data
            .chunks(16)
            .map(|chunk| u128::from_be_bytes(chunk.try_into().unwrap()))
            .collect();

        let tag_u128 = ghash_u128(ghash_key, &auth_blocks);

        // 使用 counter0 加密标签
        let e_k0 = block_encrypt(&counter0_block);
        let e_k0_u128 = u128::from_be_bytes(e_k0.to_vec().as_slice().try_into().unwrap());
        let computed_tag = tag_u128 ^ e_k0_u128;
        let computed_tag_bytes = computed_tag.to_be_bytes();

        // 验证标签
        if computed_tag_bytes != received_tag {
            panic!("GCM authentication tag verification failed");
        }

        // 返回解密后的明文
        Bytes::new(output)
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Bytes {
        match block_size {
            BlockSize::Bytes16 => {}
            _ => panic!("GCM mode only supports 128-bit block size"),
        }

        // 计算h
        let zero_block = vec![0u8; block_size.into()];
        let h = block_encrypt(&zero_block);

        let block_size: usize = block_size.into();
        let mut iv = self.iv.to_vec();
        let iv_len = iv.len() * 8; // in bits

        let ghash_key: u128 = u128::from_be_bytes(h.to_vec().as_slice().try_into().unwrap());

        let counter0 = if iv_len == 96 {
            iv.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            u128::from_be_bytes(iv.as_slice().try_into().unwrap())
        } else {
            let iv_block_count = iv.len().div_ceil(block_size);
            iv.resize(block_size * iv_block_count, 0);
            let mut iv_blocks = Vec::with_capacity(iv_block_count + 1);
            for chunk in iv.chunks(block_size) {
                iv_blocks.push(u128::from_be_bytes(chunk.try_into().unwrap()));
            }
            iv_blocks.push(iv_len as u128);
            ghash_u128(ghash_key, &iv_blocks)
        };

        let counter0_block = Bytes::new(counter0.to_be_bytes().as_ref());
        let mut vector = Bytes::new(counter0.to_be_bytes().as_ref());

        let mut output = Vec::with_capacity(input.len());
        for chunk in input.chunks(block_size) {
            // 向量不断自增
            vector.inc32();
            let block = Bytes::new(chunk);
            let block_key = block_encrypt(&vector);
            output.extend_from_slice(&block.xor(&block_key));
        }

        // 计算认证标签
        let mut auth_data = Vec::new();

        // 添加附加认证数据（AAD）
        if let Some(aad) = &self.additional_data {
            auth_data.extend_from_slice(aad);
            // 填充至 16 字节边界
            let padding_len = (16 - (aad.len() % 16)) % 16;
            auth_data.extend_from_slice(&vec![0u8; padding_len]);
        }

        // 添加密文
        auth_data.extend_from_slice(&output);
        // 填充至 16 字节边界
        let padding_len = (16 - (output.len() % 16)) % 16;
        auth_data.extend_from_slice(&vec![0u8; padding_len]);

        // 添加长度块：AAD 长度（比特）+ 密文长度（比特）
        let aad_len_bits = if let Some(aad) = &self.additional_data {
            (aad.len() * 8) as u64
        } else {
            0u64
        };
        let ciphertext_len_bits = (output.len() * 8) as u64;

        auth_data.extend_from_slice(&aad_len_bits.to_be_bytes());
        auth_data.extend_from_slice(&ciphertext_len_bits.to_be_bytes());

        // GHASH 计算
        let auth_blocks: Vec<u128> = auth_data
            .chunks(16)
            .map(|chunk| u128::from_be_bytes(chunk.try_into().unwrap()))
            .collect();

        let tag_u128 = ghash_u128(ghash_key, &auth_blocks);

        // 使用 counter0 加密标签
        let e_k0 = block_encrypt(&counter0_block);
        let e_k0_u128 = u128::from_be_bytes(e_k0.to_vec().as_slice().try_into().unwrap());
        let tag = tag_u128 ^ e_k0_u128;

        // 返回值包含密文和标签
        output.extend_from_slice(&tag.to_be_bytes());
        Bytes::new(output)
    }
}

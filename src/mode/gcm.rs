use crate::bits::Bits;
use crate::bytes::Bytes;
use crate::enums::{Bit, BlockSize};
use crate::mode::Mode;
use crate::types::Result;

// GCM (Galois/Counter Mode)
// encrypts in CTR mode and appends an authentication tag for integrity checking
// supports only 128-bit blocks and the byte interface only
#[derive(Clone, Debug)]
pub struct Gcm {
    pub iv: Bytes,
    pub additional_data: Option<Bytes>,
}

impl Gcm {
    pub fn new(iv: &[u8], additional_data: Option<&[u8]>) -> Self {
        Self {
            iv: Bytes::new(iv),
            additional_data: additional_data.map(Bytes::new),
        }
    }
}

fn ghash_u128(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0u128;
    for message in messages {
        y = gmul_u128(y ^ message, key);
    }
    y
}

/// Galois field multiplication over u128
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

fn block_to_u128(block: &[u8]) -> u128 {
    u128::from_be_bytes(block.try_into().expect("GCM block must be 16 bytes"))
}

// compute the initial counter value
// for a 96-bit IV, append [0x00, 0x00, 0x00, 0x01] directly
// for other lengths, zero-pad to a 16-byte multiple, GHASH it, then append the bit length
fn counter0_from_iv(iv: &[u8], ghash_key: u128) -> u128 {
    if iv.len() * 8 == 96 {
        let mut block = iv.to_vec();
        block.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        block_to_u128(&block)
    } else {
        let mut padded = iv.to_vec();
        padded.resize(padded.len().div_ceil(16) * 16, 0);
        let mut blocks: Vec<u128> = padded.chunks(16).map(block_to_u128).collect();
        blocks.push((iv.len() * 8) as u128);
        ghash_u128(ghash_key, &blocks)
    }
}

// CTR-mode encryption/decryption (the counter is incremented before being encrypted)
// the counter increment follows the CyberChef implementation (only the last 32 bits)
fn ctr_crypt(input: &[u8], counter0: u128, block_encrypt: &impl Fn(&[u8]) -> Bytes) -> Vec<u8> {
    let mut counter = Bytes::new(counter0.to_be_bytes().as_slice());
    let mut output = Vec::with_capacity(input.len());

    for chunk in input.chunks(16) {
        // the counter keeps incrementing
        counter.inc32();
        let block_key = block_encrypt(&counter);
        output.extend_from_slice(&Bytes::new(chunk).xor(&block_key));
    }
    output
}

// compute the authentication tag
fn authentication_tag(
    additional_data: Option<&Bytes>,
    ciphertext: &[u8],
    counter0: u128,
    ghash_key: u128,
    block_encrypt: &impl Fn(&[u8]) -> Bytes,
) -> [u8; 16] {
    let mut auth_data = Vec::new();

    // append the additional authenticated data (AAD)
    if let Some(aad) = additional_data {
        auth_data.extend_from_slice(aad);
        // pad to a 16-byte boundary
        let padding_len = (16 - (aad.len() % 16)) % 16;
        auth_data.extend_from_slice(&vec![0u8; padding_len]);
    }

    // append the ciphertext
    auth_data.extend_from_slice(ciphertext);
    // pad to a 16-byte boundary
    let padding_len = (16 - (ciphertext.len() % 16)) % 16;
    auth_data.extend_from_slice(&vec![0u8; padding_len]);

    // append the length block: AAD length in bits + ciphertext length in bits
    let aad_len_bits = additional_data.map_or(0u64, |aad| (aad.len() * 8) as u64);
    let ciphertext_len_bits = (ciphertext.len() * 8) as u64;
    auth_data.extend_from_slice(&aad_len_bits.to_be_bytes());
    auth_data.extend_from_slice(&ciphertext_len_bits.to_be_bytes());

    // GHASH computation
    let tag = ghash_u128(
        ghash_key,
        &auth_data.chunks(16).map(block_to_u128).collect::<Vec<_>>(),
    );

    // encrypt the tag with counter0
    let e_k0 = block_encrypt(&Bytes::new(counter0.to_be_bytes().as_slice()));
    (tag ^ block_to_u128(&e_k0)).to_be_bytes()
}

impl Mode for Gcm {
    fn bits_decrypt(
        &self,
        _input: &[u8],
        _block_size: BlockSize,
        _block_decrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        Err("GCM mode does not support the bits interface".into())
    }

    fn bits_encrypt(
        &self,
        _input: &[u8],
        _block_size: BlockSize,
        _block_encrypt: impl Fn(&[Bit]) -> Bits,
    ) -> Result<Bytes> {
        Err("GCM mode does not support the bits interface".into())
    }

    fn bytes_decrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        if !matches!(block_size, BlockSize::Bytes16) {
            return Err("GCM mode only supports 128-bit block size".into());
        }
        if input.len() < 16 {
            return Err("GCM decrypt input must include the authentication tag".into());
        }

        let ciphertext = &input[..input.len() - 16];
        let received_tag = &input[input.len() - 16..];

        // compute h
        let ghash_key = block_to_u128(&block_encrypt(&[0u8; 16]));
        let counter0 = counter0_from_iv(&self.iv, ghash_key);

        let output = ctr_crypt(ciphertext, counter0, &block_encrypt);

        // compute the authentication tag for verification
        let computed_tag = authentication_tag(
            self.additional_data.as_ref(),
            ciphertext,
            counter0,
            ghash_key,
            &block_encrypt,
        );

        // verify the tag
        if computed_tag.as_slice() != received_tag {
            return Err("GCM authentication tag verification failed".into());
        }

        // return the decrypted plaintext
        Ok(Bytes::new(output))
    }

    fn bytes_encrypt(
        &self,
        input: &[u8],
        block_size: BlockSize,
        block_encrypt: impl Fn(&[u8]) -> Bytes,
    ) -> Result<Bytes> {
        if !matches!(block_size, BlockSize::Bytes16) {
            return Err("GCM mode only supports 128-bit block size".into());
        }

        // compute h
        let ghash_key = block_to_u128(&block_encrypt(&[0u8; 16]));
        let counter0 = counter0_from_iv(&self.iv, ghash_key);

        let output = ctr_crypt(input, counter0, &block_encrypt);

        // compute the authentication tag
        let tag = authentication_tag(
            self.additional_data.as_ref(),
            &output,
            counter0,
            ghash_key,
            &block_encrypt,
        );

        // the result contains the ciphertext and the tag
        let mut result = output;
        result.extend_from_slice(&tag);
        Ok(Bytes::new(result))
    }
}

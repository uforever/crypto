mod xxtea_decrypt;
mod xxtea_encrypt;

pub use xxtea_decrypt::XxteaDecrypt;
pub use xxtea_encrypt::XxteaEncrypt;

const DELTA: u32 = 0x9E3779B9;

const fn xxtea_mx(z: u32, y: u32, sum: u32, key: &[u32], p: usize, e: usize) -> u32 {
    (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
        ^ ((sum ^ y).wrapping_add(key[(p & 3) ^ e] ^ z))
}

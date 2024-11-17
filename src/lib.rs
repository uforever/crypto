pub mod aes;
pub mod base64;
pub mod bits;
pub mod bytes;
pub mod des;
pub mod enums;
pub mod hex;
pub mod hmac;
pub mod md5;
pub mod mode;
pub mod operation;
pub mod padding;
pub mod rc4;
pub mod recipe;
pub mod rot13;
pub mod sha1;
pub mod sha2;
pub mod tea;
pub mod types;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

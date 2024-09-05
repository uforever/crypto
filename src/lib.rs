pub mod base64;
pub mod bytes;
pub mod hex;
pub mod hmac;
pub mod md5;
pub mod operation;
pub mod rc4;
pub mod recipe;
pub mod sha1;
pub mod sha256;
pub mod sha512;

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

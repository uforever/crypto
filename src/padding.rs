mod bit_padding;
mod pkcs7_padding;
mod zero_padding;

pub use bit_padding::BitPadding;
pub use pkcs7_padding::Pkcs7Padding;
pub use zero_padding::ZeroPadding;

pub trait Padding {
    fn pad(&self, data: &[u8]) -> Vec<u8>;
}

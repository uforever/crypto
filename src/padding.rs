use crate::enums::BlockSize;

mod bit_padding;
mod no_padding;
mod pkcs7_padding;
mod zero_padding;

pub use bit_padding::BitPadding;
pub use no_padding::NoPadding;
pub use pkcs7_padding::Pkcs7Padding;
pub use zero_padding::ZeroPadding;

pub trait Padding {
    fn pad(&self, data: &[u8]) -> Vec<u8>;
    fn unpad(&self, data: &[u8]) -> Vec<u8>;

    fn build(block_size: BlockSize) -> Self;
}

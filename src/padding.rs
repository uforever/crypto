mod bit_padding;
mod pkcs_padding;
mod zero_padding;

pub use bit_padding::BitPadding;
pub use pkcs_padding::PKCSPadding;
pub use zero_padding::ZeroPadding;

pub trait Padding {
    fn pad(&self, data: &[u8]) -> Vec<u8>;
}

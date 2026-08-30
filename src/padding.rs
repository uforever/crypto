use std::fmt::Debug;

use crate::enums::BlockSize;
use crate::types::Result;

mod bit_padding;
mod no_padding;
mod pkcs7_padding;
mod zero_padding;

pub use bit_padding::BitPadding;
pub use no_padding::NoPadding;
pub use pkcs7_padding::Pkcs7Padding;
pub use zero_padding::ZeroPadding;

/// A padding scheme that stretches data to a multiple of the block size.
pub trait Padding: Debug {
    /// Appends padding bytes so the length becomes a multiple of the block size.
    fn pad(&self, data: &[u8]) -> Vec<u8>;
    /// Strips the padding from the data, or fails if it is malformed.
    fn unpad(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Constructs the padding scheme for the given block size.
    fn build(block_size: BlockSize) -> Self;
}

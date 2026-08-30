use crate::bytes::Bytes;
use crate::types::Result;

mod hashing;
pub use hashing::Hashing;

/// A unit of work that transforms bytes into bytes.
///
/// Ciphers, hashes and encodings all implement this trait so they can be
/// composed freely.
pub trait Operation {
    /// Runs the operation over `input`, or fails with an error.
    fn run(&self, input: &[u8]) -> Result<Bytes>;
}

use crate::bytes::Bytes;
use crate::types::Result;

mod hasing;
pub use hasing::Hashing;

pub trait Operation {
    fn run(&self, input: &[u8]) -> Result<Bytes>;
}

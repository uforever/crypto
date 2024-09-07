use crate::bytes::Bytes;

mod hasing;
pub use hasing::Hashing;

pub trait Operation {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes>;
}

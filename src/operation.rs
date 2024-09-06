use crate::bytes::Bytes;
use std::fmt::Debug;

pub trait Operation {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes>;
}

pub trait Hashing: Operation + Default + Debug {
    fn block_size(&self) -> usize;
    fn output_size(&self) -> usize;
}

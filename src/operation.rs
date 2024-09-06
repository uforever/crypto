use crate::bytes::Bytes;
//use std::fmt::Debug;

pub trait Operation {
    fn run(&self, input: &[u8]) -> anyhow::Result<Bytes>;
}

#[derive(Clone, Copy, Debug)]
pub enum BlockSize {
    Bytes8,
    Bytes16,
    Bytes32,
    Bytes64,
    Bytes128,
}

impl From<BlockSize> for usize {
    fn from(value: BlockSize) -> Self {
        match value {
            BlockSize::Bytes8 => 8,
            BlockSize::Bytes16 => 16,
            BlockSize::Bytes32 => 32,
            BlockSize::Bytes64 => 64,
            BlockSize::Bytes128 => 128,
        }
    }
}

//pub trait Hashing: Operation + Default + Debug {
pub trait Hashing: Operation + Default {
    fn block_size(&self) -> BlockSize;
    //fn output_size(&self) -> usize;
}

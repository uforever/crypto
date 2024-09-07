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

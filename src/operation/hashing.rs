use crate::enums::BlockSize;
use crate::operation::Operation;
//use std::fmt::Debug;

//pub trait Hashing: Operation + Default + Debug {
/// A hashing operation that reports its internal block size.
pub trait Hashing: Operation + Default {
    /// Returns the internal block size in bytes.
    fn block_size(&self) -> BlockSize;
    //fn output_size(&self) -> usize;
}

use crate::enums::BlockSize;
use crate::operation::Operation;
//use std::fmt::Debug;

//pub trait Hashing: Operation + Default + Debug {
pub trait Hashing: Operation + Default {
    fn block_size(&self) -> BlockSize;
    //fn output_size(&self) -> usize;
}

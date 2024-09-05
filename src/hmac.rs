use crate::bytes::Bytes;
use crate::operation::{Hashing, Operation};

#[derive(Debug)]
pub struct HMAC<T: Hashing> {
    key: Bytes,
    hash_function: T,
}

impl<T: Hashing> HMAC<T> {
    //pub fn new(key: Bytes) -> Self {
    pub fn new(key: Bytes) -> Self {
        Self {
            key,
            hash_function: T::default(),
        }
    }
}

impl<T: Hashing> Operation for HMAC<T> {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
        println!("{}", self.key);
        println!("{:?}", self.hash_function);

        let output = self.hash_function.run(input)?;
        Ok(output)
    }
}

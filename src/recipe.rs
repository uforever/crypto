use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

/// A pipeline of operations applied in order to the input.
pub struct Recipe {
    pub op_list: Vec<Box<dyn Operation>>,
}

impl Recipe {
    /// Creates a recipe from a list of operations.
    pub fn new(op_list: Vec<Box<dyn Operation>>) -> Self {
        Self { op_list }
    }

    /// Runs every operation in sequence, feeding each output into the next.
    pub fn bake(&self, input: &[u8]) -> Result<Bytes> {
        let output = self.op_list.iter().try_fold(input.to_vec(), |data, op| {
            op.run(&data).map(|result| result.to_vec())
        })?;
        Ok(Bytes::new(output))
    }
}

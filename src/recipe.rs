use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

//#[derive(Debug)]
pub struct Recipe {
    pub op_list: Vec<Box<dyn Operation>>,
}

impl Recipe {
    pub fn new(op_list: Vec<Box<dyn Operation>>) -> Self {
        Self { op_list }
    }

    pub fn bake(&self, input: &[u8]) -> Result<Bytes> {
        let output = self.op_list.iter().try_fold(input.to_vec(), |data, op| {
            op.run(&data).map(|result| result.to_vec())
        })?;
        Ok(Bytes::new(output))
    }
}

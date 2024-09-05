use crate::bytes::Bytes;
use crate::operation::Operation;

#[derive(Debug)]
pub struct Recipe<T: Operation> {
    pub op_list: Vec<T>,
}

impl<T: Operation> Recipe<T> {
    pub fn new(op_list: Vec<T>) -> Self {
        Self { op_list }
    }

    pub fn bake(&self, input: Bytes) -> anyhow::Result<Bytes> {
        let mut output = input;
        for op in self.op_list.iter() {
            output = op.run(output)?;
        }
        Ok(output)
    }
}

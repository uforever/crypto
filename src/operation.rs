use crate::bytes::Bytes;

pub trait Operation {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes>;
}

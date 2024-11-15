use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug)]
pub struct Rot {
    pub shift: u8,
}

impl Rot {
    pub fn new(shift: u8) -> Self {
        Self { shift: shift % 26 }
    }
}

impl Default for Rot {
    fn default() -> Self {
        Self::new(13)
    }
}
impl Operation for Rot {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        if self.shift == 0 {
            return Ok(Bytes::new(input));
        }

        let output: Vec<u8> = input
            .iter()
            .map(|&byte| match byte {
                b'A'..=b'Z' => ((byte - b'A' + self.shift) % 26) + b'A',
                b'a'..=b'z' => ((byte - b'a' + self.shift) % 26) + b'a',
                _ => byte,
            })
            .collect();
        Ok(Bytes::new(output))
    }
}

use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug)]
pub struct Rot13 {
    pub shift: u8,
}

impl Rot13 {
    pub fn new(shift: u8) -> Self {
        Self { shift: shift % 26 }
    }
}

impl Default for Rot13 {
    fn default() -> Self {
        Self::new(13)
    }
}

impl Operation for Rot13 {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        if self.shift == 0 {
            return Ok(Bytes::new(input));
        }

        let left_shift = 26 - self.shift;
        let upper_divider = b'Z' - self.shift + 1;
        let lower_divider = b'z' - self.shift + 1;

        let output: Vec<u8> = input
            .iter()
            .map(|&byte| {
                if (byte >= b'A' && byte < upper_divider) || (byte >= b'a' && byte < lower_divider)
                {
                    byte + self.shift
                } else if (byte >= upper_divider && byte <= b'Z')
                    || (byte >= lower_divider && byte <= b'z')
                {
                    byte - left_shift
                } else {
                    byte
                }
            })
            .collect();
        Ok(Bytes::new(output))
    }
}

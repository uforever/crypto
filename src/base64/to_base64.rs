use crate::base64::alphabet::Alphabet;
use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug, Default)]
pub struct ToBase64 {
    pub alphabet: Alphabet,
}

impl ToBase64 {
    pub fn new(alphabet: Alphabet) -> Self {
        Self { alphabet }
    }
}
impl Operation for ToBase64 {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
        let mut encoded_bits_count = 0usize;
        let mut base64_string = String::new();
        let length = input.len();
        loop {
            let index = encoded_bits_count / 8;
            if index == length {
                break;
            }
            let lower_byte = input[index];
            let upper_byte = if index + 1 < length {
                input[index + 1]
            } else {
                0 // padding
            };
            let offset = (encoded_bits_count % 8) as u8;
            let combined: u16 = ((lower_byte as u16) << 8) | (upper_byte as u16);
            let index_of_64 =
                ((combined & (0b1111110000000000u16 >> offset)) >> (10 - offset)) as usize;
            base64_string.push(self.alphabet.charset[index_of_64] as char);
            encoded_bits_count += 6;
        }

        if let Some(c) = self.alphabet.padding {
            let padding_needed = ((6 - (input.len() * 8) % 6) / 2) % 3;
            for _ in 0..padding_needed {
                base64_string.push(c as char);
            }
        }

        Ok(Bytes::new(base64_string.as_bytes()))
    }
}

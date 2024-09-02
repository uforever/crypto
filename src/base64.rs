pub mod alphabet;

use crate::bytes::Bytes;
use crate::operation::Operation;
use alphabet::Alphabet;

#[derive(Default)]
pub struct FromBase64 {
    pub alphabet: Alphabet,
    pub strict_mode: bool,
}

#[derive(Default)]
pub struct ToBase64 {
    pub alphabet: Alphabet,
}

impl FromBase64 {
    pub fn new(alphabet: Alphabet, strict_mode: bool) -> Self {
        Self {
            alphabet,
            strict_mode,
        }
    }
}

impl ToBase64 {
    pub fn new(alphabet: Alphabet) -> Self {
        Self { alphabet }
    }
}
impl Operation for FromBase64 {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
        let mut collected_bits = 0usize;
        let mut combined_buffer = 0u16;
        let mut output_bytes: Vec<u8> = Vec::new();
        for byte in input.iter() {
            if let Some(index) = self.alphabet.charset.iter().position(|&c| c == *byte) {
                combined_buffer |= ((index & 0b00111111) as u16) << (10 - collected_bits);
                collected_bits += 6;
            } else if self.alphabet.padding == Some(*byte) {
                if collected_bits == 0 {
                    if self.strict_mode {
                        return Err(anyhow::anyhow!(
                            "[FromBase64] invalid padding in strict mode"
                        ));
                    } else {
                        collected_bits = 6;
                    }
                } else {
                    collected_bits -= 2;
                }
            } else {
                return Err(anyhow::anyhow!(
                    "[FromBase64] invalid character in base64 string"
                ));
            }

            if collected_bits >= 8 {
                output_bytes.push(((combined_buffer & 0xff00) >> 8) as u8);
                combined_buffer &= 0x00ff;
                combined_buffer <<= 8;
                collected_bits -= 8;
            }
        }

        // strict mode
        if self.strict_mode && collected_bits != 0 && self.alphabet.padding.is_some() {
            return Err(anyhow::anyhow!(
                "[FromBase64] invalid padding in strict mode"
            ));
        }

        Ok(Bytes::new(output_bytes))
    }
}

impl Operation for ToBase64 {
    fn run(&self, input: Bytes) -> anyhow::Result<Bytes> {
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
            let combined: u16 = (lower_byte as u16) << 8 | (upper_byte as u16);
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

        Ok(Bytes::from(base64_string))
    }
}

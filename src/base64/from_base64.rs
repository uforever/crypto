use crate::base64::alphabet::Alphabet;
use crate::bytes::Bytes;
use crate::operation::Operation;
use crate::types::Result;

#[derive(Debug, Default)]
pub struct FromBase64 {
    pub alphabet: Alphabet,
    pub strict_mode: bool,
}

impl FromBase64 {
    pub fn new(alphabet: Alphabet, strict_mode: bool) -> Self {
        Self {
            alphabet,
            strict_mode,
        }
    }
}

impl Operation for FromBase64 {
    fn run(&self, input: &[u8]) -> Result<Bytes> {
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
                        return Err("[FromBase64] invalid padding in strict mode".into());
                    } else {
                        collected_bits = 6;
                    }
                } else {
                    collected_bits -= 2;
                }
            } else {
                return Err("[FromBase64] invalid character in base64 string".into());
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
            return Err("[FromBase64] invalid padding in strict mode".into());
        }

        Ok(Bytes::new(output_bytes))
    }
}

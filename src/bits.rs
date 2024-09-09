use crate::enums::Bit;
use std::ops::Deref;

#[derive(Default, Debug)]
pub struct Bits {
    inner: Vec<Bit>,
}

impl Bits {
    pub fn new<T>(s: T) -> Self
    where
        T: Deref<Target = [Bit]>,
    {
        Self { inner: s.to_vec() }
    }

    pub fn permutation(&self, permuted_choice: &[usize]) -> Self {
        let output_len = permuted_choice.len();
        let mut output = Vec::with_capacity(output_len);
        for i in permuted_choice {
            let bit: Bit = match self.get(*i) {
                Some(bit) => *bit,
                None => Bit::Zero,
            };
            output.push(bit);
        }
        Bits::new(output)
    }
}

impl Deref for Bits {
    type Target = [Bit];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<&[u8]> for Bits {
    fn from(value: &[u8]) -> Self {
        let mut bits = vec![];

        for byte in value {
            for i in 0..8 {
                bits.push(if byte & (1 << (7 - i)) != 0 {
                    Bit::One
                } else {
                    Bit::Zero
                });
            }
        }

        Bits::new(bits)
    }
}

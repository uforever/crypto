use crate::enums::Bit;
use std::fmt::Debug;
use std::ops::{BitXor, Deref};

#[derive(Clone, Default)]
pub struct Bits {
    inner: Vec<Bit>,
}

impl Debug for Bits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl Bits {
    pub fn new<T>(s: T) -> Self
    where
        T: Deref<Target = [Bit]>,
    {
        Self { inner: s.to_vec() }
    }

    pub fn align(&self, len: usize, value: Bit) -> Self {
        let mut v = self.to_vec();
        v.reverse();
        v.resize(len, value);
        v.reverse();
        Bits::new(v)
    }

    pub fn xor(&self, other: &Self) -> Self {
        self ^ other
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

impl<'a> BitXor<&'a Bits> for &'a Bits {
    type Output = Bits;

    fn bitxor(self, rhs: &'a Bits) -> Self::Output {
        let self_len = self.len();
        let rhs_len = rhs.len();
        let max_len = self_len.max(rhs_len);

        let aligned_self = self.align(max_len, Bit::Zero);
        let aligned_rhs = rhs.align(max_len, Bit::Zero);

        let mut output = Vec::with_capacity(max_len);

        for i in 0..max_len {
            output.push(aligned_self[i] ^ aligned_rhs[i]);
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

impl From<&Bits> for usize {
    fn from(value: &Bits) -> Self {
        let mut result = 0usize;
        for bit in value.iter() {
            result <<= 1;
            match bit {
                Bit::One => result |= 1,
                Bit::Zero => {}
            }
        }
        result
    }
}

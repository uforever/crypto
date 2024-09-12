use std::fmt;
use std::ops::{BitXor, Deref};

use crate::bytes::Bytes;
use crate::enums::Bit::{self, One, Zero};

#[derive(Clone, Default)]
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

    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.deref())
    }

    pub fn xor(&self, other: &Self) -> Self {
        self ^ other
    }

    // bits to number
    pub fn to_usize(&self) -> usize {
        let mut result = 0usize;
        for bit in self.iter() {
            result <<= 1;
            match bit {
                One => result |= 1,
                Zero => {}
            }
        }
        result
    }

    // left resize
    pub fn align(&self, len: usize, value: Bit) -> Self {
        let mut v = self.to_vec();
        v.reverse();
        v.resize(len, value);
        v.reverse();
        Bits::new(v)
    }

    // 置换
    pub fn permutation(&self, permuted_choice: &[usize]) -> Self {
        let output_len = permuted_choice.len();
        let mut output = Vec::with_capacity(output_len);

        // 根据 置换选择表 得到输出序列
        for i in permuted_choice {
            output.push(match self.get(*i) {
                Some(bit) => *bit,
                None => Zero,
            });
        }
        Bits::new(output)
    }

    // 替换
    pub fn substitution<Sbox: AsRef<[Row]>, Row: AsRef<[Bit]>>(&self, sbox: Sbox) -> Self {
        // bits -> usize
        let index = self.to_usize();
        // get row(bits) from sbox
        let row = &sbox.as_ref()[index];
        // convert row(bits) to Bits
        Bits::new(row.as_ref())
    }
}

impl Deref for Bits {
    type Target = [Bit];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for Bits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl<'a> BitXor<&'a Bits> for &'a Bits {
    type Output = Bits;

    fn bitxor(self, rhs: &'a Bits) -> Self::Output {
        // align bits to the same length
        let max_len = self.len().max(rhs.len());
        let aligned_self = self.align(max_len, Zero);
        let aligned_rhs = rhs.align(max_len, Zero);

        // bit xor
        let mut output = Vec::with_capacity(max_len);
        for i in 0..max_len {
            output.push(aligned_self[i] ^ aligned_rhs[i]);
        }

        Bits::new(output)
    }
}

// bytes to bits
impl From<&[u8]> for Bits {
    fn from(value: &[u8]) -> Self {
        let length = value.len() * 8;
        let mut bits = Vec::with_capacity(length);

        for byte in value {
            bits.push(if (byte & 0b10000000) == 0 { Zero } else { One });
            bits.push(if (byte & 0b01000000) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00100000) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00010000) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00001000) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00000100) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00000010) == 0 { Zero } else { One });
            bits.push(if (byte & 0b00000001) == 0 { Zero } else { One });
        }

        Bits::new(bits)
    }
}

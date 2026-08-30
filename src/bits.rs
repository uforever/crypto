use std::fmt;
use std::ops::{BitXor, Deref};

use crate::bytes::Bytes;
use crate::enums::Bit::{self, One, Zero};

/// A bit-string wrapper around `Vec<Bit>`.
#[derive(Clone, Default)]
pub struct Bits {
    inner: Vec<Bit>,
}

impl Bits {
    /// Creates `Bits` from anything that dereferences to `[Bit]`.
    pub fn new<T>(s: T) -> Self
    where
        T: Deref<Target = [Bit]>,
    {
        Self { inner: s.to_vec() }
    }

    /// Packs the bits into bytes, zero-padding the final partial byte.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.deref())
    }

    /// Cyclic XOR: the right operand repeats to match this length.
    pub fn xor(&self, other: &Self) -> Self {
        self ^ other
    }

    // increments by one, overflow ignored
    /// Increments the value by one (big-endian), wrapping around on overflow.
    pub fn inc(&mut self) {
        for i in (0..self.len()).rev() {
            match self.inner[i] {
                Zero => {
                    self.inner[i] = One;
                    break;
                }
                One => {
                    self.inner[i] = Zero;
                }
            }
        }
    }

    // increments the last 32 bits, overflow ignored
    /// Increments only the last 32 bits (big-endian), wrapping around on overflow.
    pub fn inc32(&mut self) {
        let len = self.len();
        for i in (len - 32..len).rev() {
            match self.inner[i] {
                Zero => {
                    self.inner[i] = One;
                    break;
                }
                One => {
                    self.inner[i] = Zero;
                }
            }
        }
    }

    // bits to number
    /// Interprets the bits as a big-endian unsigned number.
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
    /// Left-pads with `value` until the length reaches `len`.
    pub fn align(&self, len: usize, value: Bit) -> Self {
        let mut v = self.to_vec();
        v.reverse();
        v.resize(len, value);
        v.reverse();
        Self::new(v)
    }

    // permutation
    /// Selects bits by the given index table; out-of-range indexes yield `Zero`.
    pub fn permutation(&self, permuted_choice: &[usize]) -> Self {
        let output_len = permuted_choice.len();
        let mut output = Vec::with_capacity(output_len);

        // build the output sequence from the permutation choice table
        for i in permuted_choice {
            output.push(match self.get(*i) {
                Some(bit) => *bit,
                None => Zero,
            });
        }
        Self::new(output)
    }

    // substitution
    /// Substitutes this bit group via an S-box looked up by its numeric value.
    pub fn substitution<Sbox: AsRef<[Row]>, Row: AsRef<[Bit]>>(&self, sbox: Sbox) -> Self {
        // bits -> usize
        let index = self.to_usize();
        // get row(bits) from sbox
        let row = &sbox.as_ref()[index];
        // convert row(bits) to Bits
        Self::new(row.as_ref())
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

    // xor is always a cyclic xor
    fn bitxor(self, rhs: &'a Bits) -> Self::Output {
        // bit xor
        let length = self.len();
        let rhs_len = rhs.len();
        let mut output = Vec::with_capacity(length);
        for i in 0..length {
            output.push(self[i] ^ rhs[i % rhs_len]);
        }

        Self::Output::new(output)
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

use std::fmt;
use std::ops::{BitXor, Deref};

use crate::bits::Bits;
use crate::enums::Bit;

#[derive(Clone, Default)]
pub struct Bytes {
    inner: Vec<u8>,
}

impl Bytes {
    pub fn new<T>(s: T) -> Self
    where
        T: Deref<Target = [u8]>,
    {
        Self { inner: s.to_vec() }
    }

    pub fn to_bits(&self) -> Bits {
        Bits::from(self.deref())
    }

    pub fn align(&self, len: usize, value: u8) -> Self {
        let mut v = self.to_vec();
        v.reverse();
        v.resize(len, value);
        v.reverse();
        Self::new(v)
    }

    pub fn xor(&self, other: &Self) -> Self {
        self ^ other
    }

    // 自增1 不关心溢出
    pub fn inc(&mut self) {
        for i in (0..self.len()).rev() {
            if self.inner[i] == 0xff {
                self.inner[i] = 0x00;
            } else {
                self.inner[i] += 1;
                break;
            }
        }
    }

    // 32位自增 不关心溢出
    pub fn inc32(&mut self) {
        let len = self.len();
        for i in (len - 4..len).rev() {
            if self.inner[i] == 0xff {
                self.inner[i] = 0x00;
            } else {
                self.inner[i] += 1;
                break;
            }
        }
    }

    pub fn permutation(&self, permuted_choice: &[usize]) -> Self {
        let output_len = permuted_choice.len();
        let mut output = Vec::with_capacity(output_len);

        for i in permuted_choice {
            output.push(match self.get(*i) {
                Some(byte) => *byte,
                None => 0,
            });
        }
        Self::new(output)
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match std::str::from_utf8(self) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => fmt::Debug::fmt(self, f),
        }
    }
}

impl From<&[Bit]> for Bytes {
    fn from(value: &[Bit]) -> Self {
        let mut length = value.len();
        let modulus = length % 8;
        let aligned_bits: Bits = if modulus != 0 {
            length = length / 8 + 1;
            Bits::new(value).align(length * 8, Bit::Zero)
        } else {
            length /= 8;
            Bits::new(value)
        };
        let mut bytes = Vec::with_capacity(length);

        for chunk in aligned_bits.chunks(8) {
            bytes.push(Bits::new(chunk).to_usize() as u8);
        }
        Self::new(bytes)
    }
}

impl<'a> BitXor<&'a Bytes> for &'a Bytes {
    type Output = Bytes;

    // xor 统一改为循环异或
    fn bitxor(self, rhs: &'a Bytes) -> Self::Output {
        let length = self.len();
        let rhs_len = rhs.len();

        let mut result = Vec::with_capacity(length);
        for i in 0..length {
            result.push(self[i] ^ rhs[i % rhs_len]);
        }

        Self::Output::new(result)
    }
}

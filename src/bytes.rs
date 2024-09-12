use crate::bits::Bits;
use crate::enums::Bit;
use crate::types::Error;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

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

impl<T> From<T> for Bytes
where
    T: Deref<Target = [Bit]>,
{
    fn from(value: T) -> Self {
        let bits = value.deref();
        let mut length = bits.len();
        let modulus = length % 8;
        let aligned_bits: Bits = if modulus != 0 {
            length = length / 8 + 1;
            Bits::new(bits).align(length * 8, Bit::Zero)
        } else {
            length /= 8;
            Bits::new(bits)
        };
        let mut bytes = Vec::with_capacity(length);

        for chunk in aligned_bits.chunks(8) {
            bytes.push(Bits::new(chunk).to_usize() as u8);
        }
        Self::new(bytes)
    }
}

impl FromStr for Bytes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.as_bytes()))
    }
}

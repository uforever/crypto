use crate::types::Error;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Default)]
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

//impl<T> From<T> for Bytes
//where
//    T: Deref<Target = [Bit]>,
//{
//    fn from(value: T) -> Self {
//        let mut bytes = vec![];
//        let bits = value.deref();
//
//        for chunk in bits.chunks(8) {
//            let mut byte = 0u8;
//            for (i, bit) in chunk.iter().enumerate() {
//                match bit {
//                    Bit::Zero => {}
//                    Bit::One => {
//                        byte |= 1 << i;
//                    }
//                }
//            }
//            bytes.push(byte);
//        }
//        Self::new(bytes)
//    }
//}

impl FromStr for Bytes {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s.as_bytes()))
    }
}

use std::fmt::Debug;

#[derive(Clone, Copy)]
pub enum Bit {
    Zero,
    One,
}

impl Debug for Bit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bit::Zero => write!(f, "0"),
            Bit::One => write!(f, "1"),
        }
    }
}

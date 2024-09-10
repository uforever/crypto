use std::fmt::Debug;
use std::ops::BitXor;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Bit {
    #[default]
    Zero,
    One,
}

impl BitXor for Bit {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Bit::Zero, Bit::Zero) => Bit::Zero,
            (Bit::Zero, Bit::One) => Bit::One,
            (Bit::One, Bit::Zero) => Bit::One,
            (Bit::One, Bit::One) => Bit::Zero,
        }
    }
}

impl<'a> BitXor<&'a Bit> for &'a Bit {
    type Output = Bit;

    fn bitxor(self, rhs: &'a Bit) -> Self::Output {
        match (self, rhs) {
            (&Bit::Zero, &Bit::Zero) => Bit::Zero,
            (&Bit::Zero, &Bit::One) => Bit::One,
            (&Bit::One, &Bit::Zero) => Bit::One,
            (&Bit::One, &Bit::One) => Bit::Zero,
        }
    }
}

impl Debug for Bit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bit::Zero => write!(f, "0"),
            Bit::One => write!(f, "1"),
        }
    }
}

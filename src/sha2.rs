//! The SHA-2 hash family (FIPS 180-4).

mod sha256;
mod sha512;

pub use sha256::Sha256;
pub use sha512::Sha512;

//! Base64 encoding and decoding (RFC 4648).

pub mod alphabet;
mod from_base64;
mod to_base64;

pub use from_base64::FromBase64;
pub use to_base64::ToBase64;

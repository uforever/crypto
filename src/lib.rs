//! A CyberChef-inspired crypto toolkit.
//!
//! Block/stream ciphers, hashes, encodings and padding schemes implemented
//! as composable [`Operation`]s, operating on the [`Bytes`] data type.
//!
//! [`Operation`]: crate::operation::Operation
//! [`Bytes`]: crate::bytes::Bytes

pub mod aes;
pub mod base64;
pub mod bits;
pub mod bytes;
pub mod des;
pub mod enums;
pub mod hex;
pub mod hmac;
pub mod md5;
pub mod mode;
pub mod operation;
pub mod padding;
pub mod rc4;
pub mod recipe;
pub mod rot13;
pub mod sha1;
pub mod sha2;
pub mod sm3;
pub mod sm4;
pub mod tea;
pub mod types;

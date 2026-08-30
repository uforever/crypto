# crypto

[中文](README.zh-CN.md) | English

Common encryption, decryption, hashing and encoding algorithms implemented in pure Rust, for
educational purposes only.

## Design

Inspired by [CyberChef](https://github.com/gchq/CyberChef), every algorithm is wrapped as an
`Operation` whose input and output are both `Bytes`.

One or more `Operation`s can be chained into a `Recipe` and applied to data in sequence.

## Features

- Zero third-party dependencies, standard library only.
- Non-standard key lengths are accepted for DES / AES and other algorithms, compatible with
  [crypto-js](https://github.com/brix/crypto-js).
- Modular `Padding` and block cipher `Mode` design, easy to extend.
- Generic `Operation` pipeline: combine hashing, encoding, encryption freely.

## Operations

| Category   | Operations |
| ---------- | ---------- |
| Encoding   | `FromHex`, `ToHex`, `FromBase64`, `ToBase64` |
| Text       | `Rot13` (configurable shift) |
| Hashing    | `Md5`, `Sha1` (configurable rounds), `Sha256`, `Sha512`, `Sm3` |
| MAC        | `Hmac<H>` (works with any `Hashing`, e.g. `Hmac::<Sha256>`) |
| Stream     | `Rc4` |
| Block      | `AesEncrypt` / `AesDecrypt`, `DesEncrypt` / `DesDecrypt`, `TripleDesEncrypt` / `TripleDesDecrypt`, `Sm4Encrypt` / `Sm4Decrypt` |
| Other      | `XxteaEncrypt` / `XxteaDecrypt` (with `include_length` option) |

## Paddings

`BitPadding` (used by MD5 / SHA family), `Pkcs7Padding`, `ZeroPadding`, `NoPadding`

## Modes

`Ecb`, `Cbc`, `Cfb`, `Ofb`, `Ctr`, `Gcm` (AEAD, authenticated with AAD support)

## Usage

Add the crate and import what you need:

```rust
use crypto::aes::{AesDecrypt, AesEncrypt};
use crypto::base64::{FromBase64, ToBase64};
use crypto::bytes::Bytes;
use crypto::md5::Md5;
use crypto::mode::Cbc;
use crypto::padding::Pkcs7Padding;
use crypto::recipe::Recipe;
use crypto::types::Result;

fn main() -> Result<()> {
    // Hashing
    let md5 = Recipe::new(vec![Box::new(Md5)]);
    let digest = md5.bake(&Bytes::new(b"123456".as_ref()))?;
    println!("{:?}", digest); // Debug prints hex

    // AES-CBC encrypt + Base64
    let key = Bytes::new("01234567890123456789".as_bytes());
    let iv = Bytes::new("01234567".as_bytes());
    let encrypt = Recipe::new(vec![
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(&key, Cbc::new(&iv))),
        Box::new(ToBase64::default()),
    ]);
    let ciphertext = encrypt.bake(&Bytes::new(b"Hello, World!".as_ref()))?;
    println!("{}", ciphertext);

    // Base64 decode + AES-CBC decrypt
    let decrypt = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(AesDecrypt::<_, Pkcs7Padding>::new(&key, Cbc::new(&iv))),
    ]);
    let plaintext = decrypt.bake(&ciphertext)?;
    println!("{}", plaintext);

    Ok(())
}
```

More advanced examples (CFB / OFB / CTR / GCM, DES, 3DES, SM4, XXTEA, RC4, custom hex / base64
alphabets) can be found in the [examples](examples) directory.

## Run examples

```sh
cargo run --example encoding
cargo run --example hashing
cargo run --example padding
cargo run --example encryption
```

## Run tests

```sh
cargo test
```

## Disclaimer

This project is for learning and CTF / crackme practice only. The implementations have not been
audited; do not use them in production.

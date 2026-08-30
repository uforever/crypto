# crypto

中文 | [English](README.md)

常见加解密、哈希与编码算法的纯 Rust 实现，仅供学习参考。

## 设计思路

参考 [CyberChef](https://github.com/gchq/CyberChef)，将每种算法封装为一个 `Operation`
（输入输出均为 `Bytes`）。

单个或多个 `Operation` 可以串联成 `Recipe`，按顺序对数据进行处理。

## 特点

- 不依赖任何第三方库，仅使用标准库。
- 对于 DES、AES 等算法，支持非标准长度的密钥，兼容
  [crypto-js](https://github.com/brix/crypto-js)。
- 模块化的填充方式（`Padding`）和加密模式（`Mode`）设计，便于扩展。
- 泛型化的 `Operation` 流水线：哈希、编码、加密可自由组合。

## `Operation`

| 分类   | 操作 |
| ------ | ---- |
| 编码   | `FromHex`、`ToHex`、`FromBase64`、`ToBase64` |
| 文本   | `Rot13`（可配置偏移量） |
| 哈希   | `Md5`、`Sha1`（可配置轮数）、`Sha256`、`Sha512`、`Sm3` |
| MAC    | `Hmac<H>`（可搭配任意 `Hashing`，如 `Hmac::<Sha256>`） |
| 流加密 | `Rc4` |
| 分组加密 | `AesEncrypt` / `AesDecrypt`、`DesEncrypt` / `DesDecrypt`、`TripleDesEncrypt` / `TripleDesDecrypt`、`Sm4Encrypt` / `Sm4Decrypt` |
| 其他   | `XxteaEncrypt` / `XxteaDecrypt`（含 `include_length` 选项） |

## `Padding`

`BitPadding`（MD5 / SHA 系列使用）、`Pkcs7Padding`、`ZeroPadding`、`NoPadding`

## `Mode`

`Ecb`、`Cbc`、`Cfb`、`Ofb`、`Ctr`、`Gcm`（AEAD，支持 AAD 认证）

## 使用方式

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
    // 哈希
    let md5 = Recipe::new(vec![Box::new(Md5)]);
    let digest = md5.bake(&Bytes::new(b"123456".as_ref()))?;
    println!("{:?}", digest); // Debug 输出十六进制

    // AES-CBC 加密 + Base64
    let key = Bytes::new("01234567890123456789".as_bytes());
    let iv = Bytes::new("01234567".as_bytes());
    let encrypt = Recipe::new(vec![
        Box::new(AesEncrypt::<_, Pkcs7Padding>::new(&key, Cbc::new(&iv))),
        Box::new(ToBase64::default()),
    ]);
    let ciphertext = encrypt.bake(&Bytes::new(b"Hello, World!".as_ref()))?;
    println!("{}", ciphertext);

    // Base64 解码 + AES-CBC 解密
    let decrypt = Recipe::new(vec![
        Box::new(FromBase64::default()),
        Box::new(AesDecrypt::<_, Pkcs7Padding>::new(&key, Cbc::new(&iv))),
    ]);
    let plaintext = decrypt.bake(&ciphertext)?;
    println!("{}", plaintext);

    Ok(())
}
```

更多进阶示例（CFB / OFB / CTR / GCM、DES、3DES、SM4、XXTEA、RC4、自定义
hex / base64 字母表）见 [examples](examples) 目录。

## 运行示例

```sh
cargo run --example encoding
cargo run --example hashing
cargo run --example padding
cargo run --example encryption
```

## 运行测试

```sh
cargo test
```

## 免责声明

本项目仅供学习以及 CTF / crackme 练习使用，实现未经安全审计，请勿用于生产环境。

# crypto

常见加解密算法的rust实现 , 仅供参考

## 设计思路

参考 [CyberChef](https://github.com/gchq/CyberChef) , 实现多种 `Operation` ( 输入输出都是 `Bytes` ) 

单个或多个 `Operation` 串联成 `Recipe` , 对数据进行操作

## 特点

不依赖于任何第三方库

对于 DES、AES 等算法 , 支持非标准长度的密钥 , 兼容 [crypto-js](https://github.com/brix/crypto-js)

模块化的 填充方式( `Padding` ) 和 加密模式( `Mode` ) 设计 , 便于扩展

## `Operation`

`FromHex`, `ToHex`，

`FromBase64`, `ToBase64`,

`Rot13`,

`Md5`,

`Sha1`,

`Sha256`, `Sha512`,

`Sm3`,

`Hmac`,

`Rc4`,

`XxteaDecrypt`, `XxteaEncrypt`,

`DesDecrypt`, `DesEncrypt`, `TripleDesDecrypt`, `TripleDesEncrypt`,

`AesDecrypt`, `AesEncrypt`,

`Sm4Decrypt`, `Sm4Encrypt`,

## `Padding`

`BitPadding`,

`NoPadding`,

`Pkcs7Padding`,

`ZeroPadding`,

## `Mode`

`Ecb`,

`Cbc`,

`Cfb`,

`Ofb`,

`Ctr`,

`Gcm`,

## 使用方式

参考 examples 目录中[编解码](examples/encoding.rs)、[哈希](examples/hashing.rs)、[填充/去填充](examples/padding.rs)、[加解密](examples/encryption.rs)相关的代码

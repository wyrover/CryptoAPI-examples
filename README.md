# CryptoAPI-examples
microsoft CryptoAPI examples

RSA 加解密可采用 openssl cryptopp CryptoAPI

采用微软自带的 CryptoAPI 写个命令行更简单一些

CryptoAPI 支持的加密算法

- CALG_MD2
- CALG_MD4
- CALG_MD5
- CALG_SHA
- CALG_SHA_1
- CALG_SHA_256
- CALG_SHA_384
- CALG_SHA_512
- CALG_RC2    
- CALG_RC4
- CALG_DES
- CALG_3DES_112
- CALG_3DES
- CALG_AES_128
- CALG_AES_192
- CALG_AES_256



## 加密脚本文件的流程

1. 生成一个固定 AES 密钥，用于加密脚本
2. 用 AES 密钥加密脚本 A.txt 生成 A.dat，用来保护脚本不明文出现
3. 生成 RSA 密钥对
4. 使用 RSA 私钥对 A.dat 进行签名，将签名信息放在 A.dat 的末端（生成 A.enc.dat)
5. 在客户端使用 RSA 公钥对 A.enc.dat 的前置数据（总大小-签名信息大小）进行 hash 签名验证
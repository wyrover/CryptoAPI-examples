# CryptoAPI-examples
microsoft CryptoAPI examples

RSA 加解密可采用 openssl cryptopp CryptoAPI

采用微软自带的 CryptoAPI 写个命令行更简单一些

## 加密脚本文件的流程

1. 生成一个固定 AES 密钥，用于加密脚本
2. 用 AES 密钥加密脚本 A.txt 生成 A.dat，用来保护脚本不明文出现
3. 生成 RSA 密钥对
4. 使用 RSA 私钥对 A.dat 进行签名，将签名信息放在 A.dat 的末端（生成 A.enc.dat)
5. 在客户端使用 RSA 公钥对 A.enc.dat 的前置数据（总大小-签名信息大小）进行 hash 签名验证
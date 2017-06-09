# CryptoAPI-examples
microsoft CryptoAPI examples

RSA 加解密可采用 openssl cryptopp CryptoAPI

采用微软自带的 CryptoAPI 写个命令行更简单一些

CryptoAPI 支持的加密算法

``` cpp
CALG_3DES = 0x00006603,//	Triple DES encryption algorithm.
CALG_3DES_112 = 0x00006609,//	Two-key triple DES encryption with effective key length equal to 112 bits.
CALG_AES = 0x00006611,//	Advanced Encryption Standard (AES). This algorithm is supported by the Microsoft AES Cryptographic Provider.
CALG_AES_128 = 0x0000660e,//	128 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
CALG_AES_192 = 0x0000660f,//	192 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
CALG_AES_256 = 0x00006610,//	256 bit AES. This algorithm is supported by the Microsoft AES Cryptographic Provider.
CALG_AGREEDKEY_ANY = 0x0000aa03,//	Temporary algorithm identifier for handles of Diffie-Hellman–agreed keys.
CALG_CYLINK_MEK = 0x0000660c,//	An algorithm to create a 40-bit DES key that has parity bits and zeroed key bits to make its key length 64 bits. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_DES = 0x00006601,//	DES encryption algorithm.
CALG_DESX = 0x00006604,//	DESX encryption algorithm.
CALG_DH_EPHEM = 0x0000aa02,//	Diffie-Hellman ephemeral key exchange algorithm.
CALG_DH_SF = 0x0000aa01,//	Diffie-Hellman store and forward key exchange algorithm.
CALG_DSS_SIGN = 0x00002200,//	DSA public key signature algorithm.
CALG_ECDH = 0x0000aa05,//	Elliptic curve Diffie-Hellman key exchange algorithm.	Note  This algorithm is supported only through Cryptography API: Next Generation.	Windows Server 2003 and Windows XP:  This algorithm is not supported.
CALG_ECDSA = 0x00002203,//	Elliptic curve digital signature algorithm.	Note  This algorithm is supported only through Cryptography API: Next Generation.	Windows Server 2003 and Windows XP:  This algorithm is not supported.
CALG_ECMQV = 0x0000a001,//	Elliptic curve Menezes, Qu, and Vanstone (MQV) key exchange algorithm. This algorithm is not supported.
CALG_HASH_REPLACE_OWF = 0x0000800b,//	One way function hashing algorithm.
CALG_HUGHES_MD5 = 0x0000a003,//	Hughes MD5 hashing algorithm.
CALG_HMAC = 0x00008009,//	HMAC keyed hash algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_KEA_KEYX = 0x0000aa04,//	KEA key exchange algorithm (FORTEZZA). This algorithm is not supported.
CALG_MAC = 0x00008005,//	MAC keyed hash algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_MD2 = 0x00008001,//	MD2 hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_MD4 = 0x00008002,//	MD4 hashing algorithm.
CALG_MD5 = 0x00008003,//	MD5 hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_NO_SIGN = 0x00002000,//	No signature algorithm.
CALG_OID_INFO_CNG_ONLY = 0xffffffff,//	The algorithm is only implemented in CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions.
CALG_OID_INFO_PARAMETERS = 0xfffffffe,//	The algorithm is defined in the encoded parameters. The algorithm is only supported by using CNG. The macro, IS_SPECIAL_OID_INFO_ALGID, can be used to determine whether a cryptography algorithm is only supported by using the CNG functions.
CALG_PCT1_MASTER = 0x00004c04,//	Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
CALG_RC2 = 0x00006602,//	RC2 block encryption algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_RC4 = 0x00006801,//	RC4 stream encryption algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_RC5 = 0x0000660d,//	RC5 block encryption algorithm.
CALG_RSA_KEYX = 0x0000a400,//	RSA public key exchange algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_RSA_SIGN = 0x00002400,//	RSA public key signature algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_SCHANNEL_ENC_KEY = 0x00004c07,//	Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
CALG_SCHANNEL_MAC_KEY = 0x00004c03,//	Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
CALG_SCHANNEL_MASTER_HASH = 0x00004c02,//	Used by the Schannel.dll operations system. This ALG_ID should not be used by applications.
CALG_SEAL = 0x00006802,//	SEAL encryption algorithm. This algorithm is not supported.
CALG_SHA = 0x00008004,//	SHA hashing algorithm. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_SHA1 = 0x00008004,//	Same as CALG_SHA. This algorithm is supported by the Microsoft Base Cryptographic Provider.
CALG_SHA_256 = 0x0000800c,//	256 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider..	Windows XP with SP3:  This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype).	Windows XP with SP2, Windows XP with SP1, and Windows XP:  This algorithm is not supported.
CALG_SHA_384 = 0x0000800d,//	384 bit SHA hashing algorithm. This algorithm is supported by Microsoft Enhanced RSA and AES Cryptographic Provider.	Windows XP with SP3:  This algorithm is supported by the Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype).	Windows XP with SP2, Windows XP with SP1, and Windows XP:  This algorithm is not supported.
```

## CryptoAPI 简介

CryptoAPI 为开发者提供在 Windows 下使用 PKI 的 API。CryptoAPI 包括编码、解码、加密、解密、Hash、数字证书管理和证书存储等功能。

## 常用 API

### CSP 相关

一个 CSP 是实现加密操作的独立模块，要实现加密，至少需要一个 CSP。每个 CSP 对 CryptAPI 的实现是不同的，使用的算法不同，有些包含了对硬件的支持。

- CryptAcquireContext 获得指定 CSP 的密钥容器的句柄
- CryptReleaseContext 释放由 CryptAcquireContext 得到的句柄


``` cpp
BOOL OpenCryptContext(HCRYPTPROV* provider)
{
    DWORD dwVersion = GetVersion();
    DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));
    LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;

    if (dwMajor <= 5)
        pszProvider = MS_ENH_RSA_AES_PROV_XP;

    if (!CryptAcquireContext(provider, 0, pszProvider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!CryptAcquireContext(provider, 0, pszProvider, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            return FALSE;
        }
    }

    return TRUE;
}
```



### 密钥相关

用来创建和销毁密钥，也可以使用一个已有的密钥

- CryptDeriveKey 从一个密码中派生一个密钥
- CryptDestoryKey 销毁密钥
- CryptDuplicateKey 制作一个密钥和密钥状态的精确复制
- CryptGenKey 创建一个随机密钥
- CryptImportKey 把一个密钥 BLOB 传送到 CSP 中

### 加解密相关

用来加解密数据，需要指定一个密钥，这个密钥可以是由 CryptGenKey 、 CryptDuplicateKey 、 CryptImportKey 产生。

- CryptEncrypt 使用指定加密密钥来加密一段信息
- CryptDecrypt 使用指定加密密钥来解密一段密文

### 哈希和数字签名函数

用来计算 Hash、创建和校验数字签名。


- CryptCreateHash 创建一个空哈希对象
- CryptDestoryHash 销毁一个哈希对象
- CryptDuplicateHash 复制一个哈希对象
- CryptGetHashParam 得到一个哈希对象参数
- CryptHashData 对一块数据进行哈希，把它加到指定的哈希对象中
- CryptHashSessionKey 对一个会话密钥进行哈希，把它加到指定的哈希对象中
- CryptSetHashParam 设置一个哈希对象的参数
- CryptSignHash 对一个哈希对象进行签名
- CryptVerifySignature 校验一个数字签名


## 加密脚本文件的流程

1. 生成一个固定 AES 密钥，用于加密脚本
2. 用 AES 密钥加密脚本 A.txt 生成 A.dat，用来保护脚本不明文出现
3. 生成 RSA 密钥对
4. 使用 RSA 私钥对 A.dat 进行签名，将签名信息放在 A.dat 的末端（生成 A.enc.dat)
5. 在客户端使用 RSA 公钥对 A.enc.dat 的前置数据（总大小-签名信息大小）进行 hash 签名验证



## links

- [循环读取文件块加解密](https://github.com/balalala/Courseware_Office/blob/71d60e0b2eb718c7bd4de87e387757c4ae04baeb/win2.4/PKI/V2.4-20121023/Samples/CryptoAPI/VC/EncryptDecryptFile/EncryptFile.cpp)
- [读写证书](https://github.com/ermilindwalekar/Windows_Classic_Samples/blob/cded84bed49cb8ef2095e6470ac83ee3264c4113/Samples/Win7Samples/netds/peertopeer/DRT/CAPIWrappers.cpp)
- [数字证书原理，公钥私钥加密 - 读过最浅显易懂的密钥 topic](http://www.jianshu.com/p/671ebeddcf60)
- [使用 C++ 实现数字证书中心演示系统](http://www.jianshu.com/p/3661d70138da)
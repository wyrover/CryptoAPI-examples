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


## 加密脚本文件的流程

1. 生成一个固定 AES 密钥，用于加密脚本
2. 用 AES 密钥加密脚本 A.txt 生成 A.dat，用来保护脚本不明文出现
3. 生成 RSA 密钥对
4. 使用 RSA 私钥对 A.dat 进行签名，将签名信息放在 A.dat 的末端（生成 A.enc.dat)
5. 在客户端使用 RSA 公钥对 A.enc.dat 的前置数据（总大小-签名信息大小）进行 hash 签名验证
#ifndef __CACTUS_CRYPTO_API_RSA_H__
#define __CACTUS_CRYPTO_API_RSA_H__

#include <Windows.h>
#include <Wincrypt.h> 
#include <stdbool.h>
#include <string>

//bool CryptoInit(HCRYPTKEY *key, HCRYPTPROV *provider, unsigned char **publicKey, unsigned char **privateKey);
//bool Encrypt(HCRYPTKEY key, char **cipherText, unsigned long *cLen, unsigned char *plainText, unsigned long pLen);
//bool Decrypt(HCRYPTKEY key, unsigned char **plainText, char *cipherText, unsigned long cLen);
//void CryptoUninit(HCRYPTKEY key, HCRYPTPROV provider);

#define RSA2048BIT_KEY 0x8000000
void gen_rsa_keys(DWORD keylen);

// sign a hash of input using private key
BOOL sign_file2(std::string filename);

BOOL verify_file2(std::string filename);

DWORD rsa_Encrypt(LPBYTE PublicKey, DWORD SizeKey, LPBYTE InData, DWORD SizeInData, LPBYTE *OutData);
DWORD rsa_Decrypt(LPBYTE PrivateKey, DWORD SizeKey, LPBYTE Data, LPDWORD SizeData);

void rsa_encrypt_test();
void rsa_encrypt_test2();



#endif // __CACTUS_CRYPTO_API_RSA_H__

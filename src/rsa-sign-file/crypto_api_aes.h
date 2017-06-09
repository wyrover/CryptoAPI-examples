#ifndef __CACTUS_CRYPTO_API_AES_H__
#define __CACTUS_CRYPTO_API_AES_H__

#include <windows.h>
#include <wincrypt.h>


class CryptAES
{
public:

    struct AESKEY128 {
        BLOBHEADER Header;
        DWORD dwKeyLen;
        BYTE pKey[16];

        AESKEY128()
        {
            this->Header.bType = PLAINTEXTKEYBLOB;
            this->Header.bVersion = CUR_BLOB_VERSION;
            this->Header.reserved = 0;
            this->Header.aiKeyAlg = CALG_AES_128;
            this->dwKeyLen = 16;
        }
    };

    CryptAES(BYTE *pKey, BYTE *pIV);
    ~CryptAES();    

    int Encrypt(BYTE *pData, DWORD *pdwDataSize, DWORD dwBufferSize, BOOL bFinal);
    int Decrypt(BYTE *pData, DWORD *pdwDataSize, BOOL bFinal);

private:
    HCRYPTPROV hProv;
    HCRYPTKEY  hKey;
};


// From:
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379931(v=vs.85).aspx
typedef struct _plaintext_blob_t {
	BLOBHEADER hdr;
	DWORD cbKeySize;
	BYTE rgbKeyData[1];
} plaintext_blob_t;

void gen_aes256_key_iv();


DWORD aes_Encrypt(LPBYTE key, DWORD SizeKey, LPBYTE iv, LPBYTE InData, DWORD SizeInData, LPBYTE *OutData);
DWORD aes_Decrypt(LPBYTE key, DWORD SizeKey, LPBYTE iv, LPBYTE Data, LPDWORD SizeData);

bool aes_encrypt_file(const char* base64_key, const char* base64_iv, const char* filename, const char* out_filename);
bool aes_decrypt_file(const char* base64_key, const char* base64_iv, const char* filename, const char* out_filename);


void aes_encrypt_test();

#endif // __CACTUS_CRYPTO_API_AES_H__

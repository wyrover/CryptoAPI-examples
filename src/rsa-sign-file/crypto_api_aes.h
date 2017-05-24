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

#endif // __CACTUS_CRYPTO_API_AES_H__

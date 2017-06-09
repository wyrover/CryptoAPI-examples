

#include "crypto_api_aes.h"
#include "common.h"
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")

CryptAES::CryptAES(BYTE *pKey, BYTE *pIV)
{
    this->hProv = NULL;
    this->hKey = NULL;

    if (CryptAcquireContext(&this->hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        AESKEY128 AESBlob;

        for (int i = 0; i < 16; i++)
            AESBlob.pKey[i] = pKey[i];

        CryptImportKey(this->hProv, reinterpret_cast<BYTE*>(&AESBlob), sizeof(AESBlob), NULL, 0, &this->hKey);

        if (this->hKey) {
            DWORD dwMode = CRYPT_MODE_CBC,
                  dwPadding = PKCS5_PADDING;
            CryptSetKeyParam(this->hKey, KP_IV, pIV, 0);
            CryptSetKeyParam(this->hKey, KP_MODE, reinterpret_cast<BYTE*>(&dwMode), 0);
            CryptSetKeyParam(this->hKey, KP_PADDING, reinterpret_cast<BYTE*>(&dwPadding), 0);
        }
    }
}

CryptAES::~CryptAES()
{
    if (this->hKey != NULL)
        CryptDestroyKey(this->hKey);

    if (this->hProv != NULL)
        CryptReleaseContext(this->hProv, 0);
}

int CryptAES::Encrypt(BYTE *pData, DWORD *pdwDataSize, DWORD dwBufferSize, BOOL bFinal)
{
    if (this->hKey == NULL)
        return -1;

    CryptEncrypt(this->hKey, 0, bFinal, 0, pData, pdwDataSize, dwBufferSize);
    return GetLastError();
}

int CryptAES::Decrypt(BYTE *pData, DWORD *pdwDataSize, BOOL bFinal)
{
    if (this->hKey == NULL)
        return -1;

    CryptDecrypt(this->hKey, 0, bFinal, 0, pData, pdwDataSize);
    return GetLastError();
}



/////////////////////////////////////////////////////////////////////////////////

// 错误报告
//void CancelByError(const wchar_t* str)
//{
//  _tprintf(L"\nFAULT:\n");
//  _tprintf(L"An error occurred in running the program. \n");
//  _tprintf(L"%s", str);
//  _tprintf(L"Error number %x. \n", GetLastError());
//  _tprintf(L"Program terminating. \n");
//  pause();
//  exit(1);
//}
//
//// 输出文件
//void writeFile(const char* sFileName, BYTE* data, DWORD nSize)
//{
//  FILE* fp = fopen(sFileName, "wb");
//  if (fp == NULL)
//  {
//      printf("Can not open output file '%s'! \n", sFileName);
//      return;
//  }
//
//  if (fwrite(data, 1, nSize, fp) != nSize)
//  {
//      fclose(fp);
//      printf("Write to file '%s' failed! \n", sFileName);
//      return;
//  }
//
//  fclose(fp);
//  printf("Write %d bytes to file '%s'! \n", nSize, sFileName);
//}
//
//// 读取文件 (data = NULL for get file size ONLY)
//void readFile(const char* sFileName, BYTE* data, DWORD & nSize)
//{
//  nSize = 0;
//
//  FILE* fp = fopen(sFileName, "rb");
//  if (fp == NULL)
//  {
//      printf("Can not open input file '%s'! \n", sFileName);
//      return;
//  }
//
//  fseek(fp, 0, SEEK_END);
//  nSize = ftell(fp);
//  fseek(fp, 0, SEEK_SET);
//
//  if (data != NULL)
//  {
//      if (fread(data, 1, nSize, fp) != nSize)
//      {
//          fclose(fp);
//          printf("Read from file '%s' failed! \n", sFileName);
//          return;
//      }
//      printf("Read %d bytes from file '%s'! \n", nSize, sFileName);
//  }
//  fclose(fp);
//}
//
//void prepareData(BYTE* inData, DWORD inSize, LPCSTR inFileName, BYTE* &outData, DWORD& outSize)
//{
//  if (inData == NULL && inFileName != NULL)
//  {
//      // Read from file
//      readFile(inFileName, NULL, outSize);
//      if (outSize != 0)
//      {
//          outData = (BYTE*) new char[outSize];
//          if (outData == NULL)    CancelByError(L"Not enough memory. \n");
//          readFile(inFileName, outData, outSize);
//      }
//  }
//  else
//  {
//      // Read from buffer
//      outSize = inSize;
//      outData = (BYTE*) new char[outSize];
//      if (outData == NULL)    CancelByError(L"Not enough memory. \n");
//      memcpy(outData, inData, outSize);
//  }
//}
//
//
//void AESEncrypt(BYTE* key, BYTE* iv, BYTE* inData, int inSize, LPCSTR inFileName = NULL, LPCSTR outFileName = NULL)
//{
//  // 准备数据
//  CRYPT_DATA_BLOB orgBlob;
//  memset(&orgBlob, 0, sizeof(orgBlob));
//  prepareData(inData, inSize, inFileName, orgBlob.pbData, orgBlob.cbData);
//
//  /*
//  BOOL WINAPI CryptAcquireContext(
//  __out         HCRYPTPROV* phProv,
//  __in          LPCTSTR pszContainer,
//  __in          LPCTSTR pszProvider,
//  __in          DWORD dwProvType,
//  __in          DWORD dwFlags
//  );
//  */
//
//  HCRYPTPROV hProv = NULL;
//  if (!CryptAcquireContext(
//      &hProv,                // 返回的句柄
//      NULL,                // CSP 容器名称
//      NULL,                // CSP 提供者名称
//      PROV_RSA_AES,        // CSP 提供者类型
//      0))            // 附加参数：
//  {
//      delete[] orgBlob.pbData;
//      CancelByError(L"Get provider context failed!\n");
//  }
//
//  // 创建 Key
//  struct keyBlob
//  {
//      BLOBHEADER hdr;
//      DWORD cbKeySize;
//      BYTE rgbKeyData[16];                // FOR AES-256 = 32
//  } keyBlob;
//
//  keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
//  keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
//  keyBlob.hdr.reserved = 0;
//  keyBlob.hdr.aiKeyAlg = CALG_AES_128;    // FOR AES-256 = CALG_AES_256
//  keyBlob.cbKeySize = 16;                    // FOR AES-256 = 32
//  CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);
//
//  /*
//  BOOL WINAPI CryptImportKey(
//  __in          HCRYPTPROV hProv,
//  __in          BYTE* pbData,
//  __in          DWORD dwDataLen,
//  __in          HCRYPTKEY hPubKey,
//  __in          DWORD dwFlags,
//  __out         HCRYPTKEY* phKey
//  );
//  */
//
//  HCRYPTKEY hKey = NULL;
//  if (!CryptImportKey(hProv, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, CRYPT_EXPORTABLE, &hKey))
//  {
//      delete[] orgBlob.pbData;
//      CryptReleaseContext(hProv, 0);
//      CancelByError(L"Create key failed!\n");
//  }
//
//  /*
//  BOOL WINAPI CryptSetKeyParam(
//  __in          HCRYPTKEY hKey,
//  __in          DWORD dwParam,
//  __in          const BYTE* pbData,
//  __in          DWORD dwFlags
//  );
//  */
//
//  // 设置初始向量
//  if (iv == NULL)
//  {
//      if (!CryptSetKeyParam(hKey, KP_IV, key, 0))
//      {
//          delete[] orgBlob.pbData;
//          CryptDestroyKey(hKey);
//          CryptReleaseContext(hProv, 0);
//          CancelByError(L"Set key's IV parameter failed!\n");
//      }
//  }
//  else
//  {
//      if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
//      {
//          delete[] orgBlob.pbData;
//          CryptDestroyKey(hKey);
//          CryptReleaseContext(hProv, 0);
//          CancelByError(L"Set key's IV parameter failed!\n");
//      }
//  }
//
//  /*
//  BOOL WINAPI CryptEncrypt(
//  __in          HCRYPTKEY hKey,
//  __in          HCRYPTHASH hHash,
//  __in          BOOL Final,
//  __in          DWORD dwFlags,
//  __in_out      BYTE* pbData,
//  __in_out      DWORD* pdwDataLen,
//  __in          DWORD dwBufLen
//  );
//  */
//
//  // 加密处理
//  CRYPT_DATA_BLOB encBlob;
//  memset(&encBlob, 0, sizeof(encBlob));
//  encBlob.cbData = orgBlob.cbData;
//  encBlob.pbData = (BYTE*) new char[(orgBlob.cbData / 16 + 1) * 16];
//  memcpy(encBlob.pbData, orgBlob.pbData, orgBlob.cbData);
//  if (!CryptEncrypt(hKey, NULL, TRUE, 0, encBlob.pbData, &encBlob.cbData, (orgBlob.cbData / 16 + 1) * 16))
//  {
//      delete[] orgBlob.pbData;
//      delete[] encBlob.pbData;
//      CryptDestroyKey(hKey);
//      CryptReleaseContext(hProv, 0);
//      CancelByError(L"AES encrypt failed!\n");
//  }
//
//  showData(encBlob.pbData, encBlob.cbData);
//  if (outFileName != NULL)
//  {
//      writeFile(outFileName, encBlob.pbData, encBlob.cbData);
//  }
//
//  // 释放获取的对象
//  delete[] orgBlob.pbData;
//  delete[] encBlob.pbData;
//
//  if (hKey != NULL)
//  {
//      CryptDestroyKey(hKey);
//      hKey = NULL;
//  }
//
//  if (hProv != NULL)
//  {
//      CryptReleaseContext(hProv, 0);
//      hProv = NULL;
//  }
//}




DWORD aes_Encrypt(LPBYTE key, DWORD SizeKey, LPBYTE iv, LPBYTE InData, DWORD SizeInData, LPBYTE *OutData)
{
    HCRYPTPROV provider = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD SizeData = SizeInData;
    DWORD SizeBuffer = 0;
    DWORD Result = -1;

    do {
        if (!OpenCryptContext(&provider)) {
            xstrerror("CryptAcquireContext()");
            break;
        }

        // 创建 Key
        struct keyBlob {
            BLOBHEADER hdr;
            DWORD cbKeySize;
            BYTE rgbKeyData[32];                // FOR AES-256 = 32
        } keyBlob;
        keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
        keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        keyBlob.hdr.reserved = 0;
        keyBlob.hdr.aiKeyAlg = CALG_AES_256;    // FOR AES-256 = CALG_AES_256
        keyBlob.cbKeySize = 32;                    // FOR AES-256 = 32
        CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);

        if (!CryptImportKey(provider, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, 0, &hKey)) {
            break;
        }

        DWORD dwMode = CRYPT_MODE_CBC, dwPadding = PKCS5_PADDING;

        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&dwMode), 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_PADDING, reinterpret_cast<BYTE*>(&dwPadding), 0)) {
            break;
        }

        DWORD block_size = GetCipherBlockSize(hKey);
        DWORD data_len = SizeInData;
        SizeBuffer = data_len + block_size;
        *OutData = (LPBYTE)xmalloc(SizeBuffer);

        if (*OutData == NULL)
            break;

        memcpy(*OutData, InData, SizeInData);

        if (!CryptEncrypt(hKey, NULL, TRUE, 0, *OutData, &SizeData, SizeBuffer)) {
            xstrerror("CryptEncrypt()");
            break;
        }

        Result = SizeData;
    } while (0);

    if (hKey != NULL) {
        CryptDestroyKey(hKey);
    }

    if (provider != NULL)   {
        CryptReleaseContext(provider, 0);
    }

    if (OutData != NULL && !Result)
        xfree(*OutData);

    return Result;
}

DWORD aes_Decrypt(LPBYTE key, DWORD SizeKey, LPBYTE iv, LPBYTE Data, LPDWORD SizeData)
{
    HCRYPTPROV provider = NULL;
    HCRYPTKEY hKey = NULL;
    DWORD Result = -1;

    do {
        if (!OpenCryptContext(&provider)) {
            xstrerror("CryptAcquireContext()");
            break;
        }

        // 创建 Key
        struct keyBlob {
            BLOBHEADER hdr;
            DWORD cbKeySize;
            BYTE rgbKeyData[32];                // FOR AES-256 = 32
        } keyBlob;
        keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
        keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        keyBlob.hdr.reserved = 0;
        keyBlob.hdr.aiKeyAlg = CALG_AES_256;    // FOR AES-256 = CALG_AES_256
        keyBlob.cbKeySize = 32;                    // FOR AES-256 = 32
        CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);

        if (!CryptImportKey(provider, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, 0, &hKey)) {
            break;
        }

        DWORD dwMode = CRYPT_MODE_CBC, dwPadding = PKCS5_PADDING;

        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv, 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&dwMode), 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_PADDING, reinterpret_cast<BYTE*>(&dwPadding), 0)) {
            break;
        }

        if (!CryptDecrypt(hKey, NULL, TRUE, 0, Data, SizeData)) {
            xstrerror("CryptDecrypt()");
            break;
        }

        Result = *SizeData; // Set return value to the decrypted data size
    } while (0);

    if (hKey != NULL) {
        CryptDestroyKey(hKey);
    }

    if (provider != NULL)   {
        CryptReleaseContext(provider, 0);
    }

    return Result;
}

void aes_encrypt_test()
{
    BYTE test_aes256_key[] = {
        0x18, 0xfc, 0x7c, 0xc2, 0x17, 0xc9, 0x71, 0x98,
        0x21, 0xb0, 0x80, 0xc8, 0x6d, 0x73, 0x5d, 0x7e,
        0x20, 0x02, 0xc8, 0x75, 0x0e, 0xa5, 0x55, 0x49,
        0x4c, 0xd1, 0xdc, 0x13, 0x23, 0xa6, 0xfe, 0x58
    };
    BYTE test_aes256_iv[] = {
        0x88, 0x8c, 0xe7, 0xe5, 0x37, 0xdc, 0x2b, 0xa4,
        0x4b, 0xc5, 0xd2, 0x41, 0xbc, 0x60, 0x5f, 0xa9
    };
    char inData[] = "hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!hello world!";
    LPBYTE OutData = NULL;
    DWORD OutData_Len = aes_Encrypt(test_aes256_key, sizeof(test_aes256_key), test_aes256_iv, (LPBYTE)inData, strlen(inData), &OutData);
    printf("AES encrypt data:\n");
    print_bin2c(OutData, OutData_Len);
    printf("\n\n");
    DWORD Decrypt_Len = aes_Decrypt(test_aes256_key, sizeof(test_aes256_key), test_aes256_iv, OutData, &OutData_Len);
    OutData[Decrypt_Len] = '\0';
    printf("AES decrypt data:\n");
    printf("%s", OutData);
    printf("\n\n");

    if (OutData) {
        xfree(OutData);
        OutData = NULL;
    }
}

bool aes_encrypt_file(const char* base64_key, const char* base64_iv, const char* filename, const char* out_filename)
{
    bool ret = false;
    std::vector<BYTE> key;
    std::vector<BYTE> iv;
    LPBYTE OutData = NULL;
    DWORD OutData_Len;

    do {
        if (!get_key_iv_from_base64(base64_key, base64_iv, key, iv)) {
            break;
        }

        std::vector<byte> inData;

        if (!get_file_contents(filename, inData)) {
            break;
        }

        OutData_Len = aes_Encrypt(&key[0], key.size(), &iv[0], (LPBYTE)&inData[0], inData.size(), &OutData);

        if (!OutData_Len)
            break;

        put_file_content(out_filename, OutData, OutData_Len);
        ret = true;
    } while (0);

    if (OutData) {
        xfree(OutData);
        OutData = NULL;
    }

    return ret;
}

bool aes_decrypt_file(const char* base64_key, const char* base64_iv, const char* filename, const char* out_filename)
{
    bool ret = false;
    std::vector<BYTE> key;
    std::vector<BYTE> iv;

    do {
        if (!get_key_iv_from_base64(base64_key, base64_iv, key, iv)) {
            break;
        }

        std::vector<byte> inData;

        if (!get_file_contents(filename, inData)) {
            break;
        }

        DWORD inData_len = inData.size();
        DWORD Decrypt_Len = aes_Decrypt(&key[0], key.size(), &iv[0], (LPBYTE)&inData[0], &inData_len);

        if (!Decrypt_Len)
            break;

        put_file_content(out_filename, &inData[0], Decrypt_Len);
        ret = true;
    } while (0);

    return ret;
}

void gen_aes256_key_iv()
{
    HCRYPTPROV provider = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY newHKey = NULL;
    DWORD ivLen, blockLen = 0;
    BYTE* iv = NULL;
    BYTE* buffer = NULL;
    char* cipherText = NULL;
    unsigned long cLen;
    char* cipherText2 = NULL;
    unsigned long cLen2;
    char* cipherText3 = NULL;
    unsigned long cLen3;
    char* cipherText4 = NULL;
    unsigned long cLen4;

    if (!OpenCryptContext(&provider)) {
        printf("CryptAcquireContext() failed:");
        goto Exit0;
    }

    // 生成随机密钥
    // 还可以从通过给定密码 HASH 后获取 AES 密钥
    if (!CryptGenKey(provider, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        goto Exit0;
    }

    // Get the key size.
    DWORD buffer_size = 0;

    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &buffer_size)) {
        printf("CryptExportKey failed.\n");
        goto Exit0;
    }

    // Export the key.
    buffer = new BYTE[buffer_size];

    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, buffer, &buffer_size)) {
        printf("CryptExportKey2 failed.\n");
        goto Exit0;
    }

    plaintext_blob_t* blob = (plaintext_blob_t*)buffer;
    printf("aes Key:\n");
    printf("\nchar aes256_key[]=\n{");
    print_bin2c(blob->rgbKeyData, blob->cbKeySize);
    printf("};");
    printf("\n\n");

    // base64 编码
    if (!Base64EncodeA(&cipherText, &cLen, blob->rgbKeyData, blob->cbKeySize))  {
        //xfree(encrypted);
        xstrerror("Base64EncodeA()");
        goto Exit0;
    }

    printf("aes base64 Key:\n");
    printf(cipherText);
    printf("\n\n");

    // Hex 编码
    if (!Bin2Hex(&cipherText3, &cLen3, blob->rgbKeyData, blob->cbKeySize)) {
        xstrerror("Bin2Hex()");
        goto Exit0;
    }

    printf("aes hex Key:\n");
    printf(cipherText3);
    printf("\n\n");

    // 从随机密钥获取 IV 长度
    if (!CryptGetKeyParam(hKey, KP_IV, NULL, &ivLen, 0)) {
        goto Exit0;
    }

    iv = new BYTE[ivLen];
    ZeroMemory(iv, ivLen);

    if (!CryptGenRandom(provider, ivLen, iv)) {
        goto Exit0;
    }

    printf("aes IV:\n");
    printf("\nchar aes256_iv[]=\n{");
    print_bin2c(iv, ivLen);
    printf("};");
    printf("\n\n");

    if (!Base64EncodeA(&cipherText2, &cLen2, iv, ivLen))    {
        xstrerror("Base64EncodeA()");
        goto Exit0;
    }

    printf("aes base64 iv:\n");
    printf(cipherText2);
    printf("\n\n");

    // Hex 编码
    if (!Bin2Hex(&cipherText4, &cLen4, iv, ivLen)) {
        xstrerror("Bin2Hex()");
        goto Exit0;
    }

    printf("aes hex iv:\n");
    printf(cipherText4);
    printf("\n\n");
    DWORD LenBlockAES = 0;
    DWORD dwCount = sizeof(DWORD);

    if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&LenBlockAES, &dwCount, 0)) {
        goto Exit0;
    }

    printf("aes block data len: %d\n", LenBlockAES);
Exit0:

    if (cipherText4) {
        xfree(cipherText4);
        cipherText4 = NULL;
    }

    if (cipherText3) {
        xfree(cipherText3);
        cipherText3 = NULL;
    }

    if (cipherText2) {
        xfree(cipherText2);
        cipherText2 = NULL;
    }

    if (cipherText) {
        xfree(cipherText);
        cipherText = NULL;
    }

    if (buffer) {
        delete[] buffer;
        buffer = NULL;
    }

    if (iv) {
        delete[] iv;
        iv = NULL;
    }

    if (hKey) {
        CryptDestroyKey(hKey);
    }

    if (provider) {
        CryptReleaseContext(provider, 0);
    }

    return;
}



#include "crypto_api_aes.h"
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
//	_tprintf(L"\nFAULT:\n");
//	_tprintf(L"An error occurred in running the program. \n");
//	_tprintf(L"%s", str);
//	_tprintf(L"Error number %x. \n", GetLastError());
//	_tprintf(L"Program terminating. \n");
//	pause();
//	exit(1);
//}
//
//// 输出文件
//void writeFile(const char* sFileName, BYTE* data, DWORD nSize)
//{
//	FILE* fp = fopen(sFileName, "wb");
//	if (fp == NULL)
//	{
//		printf("Can not open output file '%s'! \n", sFileName);
//		return;
//	}
//
//	if (fwrite(data, 1, nSize, fp) != nSize)
//	{
//		fclose(fp);
//		printf("Write to file '%s' failed! \n", sFileName);
//		return;
//	}
//
//	fclose(fp);
//	printf("Write %d bytes to file '%s'! \n", nSize, sFileName);
//}
//
//// 读取文件 (data = NULL for get file size ONLY)
//void readFile(const char* sFileName, BYTE* data, DWORD & nSize)
//{
//	nSize = 0;
//
//	FILE* fp = fopen(sFileName, "rb");
//	if (fp == NULL)
//	{
//		printf("Can not open input file '%s'! \n", sFileName);
//		return;
//	}
//
//	fseek(fp, 0, SEEK_END);
//	nSize = ftell(fp);
//	fseek(fp, 0, SEEK_SET);
//
//	if (data != NULL)
//	{
//		if (fread(data, 1, nSize, fp) != nSize)
//		{
//			fclose(fp);
//			printf("Read from file '%s' failed! \n", sFileName);
//			return;
//		}
//		printf("Read %d bytes from file '%s'! \n", nSize, sFileName);
//	}
//	fclose(fp);
//}
//
//void prepareData(BYTE* inData, DWORD inSize, LPCSTR inFileName, BYTE* &outData, DWORD& outSize)
//{
//	if (inData == NULL && inFileName != NULL)
//	{
//		// Read from file
//		readFile(inFileName, NULL, outSize);
//		if (outSize != 0)
//		{
//			outData = (BYTE*) new char[outSize];
//			if (outData == NULL)    CancelByError(L"Not enough memory. \n");
//			readFile(inFileName, outData, outSize);
//		}
//	}
//	else
//	{
//		// Read from buffer
//		outSize = inSize;
//		outData = (BYTE*) new char[outSize];
//		if (outData == NULL)    CancelByError(L"Not enough memory. \n");
//		memcpy(outData, inData, outSize);
//	}
//}
//
//
//void AESEncrypt(BYTE* key, BYTE* iv, BYTE* inData, int inSize, LPCSTR inFileName = NULL, LPCSTR outFileName = NULL)
//{
//	// 准备数据
//	CRYPT_DATA_BLOB orgBlob;
//	memset(&orgBlob, 0, sizeof(orgBlob));
//	prepareData(inData, inSize, inFileName, orgBlob.pbData, orgBlob.cbData);
//
//	/*
//	BOOL WINAPI CryptAcquireContext(
//	__out         HCRYPTPROV* phProv,
//	__in          LPCTSTR pszContainer,
//	__in          LPCTSTR pszProvider,
//	__in          DWORD dwProvType,
//	__in          DWORD dwFlags
//	);
//	*/
//
//	HCRYPTPROV hProv = NULL;
//	if (!CryptAcquireContext(
//		&hProv,                // 返回的句柄
//		NULL,                // CSP 容器名称
//		NULL,                // CSP 提供者名称
//		PROV_RSA_AES,        // CSP 提供者类型
//		0))            // 附加参数：
//	{
//		delete[] orgBlob.pbData;
//		CancelByError(L"Get provider context failed!\n");
//	}
//
//	// 创建 Key
//	struct keyBlob
//	{
//		BLOBHEADER hdr;
//		DWORD cbKeySize;
//		BYTE rgbKeyData[16];                // FOR AES-256 = 32
//	} keyBlob;
//
//	keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
//	keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
//	keyBlob.hdr.reserved = 0;
//	keyBlob.hdr.aiKeyAlg = CALG_AES_128;    // FOR AES-256 = CALG_AES_256
//	keyBlob.cbKeySize = 16;                    // FOR AES-256 = 32
//	CopyMemory(keyBlob.rgbKeyData, key, keyBlob.cbKeySize);
//
//	/*
//	BOOL WINAPI CryptImportKey(
//	__in          HCRYPTPROV hProv,
//	__in          BYTE* pbData,
//	__in          DWORD dwDataLen,
//	__in          HCRYPTKEY hPubKey,
//	__in          DWORD dwFlags,
//	__out         HCRYPTKEY* phKey
//	);
//	*/
//
//	HCRYPTKEY hKey = NULL;
//	if (!CryptImportKey(hProv, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, CRYPT_EXPORTABLE, &hKey))
//	{
//		delete[] orgBlob.pbData;
//		CryptReleaseContext(hProv, 0);
//		CancelByError(L"Create key failed!\n");
//	}
//
//	/*
//	BOOL WINAPI CryptSetKeyParam(
//	__in          HCRYPTKEY hKey,
//	__in          DWORD dwParam,
//	__in          const BYTE* pbData,
//	__in          DWORD dwFlags
//	);
//	*/
//
//	// 设置初始向量
//	if (iv == NULL)
//	{
//		if (!CryptSetKeyParam(hKey, KP_IV, key, 0))
//		{
//			delete[] orgBlob.pbData;
//			CryptDestroyKey(hKey);
//			CryptReleaseContext(hProv, 0);
//			CancelByError(L"Set key's IV parameter failed!\n");
//		}
//	}
//	else
//	{
//		if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
//		{
//			delete[] orgBlob.pbData;
//			CryptDestroyKey(hKey);
//			CryptReleaseContext(hProv, 0);
//			CancelByError(L"Set key's IV parameter failed!\n");
//		}
//	}
//
//	/*
//	BOOL WINAPI CryptEncrypt(
//	__in          HCRYPTKEY hKey,
//	__in          HCRYPTHASH hHash,
//	__in          BOOL Final,
//	__in          DWORD dwFlags,
//	__in_out      BYTE* pbData,
//	__in_out      DWORD* pdwDataLen,
//	__in          DWORD dwBufLen
//	);
//	*/
//
//	// 加密处理
//	CRYPT_DATA_BLOB encBlob;
//	memset(&encBlob, 0, sizeof(encBlob));
//	encBlob.cbData = orgBlob.cbData;
//	encBlob.pbData = (BYTE*) new char[(orgBlob.cbData / 16 + 1) * 16];
//	memcpy(encBlob.pbData, orgBlob.pbData, orgBlob.cbData);
//	if (!CryptEncrypt(hKey, NULL, TRUE, 0, encBlob.pbData, &encBlob.cbData, (orgBlob.cbData / 16 + 1) * 16))
//	{
//		delete[] orgBlob.pbData;
//		delete[] encBlob.pbData;
//		CryptDestroyKey(hKey);
//		CryptReleaseContext(hProv, 0);
//		CancelByError(L"AES encrypt failed!\n");
//	}
//
//	showData(encBlob.pbData, encBlob.cbData);
//	if (outFileName != NULL)
//	{
//		writeFile(outFileName, encBlob.pbData, encBlob.cbData);
//	}
//
//	// 释放获取的对象
//	delete[] orgBlob.pbData;
//	delete[] encBlob.pbData;
//
//	if (hKey != NULL)
//	{
//		CryptDestroyKey(hKey);
//		hKey = NULL;
//	}
//
//	if (hProv != NULL)
//	{
//		CryptReleaseContext(hProv, 0);
//		hProv = NULL;
//	}
//}
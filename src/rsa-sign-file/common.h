#ifndef __CACTUS_COMMON_H__
#define __CACTUS_COMMON_H__

#include <Windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <string>
#include <vector>



// allocate memory
void* xmalloc(SIZE_T dwSize);

// free memory
void xfree(void* mem);

// display extended windows error
void xstrerror(char* fmt, ...);

void print_bin2c(BYTE* buffer, unsigned int buffer_len);

std::string HexEncode(const void* bytes, size_t size);

BOOL get_file_contents(const char* filename, std::vector<BYTE>& out_buffer);

void put_file_content(const char* filename, const BYTE* data, DWORD data_len);

void put_file_sign_content(const char* filename, const BYTE* data, DWORD data_len);


BOOL get_enc_file_data(const char* filename, std::vector<BYTE>& out_buffer);

BOOL get_enc_file_sign_message(const char* filename, std::vector<BYTE>& out_buffer);

DWORD GetCipherBlockSize(HCRYPTKEY key);

bool Base64EncodeA(char **dest, unsigned long *dlen, const unsigned char *src, unsigned long slen);

bool Base64DecodeA(unsigned char **dest, unsigned long *dlen, const char *src, unsigned long slen);

bool Bin2Hex(char **dest, unsigned long *dlen, const unsigned char *src, unsigned long slen);

bool Hex2Bin(unsigned char **dest, unsigned long *dlen, const char *src, unsigned long slen);

bool get_key_iv_from_base64(const char* key_base64_str, const char* iv_base64_str, std::vector<BYTE>& key, std::vector<BYTE>& iv);

bool get_key_iv_from_hex(const char* key_base64_str, const char* iv_base64_str, std::vector<BYTE>& key, std::vector<BYTE>& iv);

// convert binary signature to hex string
// pointer should be freed after use
PBYTE sig2hex(BYTE* pbSignature, DWORD dwSigLen);

char* Xor(char* szData, DWORD dwKey, int nLength);


// ×Ö½Ú·´Ðò
void reverse(BYTE* data, int nLen);


BOOL OpenCryptContext(HCRYPTPROV* provider);


#endif // __CACTUS_COMMON_H__

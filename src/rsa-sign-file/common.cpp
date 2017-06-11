#include "common.h"
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iomanip>

// allocate memory
void* xmalloc(SIZE_T dwSize) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// free memory
void xfree(void* mem) {
    HeapFree(GetProcessHeap(), 0, mem);
}

// print binary as c array
void print_bin2c(BYTE* buffer, unsigned int buffer_len) {
    int i;

    for (i = 0; i < buffer_len; i++) {
        if ((i & 7) == 0 && i != 0) printf("\n");

        if (i != 0) printf(" ");

        printf("0x%02x", buffer[i]);

        if ((i + 1) != buffer_len) printf(",");
    }
}

std::string HexEncode(const void* bytes, size_t size) {
    static const char kHexChars[] = "0123456789ABCDEF";
    // Each input byte creates two output hex characters.
    std::string ret(size * 2, '\0');

    for (size_t i = 0; i < size; ++i) {
        char b = reinterpret_cast<const char*>(bytes)[i];
        ret[(i * 2)] = kHexChars[(b >> 4) & 0xf];
        ret[(i * 2) + 1] = kHexChars[b & 0xf];
    }

    return ret;
}

BOOL get_file_contents(const char* filename, std::vector<BYTE>& out_buffer) {
    std::ifstream in(filename, std::ios::in | std::ios::binary);

    if (in) {
        in.seekg(0, std::ios::end);
        out_buffer.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read((char*)&out_buffer[0], out_buffer.size());
        in.close();
        return TRUE;
    }

    return FALSE;
}

void put_file_content(const char* filename, const BYTE* data, DWORD data_len) {
    FILE* f = fopen(filename, "wb+");
    fwrite(data, 1, data_len, f);
    fflush(f);
    fclose(f);
}

// display extended windows error
void xstrerror(char* fmt, ...) {
    char*    error = NULL;
    va_list arglist;
    char    buffer[2048];
    DWORD   dwError = GetLastError();
    va_start(arglist, fmt);
    wvnsprintf(buffer, sizeof(buffer) - 1, fmt, arglist);
    va_end(arglist);

    if (FormatMessage(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&error, 0, NULL)) {
        printf("  [ %s : %s\n", buffer, error);
        LocalFree(error);
    } else {
        printf("  [ %s : %i\n", buffer, dwError);
    }
}


DWORD GetCipherBlockSize(HCRYPTKEY key) {
    DWORD block_size_in_bits = 0;
    DWORD param_size = sizeof(block_size_in_bits);
    BOOL ok = CryptGetKeyParam(key, KP_BLOCKLEN,
                               reinterpret_cast<BYTE*>(&block_size_in_bits),
                               &param_size, 0);

    if (!ok)
        return 0;

    return block_size_in_bits / 8;
}


bool Base64EncodeA(char** dest, unsigned long* dlen, const unsigned char* src, unsigned long slen) {
    if (src == NULL)
        return false;

    if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
        return false;

    //*dest = (char *)malloc(*dlen * sizeof(char));
    *dest = (char*)xmalloc(*dlen * sizeof(char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, *dlen * sizeof(char));

    if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen)) {
        //SAFE_FREE(*dest);
        xfree(*dest);
        return false;
    }

    return true;
}


bool Base64DecodeA(unsigned char** dest, unsigned long* dlen, const char* src, unsigned long slen) {
    if (src == NULL)
        return false;

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
        return false;

    //*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
    *dest = (unsigned char*)xmalloc((*dlen + 1) * sizeof(unsigned char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL)) {
        //SAFE_FREE(*dest);
        xfree(*dest);
        return false;
    }

    return true;
}


bool Bin2Hex(char** dest, unsigned long* dlen, const unsigned char* src, unsigned long slen) {
    if (src == NULL)
        return false;

    if (!CryptBinaryToString(src, slen, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, dlen))
        return false;

    *dest = (char*)xmalloc(*dlen * sizeof(char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, *dlen * sizeof(char));

    if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, *dest, dlen)) {
        //SAFE_FREE(*dest);
        xfree(*dest);
        return false;
    }

    return true;
}


bool Hex2Bin(unsigned char** dest, unsigned long* dlen, const char* src, unsigned long slen) {
    if (src == NULL)
        return false;

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_HEXRAW, NULL, dlen, NULL, NULL))
        return false;

    //*dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));
    *dest = (unsigned char*)xmalloc((*dlen + 1) * sizeof(unsigned char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_HEXRAW, *dest, dlen, NULL, NULL)) {
        //SAFE_FREE(*dest);
        xfree(*dest);
        return false;
    }

    return true;
}



bool get_key_iv_from_base64(const char* key_base64_str, const char* iv_base64_str, std::vector<BYTE>& key, std::vector<BYTE>& iv) {
    bool ret = false;
    LPBYTE dest_key = NULL;
    unsigned long dest_key_len;
    LPBYTE dest_iv = NULL;
    unsigned long dest_iv_len;

    do {
        if (!Base64DecodeA(&dest_key, &dest_key_len, key_base64_str, strlen(key_base64_str)))
            break;

        key.resize(dest_key_len);
        memcpy(&key[0], dest_key, dest_key_len);

        if (!Base64DecodeA(&dest_iv, &dest_iv_len, iv_base64_str, strlen(iv_base64_str)))
            break;

        iv.resize(dest_key_len);
        memcpy(&iv[0], dest_key, dest_key_len);
        ret = true;
    } while (0);

    if (dest_key) {
        xfree(dest_key);
        dest_key = NULL;
    }

    if (dest_iv) {
        xfree(dest_iv);
        dest_iv = NULL;
    }

    return ret;
}

bool get_key_iv_from_hex(const char* key_hex_str, const char* iv_hex_str, std::vector<BYTE>& key, std::vector<BYTE>& iv) {
    bool ret = false;
    LPBYTE dest_key = NULL;
    unsigned long dest_key_len;
    LPBYTE dest_iv = NULL;
    unsigned long dest_iv_len;

    do {
        if (!Hex2Bin(&dest_key, &dest_key_len, key_hex_str, strlen(key_hex_str)))
            break;

        key.resize(dest_key_len);
        memcpy(&key[0], dest_key, dest_key_len);

        if (!Hex2Bin(&dest_iv, &dest_iv_len, iv_hex_str, strlen(iv_hex_str)))
            break;

        iv.resize(dest_key_len);
        memcpy(&iv[0], dest_key, dest_key_len);
        ret = true;
    } while (0);

    if (dest_key) {
        xfree(dest_key);
        dest_key = NULL;
    }

    if (dest_iv) {
        xfree(dest_iv);
        dest_iv = NULL;
    }

    return ret;
}

char* Xor(char* szData, DWORD dwKey, int nLength) {
    if (szData == NULL)
        return NULL;

    for (int i = 0; i < nLength; i++)
        szData[i] = szData[i] ^ (char)dwKey;

    return szData;
}

void reverse(BYTE* data, int nLen) {
    for (int ii = 0; ii < nLen / 2; ii++) {
        BYTE c = data[ii];
        data[ii] = data[nLen - ii - 1];
        data[nLen - ii - 1] = c;
    }
}

PBYTE sig2hex(BYTE* pbSignature, DWORD dwSigLen) {
    DWORD len = 0;
    PBYTE hex;
    // determine how much space we need
    CryptBinaryToString(pbSignature, dwSigLen,
                        CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, &len);
    // allocate memory
    hex = (BYTE*)xmalloc(len);
    // get the string
    CryptBinaryToString(pbSignature, dwSigLen,
                        CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, (char*)hex, &len);
    // return it (ensure pointer is freed after being used)
    return hex;
}

void put_file_sign_content(const char* filename, const BYTE* data, DWORD data_len) {
    FILE* f = fopen(filename, "ab+");
    fwrite(data, 1, data_len, f);
    fflush(f);
    fclose(f);
}

BOOL get_enc_file_data(const char* filename, std::vector<BYTE>& out_buffer) {
    std::ifstream in(filename, std::ios::in | std::ios::binary);

    if (in) {
        in.seekg(0, std::ios::end);
        size_t filesize = in.tellg();
        in.seekg(0, std::ios::beg);

        if (filesize > 256) {
            out_buffer.resize(filesize - 256);
            in.read((char*)&out_buffer[0], out_buffer.size());
            in.close();
            return TRUE;
        }
    }

    return FALSE;
}

BOOL get_enc_file_sign_message(const char* filename, std::vector<BYTE>& out_buffer) {
    std::ifstream in(filename, std::ios::in | std::ios::binary);

    if (in) {
        in.seekg(0, std::ios::end);
        size_t filesize = in.tellg();
        in.seekg(0, std::ios::beg);

        if (filesize > 256) {
            in.seekg(filesize - 256, std::ios::beg);
            out_buffer.resize(256);
            in.read((char*)&out_buffer[0], out_buffer.size());
            in.close();
            return TRUE;
        }
    }

    return FALSE;
}

BOOL OpenCryptContext(HCRYPTPROV* provider) {
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

typedef	std::vector<unsigned char> ByteVec;

std::string toHex(const std::vector<unsigned char>& byteVec) {
    std::ostringstream buf;
    for (ByteVec::const_iterator it = byteVec.begin(); it != byteVec.end(); it++)
        buf << std::setfill('0') << std::setw(2) << std::hex <<
            (short)*it;
    return buf.str();
}


bool getOneChar(ByteVec& hexStr, int& c) {
    if (hexStr.empty()) return false;
    int ch = hexStr.back();
    hexStr.pop_back();
    while (ch == ' ' || ch == '\r' || ch == '\t' || ch == '\n') {
        if (hexStr.empty()) return false;
        ch = hexStr.back();
        hexStr.pop_back();
    }
    if (ch >= '0' && ch <= '9')
        c = ch - '0';
    else if (ch >= 'A' && ch <= 'F')
        c = ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
        c = ch - 'a' + 10;
    return true;
}

ByteVec fromHex(const std::string& hexStr) {
    ByteVec retVal, inpVal(hexStr.length(), '\0');
    copy(hexStr.begin(), hexStr.end(), inpVal.begin());
    reverse(inpVal.begin(), inpVal.end());
    int c1, c2;
    while (getOneChar(inpVal, c1) && getOneChar(inpVal, c2)) {
        retVal.push_back((c1 << 4) | c2);
    }
    return retVal;
}


int win32_get_random_bytes(unsigned char *buf, size_t size) {  /* {{{ */

	unsigned int has_contextg = 0;

	BOOL ret;
	size_t i = 0;

	HCRYPTPROV   hCryptProv;
	unsigned int has_crypto_ctx = 0;

	if (has_crypto_ctx == 0) {
		/* CRYPT_VERIFYCONTEXT > only hashing&co-like use, no need to acces prv keys */
		if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_VERIFYCONTEXT)) {
			/* Could mean that the key container does not exist, let try
			again by asking for a new one. If it fails here, it surely means that the user running
			this process does not have the permission(s) to use this container.
			*/
			if (GetLastError() == NTE_BAD_KEYSET) {
				if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET | CRYPT_VERIFYCONTEXT)) {
					has_crypto_ctx = 1;
				}
				else {
					has_crypto_ctx = 0;
				}
			}
		}
		else {
			has_crypto_ctx = 1;
		}
	}


	if (has_crypto_ctx == 0) {
		return FAILURE;
	}

	ret = CryptGenRandom(hCryptProv, size, buf);

	if (ret) {
		return SUCCESS;
	}
	else {
		return FAILURE;
	}
}

int usleep(unsigned int useconds)
{
	HANDLE timer;
	LARGE_INTEGER due;

	due.QuadPart = -(10 * (__int64)useconds);

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &due, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
	return 0;
}


int utf16string_length(LPWSTR s) {
	int i = 0;

	while (s[i]) {
		i++;
	}
	return i;
}

LPSTR utf16string_convert(LPWSTR s) {
	LPSTR r;
	int i = 0;
	r = (LPSTR)malloc((utf16string_length(s) + 1)*sizeof(CHAR));
	if (r != NULL){
		while (s[i]) {
			r[i] = s[i];
			i++;
		}
		r[i] = '\0';
	}
	return r;
}
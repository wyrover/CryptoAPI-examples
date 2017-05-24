#include <iostream>
#include <gflags/gflags.h>
#include <Windows.h>
#include <Wincrypt.h>
#include <Shlwapi.h>
#include <fstream>
#include <string>

using namespace std;

void genkeys(DWORD keylen);
void export_key(DWORD dwType, char out[], int fmt);
void close_key();
void bin2c(FILE* fd, char s[]);
void sign_file(std::string filename);
BOOL verify_file(std::string filename);
BOOL get_file_contents(const char* filename, std::vector<BYTE>& out_buffer);
BOOL get_enc_file_data(const char* filename, std::vector<BYTE>& out_buffer);
BOOL get_enc_file_sign_message(const char* filename, std::vector<BYTE>& out_buffer);
void put_file_content(const char* filename, const BYTE* data, DWORD data_len);
void put_file_sign_content(const char* filename, const BYTE* data, DWORD data_len);
std::string HexEncode(const void* bytes, size_t size);
void gen_aes_key();
void sha512_file(const std::string filename, std::string& data_hash);
void gen_aes_key_iv();
void gen_aes256_key_iv();
void AESEncrypt(const char* inFileName, const char* outFileName);
std::string SHA1HashString(const std::string& str);

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

template <class string_type>
inline typename string_type::value_type* WriteInto(string_type* str,
	size_t length_with_null) {
	str->reserve(length_with_null);
	str->resize(length_with_null - 1);
	return &((*str)[0]);
}

DEFINE_bool(genkey, false, "创建 rsa 密钥对");
DEFINE_int32(keylen, 2048, "rsa 密钥位数");
DEFINE_string(src_filename, "", "待加密文件");
DEFINE_string(enc_filename, "", "待解密文件");
DEFINE_bool(gen_aes_key, false, "创建 AES 密钥");
DEFINE_bool(gen_aes256_key, false, "创建 AES256 密钥");
DEFINE_string(src_sha512_filename, "", "待 sha512 文件");



int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);


    if (FLAGS_genkey) {
        std::cout << "创建 rsa 密钥对" << std::endl;
        genkeys(FLAGS_keylen);
    }

    if (!FLAGS_src_filename.empty()) {
        std::cout << "签名文件" << std::endl;
        sign_file(FLAGS_src_filename);
    }

    if (!FLAGS_enc_filename.empty()) {
        std::cout << "验证签名文件" << std::endl;
        verify_file(FLAGS_enc_filename);
    }

    if (FLAGS_gen_aes_key) {
        std::cout << "创建 AES 密钥" << std::endl;
        gen_aes_key();
    }

    if (FLAGS_gen_aes256_key) {
        std::cout << "创建 AES256 密钥" << std::endl;
        gen_aes256_key_iv();
    }

    if (!FLAGS_src_sha512_filename.empty()) {
        std::cout << "待 sha512 文件" << std::endl;
        std::string sha512;
        sha512_file(FLAGS_src_sha512_filename, sha512);
        std::cout << sha512.c_str() << std::endl;
    }


    //cout << "src_filename =" << FLAGS_src_filename << std::endl;


    AESEncrypt("test1.txt", "test2.txt");

	std::cout << HexEncode(SHA1HashString("hello world!").data(), SHA1HashString("hello world!").length()) << std::endl;

	

    gflags::ShutDownCommandLineFlags();


    //system("pause");
    return 0;
}


HCRYPTPROV hProv = 0;    // crypto API provider
HCRYPTKEY  hKey = 0;    // key object


BYTE* pbBlob = NULL;
DWORD dwBlob = 0;


#define RSA_KEY_LEN 2048

#define RSA_PUBLIC_BIN "rsa_public.bin"
#define RSA_PUBLIC_H "rsa_public.h"

#define RSA_PRIVATE_BIN "rsa_private.bin"
#define RSA_PRIVATE_H "rsa_private.h"

#define RSA_C_ARRAY 0
#define RSA_BINARY  1
#define RSA_SIGN    2
#define RSA_VERIFY  3


// allocate memory
void* xmalloc(SIZE_T dwSize) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// free memory
void xfree(void* mem) {
    HeapFree(GetProcessHeap(), 0, mem);
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


// initialize crypto provider
BOOL open_crypt() {
    BOOL bStatus = FALSE;
    bStatus = CryptAcquireContext(&hProv, NULL, NULL,
                                  PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    return bStatus;
}

void close_crypt() {
    // release provider
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
        hProv = 0;
    }
}


void genkeys(DWORD keylen) {
    if (open_crypt()) {
        if (CryptGenKey(hProv, AT_SIGNATURE,
                        keylen << 16 | CRYPT_EXPORTABLE, &hKey)) {
            // export as C array and binary
            export_key(PUBLICKEYBLOB, RSA_PUBLIC_H, RSA_C_ARRAY);
            export_key(PUBLICKEYBLOB, RSA_PUBLIC_BIN, RSA_BINARY);
            export_key(PRIVATEKEYBLOB, RSA_PRIVATE_H, RSA_C_ARRAY);
            export_key(PRIVATEKEYBLOB, RSA_PRIVATE_BIN, RSA_BINARY);
            close_key();
        } else {
            xstrerror("CryptGenKey(%i)", keylen);
        }

        close_crypt();
    } else {
        xstrerror("CryptAcquireContext()");
    }
}

// export key as C array string
void export_key(DWORD dwType, char out[], int fmt) {
    DWORD dwWritten, i;
    char* type = (dwType == PUBLICKEYBLOB) ? "sign_public" : "sign_private";
    FILE* fd = NULL;
    fd = fopen(out, "wb");

    if (fd != NULL) {
        // obtain lengtth of key blob
        if (CryptExportKey(hKey, 0, dwType, 0, NULL, &dwBlob)) {
            // allocate memory
            if (pbBlob = (PBYTE)xmalloc(dwBlob)) {
                // get blob
                if (CryptExportKey(hKey, 0, dwType, 0, pbBlob, &dwBlob)) {
                    printf("  [ writing %i bytes to %s\n", dwBlob, out);

                    switch (fmt) {
                        case RSA_C_ARRAY:
                            bin2c(fd, type);
                            break;

                        case RSA_BINARY:
                            fwrite(pbBlob, 1, dwBlob, fd);
                            break;
                    }
                }

                xfree(pbBlob);
                pbBlob = NULL;
            }
        } else {
            xstrerror("CryptExportKey()");
        }
    } else {
        xstrerror("fopen(%s)", out);
    }

    if (fd != NULL) {
        fclose(fd);
        fd = NULL;
    }
}

// open key file
BOOL open_key(char* key_file) {
    BOOL   bStatus = FALSE;
    HANDLE hFile;
    DWORD  dwRead;
    // open private key
    hFile = CreateFile(key_file, GENERIC_READ,
                       FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        dwBlob = GetFileSize(hFile, NULL);

        if (dwBlob != 0 && (pbBlob = (PBYTE)xmalloc(dwBlob)) != NULL) {
            // read key
            ReadFile(hFile, pbBlob, dwBlob, &dwRead, NULL);
            printf("  [ read %i bytes from %s\n", dwBlob, key_file);
            // import key into object
            bStatus = CryptImportKey(hProv, pbBlob, dwBlob, 0, 0, &hKey);
        } else {
            xstrerror("HeapAlloc()");
        }

        // close key file
        CloseHandle(hFile);
    } else {
        xstrerror("CreateFile(%s)", key_file);
    }

    return bStatus;
}

void close_key() {
    if (pbBlob != NULL) {
        xfree(pbBlob);
        pbBlob = NULL;
    }
}

// generates SHA-256 hash of input
BOOL open_hash(std::string filename, HCRYPTHASH* hHash) {
    BOOL bStatus = FALSE;

    std::vector<BYTE> input;
    if (get_file_contents(filename.c_str(), input)) {

        // create hash object
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, hHash)) {
            // hash input
            bStatus = CryptHashData(*hHash, &input[0], input.size(), 0);
        }

        put_file_content((filename + ".enc").c_str(), &input[0], input.size());

    }

    return bStatus;
}



// convert binary signature to hex string
// pointer should be freed after use
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

//// convert signature to binary
//// ensure to free pbSignature after use
//void sig2bin(void)
//{
//	DWORD slen = lstrlen(signature);
//	// determine how much space we need
//	CryptStringToBinary(signature, slen,
//		CRYPT_STRING_HEX_ANY, NULL, &dwSigLen, NULL, NULL);
//	// allocate memory
//	pbSignature = xmalloc(dwSigLen);
//	// get the binary
//	CryptStringToBinary(signature, slen,
//		CRYPT_STRING_HEX_ANY, pbSignature, &dwSigLen, NULL, NULL);
//}


// sign a hash of input using private key
void sign_file(std::string filename) {
    char* p;
    HCRYPTHASH hHash = 0;    // hash object
    DWORD dwSigLen = 0;
    BYTE* pbSignature = NULL;

    // initialize crypto API
    if (!open_crypt()) {
        xstrerror("open_crypt()");
        goto Exit0;
    }

    // import our private key
    if (!open_key(RSA_PRIVATE_BIN)) {
        xstrerror("open_key()");
        goto Exit0;
    }

    // hash the input
    if (open_hash(filename, &hHash)) {
        xstrerror("open_hash()");
        goto Exit0;
    }

    // obtain size of signature
    CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
    pbSignature = (BYTE*)xmalloc(dwSigLen);

    // sign the hash to obtain signature
    if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
        p = (char*)sig2hex(pbSignature, dwSigLen);

        if (p) {
            printf("  [ signature is: %i::%s\n", lstrlen(p), p);

            put_file_sign_content((filename + ".enc").c_str(), pbSignature, dwSigLen);
        }

        xfree(pbSignature);
    } else {
        xstrerror("CryptSignHash()");
    }


Exit0:

    if (hHash != 0) {
        CryptDestroyHash(hHash);
        hHash = 0;
    }

    close_key();
    close_crypt();

}




BOOL get_enc_file_data_hash(const char* filename, HCRYPTHASH* hHash) {
    BOOL bStatus = FALSE;
    std::vector<BYTE> enc_file_data;
    if (get_enc_file_data(filename, enc_file_data)) {
        // create hash object
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, hHash)) {
            // hash input
            bStatus = CryptHashData(*hHash, &enc_file_data[0], enc_file_data.size(), 0);
        }
    }

    return bStatus;
}



BOOL verify_file(std::string filename) {
    BOOL bStatus = FALSE;

    HCRYPTHASH hHash = 0;    // hash object

    BYTE* pbSignature = NULL;
    std::vector<BYTE> sign_message;

    if (!open_crypt()) {
        printf("open_crypt()");
        goto Exit0;
    }

    // import public key
    if (!open_key(RSA_PUBLIC_BIN)) {
        printf("open_key()");
        goto Exit0;
    }

    // hash the input
    if (!get_enc_file_data_hash(filename.c_str(), &hHash)) {
        printf("open_hash()");
        goto Exit0;
    }


    // convert signature to binary
    if (get_enc_file_sign_message(filename.c_str(), sign_message)) {
        if (sign_message.size() > 0) {
            // verify signature
            bStatus = CryptVerifySignature(hHash, &sign_message[0],
                                           sign_message.size(), hKey, NULL, 0);
            printf("  [ signature is %s\n",
                   bStatus ? "valid" : "invalid");

        }
    }

Exit0:

    if (hHash != 0) {
        CryptDestroyHash(hHash);
        hHash = 0;
    }

    close_key();
    close_crypt();

    return bStatus;
}




// print binary as c array
void bin2c(FILE* fd, char s[]) {
    int i;
    fprintf(fd, "\nchar %s[]=\n{", s);

    for (i = 0; i < dwBlob; i++) {
        if ((i & 7) == 0 && i != 0) fprintf(fd, "\n");

        if (i != 0) fprintf(fd, " ");

        fprintf(fd, "0x%02x", pbBlob[i]);

        if ((i + 1) != dwBlob) fprintf(fd, ",");
    }

    fprintf(fd, "};");
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

void put_file_content(const char* filename, const BYTE* data, DWORD data_len) {
    FILE* f = fopen(filename, "wb+");
    fwrite(data, 1, data_len, f);
    fflush(f);
    fclose(f);
}


void put_file_sign_content(const char* filename, const BYTE* data, DWORD data_len) {
    FILE* f = fopen(filename, "ab+");
    fwrite(data, 1, data_len, f);
    fflush(f);
    fclose(f);
}

// print binary as c array
void bin2c(FILE* fd, char s[], BYTE* buffer, unsigned int buffer_len) {
    int i;
    fprintf(fd, "\nchar %s[]=\n{", s);

    for (i = 0; i < buffer_len; i++) {
        if ((i & 7) == 0 && i != 0) fprintf(fd, "\n");

        if (i != 0) fprintf(fd, " ");

        fprintf(fd, "0x%02x", buffer[i]);

        if ((i + 1) != buffer_len) fprintf(fd, ",");
    }

    fprintf(fd, "};");
}

void BinaryDataToHexString(const BYTE *hash, DWORD &hashSize, LPWSTR hexString)
{
	WCHAR *p = hexString;
	for (DWORD i = 0; i < hashSize; ++i) {
		wsprintfW(p, L"%.2x", hash[i]);
		p += 2;
	}
}

// From:
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa379931(v=vs.85).aspx
typedef struct _plaintext_blob_t {
    BLOBHEADER hdr;
    DWORD cbKeySize;
    BYTE rgbKeyData[1];
} plaintext_blob_t;

void gen_aes_key() {

    BOOL success;
    HCRYPTPROV provider;
    success = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES, 0);
    // Ask for a new keyset if this one doesn't exist.
    if (!success && GetLastError() == NTE_BAD_KEYSET) {
        success = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES,
                                      CRYPT_NEWKEYSET);
    }
    //ASSERT_TRUE(success) << "CryptAcquireContext failed: " << GetLastError();

    HCRYPTKEY key;
    success = CryptGenKey(provider, CALG_AES_256, CRYPT_EXPORTABLE, &key);
    //ASSERT_TRUE(success) << "CryptGenKey failed: " << GetLastError();

    // Get the key size.
    DWORD buffer_size = 0;
    success = CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, NULL, &buffer_size);
    //ASSERT_TRUE(success) << "CryptExportKey 1 failed: " << GetLastError();

    // Export the key.
    BYTE* buffer = new BYTE[buffer_size];
    success = CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, buffer, &buffer_size);
    //ASSERT_TRUE(success) << "CryptExportKey 2 failed: " << GetLastError();

    plaintext_blob_t* blob = (plaintext_blob_t*)buffer;
    //ASSERT_EQ(buffer_size - offsetof(plaintext_blob_t, rgbKeyData), blob->cbKeySize);

    // Check that the rest of it is initialized.  Copy the buffer and compare it
    // against itself to trigger the uninit checks.
    BYTE* key_copy = new BYTE[blob->cbKeySize];
    memcpy(key_copy, blob->rgbKeyData, blob->cbKeySize);
    //ASSERT_EQ(0, memcmp(blob->rgbKeyData, key_copy, blob->cbKeySize));




    FILE* fd = NULL;
    fd = fopen("aes_key.key", "wb");
    if (fd != NULL) {
        bin2c(fd, "aes_key", key_copy, blob->cbKeySize);
        fclose(fd);
        fd = NULL;
    }

    FILE* fd2 = NULL;
    fd2 = fopen("aes_key.bin", "wb");
    if (fd2 != NULL) {
        fwrite(key_copy, 1, blob->cbKeySize, fd2);
        printf("  [ writing %i bytes to %s\n", blob->cbKeySize, "aes_key.bin");
        fclose(fd2);
        fd2 = NULL;
    }




    delete[] key_copy;
    delete[] buffer;
    CryptDestroyKey(key);
    CryptReleaseContext(provider, 0);


}

static const DWORD kExpectedHashSize = 64;

void sha512_file(const std::string filename, std::string& data_hash) {
    std::string data;

    std::vector<BYTE> input;
    if (get_file_contents(filename.c_str(), input)) {
        data = std::string((char*)&input[0]);
    }


    HCRYPTPROV provider = NULL;

    DWORD dwVersion = GetVersion();
    DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));

    LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;
    if (dwMajor <= 5)
        pszProvider = MS_ENH_RSA_AES_PROV_XP;

    if (!CryptAcquireContext(&provider,
                             NULL,
                             pszProvider,
                             PROV_RSA_AES,
                             CRYPT_VERIFYCONTEXT)) {
        //LOG(ERROR) << "CryptAcquireContextW() failed: " << GetLastSystemErrorString();
        goto Exit0;

    }

    HCRYPTHASH hHash;

    if (!CryptCreateHash(provider, CALG_SHA_512, NULL, 0, &hHash)) {
        //LOG(ERROR) << "CryptCreateHash() failed: " << GetLastSystemErrorString();
        goto Exit0;
    }

    if (!CryptHashData(hHash,
                       reinterpret_cast<const BYTE*>(data.c_str()),
                       static_cast<DWORD>(data.length()),
                       0)) {
        //LOG(ERROR) << "CryptHashData() failed: " << GetLastSystemErrorString();
        goto Exit0;
    }

    DWORD size = 0;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &size, 0)) {
        //LOG(ERROR) << "CryptGetHashParam() failed: " << GetLastSystemErrorString();
        goto Exit0;
    }

    if (size != kExpectedHashSize) {
        //LOG(ERROR) << "Wrong hash size: " << size;
        goto Exit0;
    }

    data_hash.resize(size);

    if (!CryptGetHashParam(hHash,
                           HP_HASHVAL,
                           reinterpret_cast<BYTE*>(&data_hash[0]),
                           &size,
                           0)) {
        //LOG(ERROR) << "CryptGetHashParam() failed: " << GetLastSystemErrorString();
        goto Exit0;
    }

Exit0:

    if (hHash)
        CryptDestroyHash(hHash);

    if (provider)
        CryptReleaseContext(provider, 0);

    return;
}

char* Xor(char* szData, DWORD dwKey, int nLength) {
    if (szData == NULL)
        return NULL;

    for (int i = 0; i < nLength; i++)
        szData[i] = szData[i] ^ (char)dwKey;

    return szData;
}


// 字节反序
void reverse(BYTE* data, int nLen) {
    for (int ii = 0; ii < nLen / 2; ii++) {
        BYTE c = data[ii];
        data[ii] = data[nLen - ii - 1];
        data[nLen - ii - 1] = c;
    }
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


void gen_aes_key_iv() {
    HCRYPTPROV provider = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY newHKey = NULL;
    DWORD ivLen, blockLen = 0;

    BYTE* iv = NULL;
    BYTE* buffer = NULL;

    DWORD dwVersion = GetVersion();
    DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));

    LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;
    if (dwMajor <= 5)
        pszProvider = MS_ENH_RSA_AES_PROV_XP;

    if (!CryptAcquireContext(&provider,
                             NULL,
                             pszProvider,
                             PROV_RSA_AES,
                             0)) {
        printf("CryptAcquireContext() failed:");
        goto Exit0;
    }


    // 生成随机密钥
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

    printf("Default Key:\n");
    print_bin2c(blob->rgbKeyData, blob->cbKeySize);
    printf("\n\n");



    //// 复制随机密钥
    //if (!CryptDuplicateKey(hKey, NULL, 0, &newHKey)) {
    //	goto Exit0;
    //}


    // 从随机密钥获取 IV 长度
    if (!CryptGetKeyParam(hKey, KP_IV, NULL, &ivLen, 0)) {
        goto Exit0;
    }

    iv = new BYTE[ivLen];
    ZeroMemory(iv, ivLen);

    if (!CryptGenRandom(provider, ivLen, iv)) {
        goto Exit0;
    }


    printf("Default IV:\n");
    print_bin2c(iv, ivLen);
    printf("\n\n");

    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0)) {
        goto Exit0;
    }

    ZeroMemory(iv, ivLen);
    if (!CryptGetKeyParam(hKey, KP_IV, iv, &ivLen, 0)) {
        goto Exit0;
    }

    printf("Default IV:\n");
    print_bin2c(iv, ivLen);
    printf("\n\n");

    DWORD LenBlockAES = 0;
    DWORD dwCount = sizeof(DWORD);
    if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&LenBlockAES, &dwCount, 0)) {
        goto Exit0;
    }

    printf("aes block data len: %d\n", LenBlockAES);


    // 设置 CBC 模式
    DWORD cipher_mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&cipher_mode), 0)) {
        goto Exit0;
    }


    // 设置 padding
    DWORD padding_method = PKCS5_PADDING;
    if (!CryptSetKeyParam(hKey, KP_PADDING, reinterpret_cast<BYTE*>(&padding_method), 0)) {
        goto Exit0;
    }

Exit0:

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

    if (newHKey) {
        CryptDestroyKey(newHKey);
    }

    if (provider) {
        CryptReleaseContext(provider, 0);
    }

    return;
}


void gen_aes256_key_iv() {
    HCRYPTPROV provider = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTKEY newHKey = NULL;
    DWORD ivLen, blockLen = 0;

    BYTE* iv = NULL;
    BYTE* buffer = NULL;

    DWORD dwVersion = GetVersion();
    DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));

    LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;
    if (dwMajor <= 5)
        pszProvider = MS_ENH_RSA_AES_PROV_XP;

    if (!CryptAcquireContext(&provider,
                             NULL,
                             pszProvider,
                             PROV_RSA_AES,
                             0)) {
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

    DWORD LenBlockAES = 0;
    DWORD dwCount = sizeof(DWORD);
    if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&LenBlockAES, &dwCount, 0)) {
        goto Exit0;
    }

    printf("aes block data len: %d\n", LenBlockAES);

Exit0:

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


char test_aes256_key[] = {
    0x18, 0xfc, 0x7c, 0xc2, 0x17, 0xc9, 0x71, 0x98,
    0x21, 0xb0, 0x80, 0xc8, 0x6d, 0x73, 0x5d, 0x7e,
    0x20, 0x02, 0xc8, 0x75, 0x0e, 0xa5, 0x55, 0x49,
    0x4c, 0xd1, 0xdc, 0x13, 0x23, 0xa6, 0xfe, 0x58
};

char test_aes256_iv[] = {
    0x88, 0x8c, 0xe7, 0xe5, 0x37, 0xdc, 0x2b, 0xa4,
    0x4b, 0xc5, 0xd2, 0x41, 0xbc, 0x60, 0x5f, 0xa9
};

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



void AESEncrypt(const char* inFileName, const char* outFileName) {
    std::vector<BYTE> orgine_data;
	HCRYPTPROV provider = NULL;
	HCRYPTKEY hKey = NULL;

    do {
        if (!inFileName || !outFileName) {
            break;
        }

        if (!get_file_contents(inFileName, orgine_data)) {
            break;
        }       

        DWORD dwVersion = GetVersion();
        DWORD dwMajor = (DWORD)(LOBYTE(LOWORD(dwVersion)));

        LPCTSTR pszProvider = MS_ENH_RSA_AES_PROV;
        if (dwMajor <= 5)
            pszProvider = MS_ENH_RSA_AES_PROV_XP;

        if (!CryptAcquireContext(&provider,
                                 NULL,
                                 pszProvider,
                                 PROV_RSA_AES,
                                 0)) {
            printf("CryptAcquireContext() failed:");
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
        CopyMemory(keyBlob.rgbKeyData, test_aes256_key, keyBlob.cbKeySize);

        if (!CryptImportKey(provider, (BYTE*)(&keyBlob), sizeof(keyBlob), NULL, 0, &hKey)) {
            break;

        }

        DWORD dwMode = CRYPT_MODE_CBC, dwPadding = PKCS5_PADDING;

        if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)test_aes256_iv, 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE*>(&dwMode), 0)) {
            break;
        }

        if (!CryptSetKeyParam(hKey, KP_PADDING, reinterpret_cast<BYTE*>(&dwPadding), 0)) {
            break;
        }

        DWORD block_size = GetCipherBlockSize(hKey);

        DWORD data_len = orgine_data.size();
        DWORD total_len = data_len + block_size;

        std::vector<BYTE> tmp(total_len);
        memcpy(&tmp[0], orgine_data.data(), data_len);



        if (!CryptEncrypt(hKey, NULL, TRUE, 0, &tmp[0], &data_len, total_len)) {
            printf("Error %x during CryptEncrypt!\n", GetLastError());
            break;
        }

        printf("%d\n%s\n", total_len, &tmp[0]);

        DWORD data_len2 = data_len;
        std::vector<BYTE> tmp2(data_len2);
        memcpy(&tmp2[0], tmp.data(), data_len2);


        if (!CryptDecrypt(hKey, NULL, TRUE, 0, (BYTE*)&tmp2[0], &data_len2)) {
            printf("CryptDecrypt failed.\n");
            break;
        }

        std::string output;
        output.assign(reinterpret_cast<char*>(&tmp2[0]), data_len2);

        printf("%s\n", output.c_str());
    } while (0);

    if (hKey != NULL) {
        CryptDestroyKey(hKey);
    }

	if (provider != NULL)	{
		CryptReleaseContext(provider, 0);
    }
}



std::string SHA1HashString(const std::string& str) {

	enum {
		SHA1_LENGTH = 20  // Length in bytes of a SHA-1 hash.
	};

	std::string retval = std::string(SHA1_LENGTH, '\0');

	HCRYPTPROV provider = NULL;	
	HCRYPTHASH hash = NULL;
	
	do 
	{
		if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT)) {
			//LOG(ERROR) << "CryptAcquireContext failed: " << GetLastError();
			break;
		}

		if (!CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash)) {
			//LOG(ERROR) << "CryptCreateHash failed: " << GetLastError();
			break;
		}

		if (!CryptHashData(hash, reinterpret_cast<CONST BYTE*>(str.data()),
			static_cast<DWORD>(str.length()), 0)) {
			//LOG(ERROR) << "CryptHashData failed: " << GetLastError();
			break;
		}

		DWORD hash_len = 0;
		DWORD buffer_size = sizeof hash_len;
		if (!CryptGetHashParam(hash, HP_HASHSIZE,
			reinterpret_cast<unsigned char*>(&hash_len),
			&buffer_size, 0)) {
			//LOG(ERROR) << "CryptGetHashParam(HP_HASHSIZE) failed: " << GetLastError();
			break;
		}

		
		if (!CryptGetHashParam(hash, HP_HASHVAL,
			// We need the + 1 here not because the call will write a trailing \0,
			// but so that result.length() is correctly set to |hash_len|.
			reinterpret_cast<BYTE*>(WriteInto(&retval, hash_len + 1)), &hash_len, 0)) {
			//LOG(ERROR) << "CryptGetHashParam(HP_HASHVAL) failed: " << GetLastError();
			break;
		}

		if (hash_len != SHA1_LENGTH) {
			//LOG(ERROR) << "Returned hash value is wrong length: " << hash_len	<< " should be " << SHA1_LENGTH;
			break;
		}

		

	} while (0);

	if (hash != NULL) {
		CryptDestroyHash(hash);
	}

	if (provider != NULL)	{
		CryptReleaseContext(provider, 0);
	}


	return retval;
   
	

}
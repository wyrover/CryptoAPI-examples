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

DEFINE_bool(genkey, false, "创建 rsa 密钥对");
DEFINE_int32(keylen, 2048, "rsa 密钥位数");
DEFINE_string(src_filename, "", "待加密文件");
DEFINE_string(enc_filename, "", "待解密文件");




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


    //cout << "src_filename =" << FLAGS_src_filename << std::endl;


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
    if (open_crypt()) {
        // import our private key
        if (open_key(RSA_PRIVATE_BIN)) {
            // hash the input
            if (open_hash(filename, &hHash)) {
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

                if (hHash != 0) {
                    CryptDestroyHash(hHash);
                    hHash = 0;
                }
            } else {
                xstrerror("open_hash()");
            }

            close_key();
        } else {
            xstrerror("open_key()");
        }

        close_crypt();
    } else {
        xstrerror("open_crypt()");
    }
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

    // initialize crypto API
    if (open_crypt()) {
        // import public key
        if (open_key(RSA_PUBLIC_BIN)) {
            // hash the input
            if (get_enc_file_data_hash(filename.c_str(), &hHash)) {
                // convert signature to binary

                std::vector<BYTE> sign_message;
                if (get_enc_file_sign_message(filename.c_str(), sign_message)) {
                    if (sign_message.size() > 0) {
                        // verify signature
                        bStatus = CryptVerifySignature(hHash, &sign_message[0],
                                                       sign_message.size(), hKey, NULL, 0);
                        printf("  [ signature is %s\n",
                               bStatus ? "valid" : "invalid");

                    }
                }

                if (hHash != 0) {
                    CryptDestroyHash(hHash);
                    hHash = 0;
                }
            } else {
                printf("open_hash()");
            }

            close_key();
        } else {
            printf("open_key()");
        }

        close_crypt();
    } else {
        printf("open_crypt()");
    }

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


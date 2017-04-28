/**
  Copyright (C) 2016 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <windows.h>
#include <Wincrypt.h>
#include <Shlwapi.h>

#if !defined(__GNUC__)
    #pragma comment(lib, "crypt32.lib")
    #pragma comment(lib, "advapi32.lib")
    #pragma comment(lib, "shlwapi.lib")
    #pragma comment(lib, "user32.lib")
#endif

#define RSA_KEY_LEN 2048

#define RSA_PUBLIC_BIN "rsa_public.bin"
#define RSA_PUBLIC_H "rsa_public.h"

#define RSA_PRIVATE_BIN "rsa_private.bin"
#define RSA_PRIVATE_H "rsa_private.h"

#define RSA_C_ARRAY 0
#define RSA_BINARY  1
#define RSA_SIGN    2
#define RSA_VERIFY  3

FILE       *fd    = NULL;
HCRYPTPROV hProv  = 0;    // crypto API provider
HCRYPTKEY  hKey   = 0;    // key object
HCRYPTHASH hHash  = 0;    // hash object

BYTE *pbBlob      = NULL;
DWORD dwBlob      = 0;

BYTE *pbSignature = NULL;
DWORD dwSigLen    = 0;

DWORD keylen      = RSA_KEY_LEN;

char *input = NULL, *signature = NULL;

// allocate memory
void *xmalloc(SIZE_T dwSize)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// free memory
void xfree(void *mem)
{
    HeapFree(GetProcessHeap(), 0, mem);
}

// display extended windows error
void xstrerror(char *fmt, ...)
{
    char    *error = NULL;
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
BOOL open_crypt(void)
{
    BOOL bStatus = FALSE;
    bStatus = CryptAcquireContext(&hProv, NULL, NULL,
                                  PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    return bStatus;
}

void close_crypt(void)
{
    // release provider
    if (hProv != 0) {
        CryptReleaseContext(hProv, 0);
        hProv = 0;
    }
}

// open key file
BOOL open_key(char *key_file)
{
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

void close_key(void)
{
    if (pbBlob != NULL) {
        xfree(pbBlob);
        pbBlob = NULL;
    }

    if (fd != NULL) {
        fclose(fd);
        fd = NULL;
    }
}

// generates SHA-256 hash of input
BOOL open_hash(void)
{
    BOOL bStatus = FALSE;

    // create hash object
    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        // hash input
        bStatus = CryptHashData(hHash, input, lstrlen(input), 0);
    }

    return bStatus;
}

// destroy hash object
void close_hash(void)
{
    if (hHash != 0) {
        CryptDestroyHash(hHash);
        hHash = 0;
    }
}

// print binary as c array
void bin2c(char s[])
{
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

// export key as C array string
void export_key(DWORD dwType, char out[], int fmt)
{
    DWORD dwWritten, i;
    char *type = (dwType == PUBLICKEYBLOB) ? "sign_public" : "sign_private";
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
                        bin2c(type);
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

        fclose(fd);
    } else {
        xstrerror("fopen(%s)", out);
    }
}

// generate public/private key pair for digital signatures
void genkeys(void)
{
    if (open_crypt()) {
        if (CryptGenKey(hProv, AT_SIGNATURE,
                        keylen << 16 | CRYPT_EXPORTABLE, &hKey)) {
            // export as C array and binary
            export_key(PUBLICKEYBLOB,  RSA_PUBLIC_H,    RSA_C_ARRAY);
            export_key(PUBLICKEYBLOB,  RSA_PUBLIC_BIN,  RSA_BINARY);
            export_key(PRIVATEKEYBLOB, RSA_PRIVATE_H,   RSA_C_ARRAY);
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

// convert binary signature to hex string
// pointer should be freed after use
PBYTE sig2hex(void)
{
    DWORD len = 0;
    PBYTE hex;
    // determine how much space we need
    CryptBinaryToString(pbSignature, dwSigLen,
                        CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, NULL, &len);
    // allocate memory
    hex = xmalloc(len);
    // get the string
    CryptBinaryToString(pbSignature, dwSigLen,
                        CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, hex, &len);
    // return it (ensure pointer is freed after being used)
    return hex;
}

// convert signature to binary
// ensure to free pbSignature after use
void sig2bin(void)
{
    DWORD slen = lstrlen(signature);
    // determine how much space we need
    CryptStringToBinary(signature, slen,
                        CRYPT_STRING_HEX_ANY, NULL, &dwSigLen, NULL, NULL);
    // allocate memory
    pbSignature = xmalloc(dwSigLen);
    // get the binary
    CryptStringToBinary(signature, slen,
                        CRYPT_STRING_HEX_ANY, pbSignature, &dwSigLen, NULL, NULL);
}

// sign a hash of input using private key
void sign(void)
{
    char *p;

    // initialize crypto API
    if (open_crypt()) {
        // import our private key
        if (open_key(RSA_PRIVATE_BIN)) {
            // hash the input
            if (open_hash()) {
                // obtain size of signature
                CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
                pbSignature = xmalloc(dwSigLen);

                // sign the hash to obtain signature
                if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) {
                    p = sig2hex();

                    if (p) {
                        printf("  [ signature is: %i::%s\n", lstrlen(p), p);
                    }

                    xfree(pbSignature);
                } else {
                    xstrerror("CryptSignHash()");
                }

                close_hash();
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

// verify a signature using public key
BOOL verify(void)
{
    BOOL bStatus = FALSE;

    // initialize crypto API
    if (open_crypt()) {
        // import public key
        if (open_key(RSA_PUBLIC_BIN)) {
            // hash the input
            if (open_hash()) {
                // convert signature to binary
                sig2bin();

                if (pbSignature != NULL) {
                    // verify signature
                    bStatus = CryptVerifySignature(hHash, pbSignature,
                                                   dwSigLen, hKey, NULL, 0);
                    printf("  [ signature is %s\n",
                           bStatus ? "valid" : "invalid");
                    xfree(pbSignature);
                }

                close_hash();
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

char* getparam(int argc, char *argv[], int *i)
{
    int n = *i;

    if (argv[n][2] != 0) {
        return &argv[n][2];
    }

    if ((n + 1) < argc) {
        *i = n + 1;
        return argv[n + 1];
    }

    printf("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit(0);
}

void usage(void)
{
    printf("  [ usage: keygen [options]\n");
    printf("     -g              Generate RSA key pair for signing\n");
    printf("     -k <keylen>     Key length in bits (default is %i)\n", RSA_KEY_LEN);
    printf("     -m <message>    Sign <message> using private key\n");
    printf("     -v <signature>  Verify <signature> using public key, requires -m\n\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int i, g = 0, s = 0, v = 0;
    char opt;
    printf("\n\n  [ RSA key generation/signing/verifcation\n\n");

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            opt = argv[i][1];

            switch (opt) {
            case 'g': // generate RSA key pair
                g = 1;
                break;

            case 'm': // sign a message using RSA (just for testing)
                input = getparam(argc, argv, &i);
                s = 1;
                break;

            case 'k': // key length (max is 1024-bits)
                keylen = atoi(getparam(argc, argv, &i));
                break;

            case 'v': // verify RSA signature (just for testing)
                signature = getparam(argc, argv, &i);
                v = 1;
                break;

            default:
                usage();
                break;
            }
        }
    }

    // generate keys?
    if (g) {
        printf("  [ generating RSA key pair of %i-bits\n", keylen);
        genkeys();
    } else

        // generate signature of message using RSA private key?
        if (s == 1 && v == 0) {
            // have input?
            if (input == NULL) {
                printf("  [ signing requires a message, use -m option\n");
                return 0;
            }

            printf("  [ signing message using RSA\n");
            sign();
        } else

            // verify signature using RSA public key?
            if (v) {
                // have input + signature?
                if (input == NULL || signature == NULL) {
                    printf("  [ verification requires message and signature\n");
                    return 0;
                }

                printf("  [ verifying message and signature using RSA\n");
                verify();
            } else {
                usage();
            }

    return 0;
}

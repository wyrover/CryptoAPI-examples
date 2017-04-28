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

#include <windows.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

#define PUBLIC_KEY  0
#define PRIVATE_KEY 1

typedef struct _rsa_key_t {
    PUBLICKEYSTRUC  hdr;
    RSAPUBKEY       rsa;
    BYTE            mod[1];
} RSA_KEY, *PRSA_KEY;

// allocate memory
LPVOID xmalloc(DWORD dwSize)
{
    return HeapAlloc(GetProcessHeap(),
                     HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc(LPVOID lpMem, DWORD dwSize)
{
    return HeapReAlloc(GetProcessHeap(),
                       HEAP_ZERO_MEMORY, lpMem, dwSize);
}

// free memory
void xfree(LPVOID lpMem)
{
    HeapFree(GetProcessHeap(), 0, lpMem);
}

void hex_dump(void *in, int len)
{
    DWORD outlen = 0;
    int ofs = 0;
    LPTSTR out;

    if (ofs == 0) printf("\n");

    ofs += len;

    if (CryptBinaryToString(
            in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
            NULL, &outlen)) {
        out = xmalloc(outlen);

        if (out != NULL) {
            if (CryptBinaryToString(
                    in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
                    out, &outlen)) {
                printf("%s", out);
            }

            xfree(out);
        }
    }

    putchar('\n');
}

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
        printf("\n  [ %s : %s", buffer, error);
        LocalFree(error);
    } else {
        printf("\n  [ %s : %i", buffer, dwError);
    }
}

// decodes a public or private key in PEM format
LPVOID decode_private(char *file, PDWORD keyLen)
{
    HANDLE in;
    PBYTE  derData, baseData, pemData, keyData = NULL;
    DWORD  read, derLen, baseLen, pemLen;
    // try open PEM file
    in = CreateFile(file, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (in != INVALID_HANDLE_VALUE) {
        // get size of PEM data
        pemLen = GetFileSize(in, NULL);

        if (pemLen != 0) {
            // allocate memory for base64 string
            pemData = xmalloc(pemLen);

            if (pemData != NULL) {
                // read contents
                ReadFile(in, pemData, pemLen, &read, NULL);
                hex_dump(pemData, pemLen);

                // calculate how much space required for DER format
                if (CryptStringToBinary(pemData, pemLen,
                                        CRYPT_STRING_BASE64HEADER, NULL,
                                        &derLen, NULL, NULL)) {
                    derData = xmalloc(derLen);

                    if (derData != NULL) {
                        // decode PEM string
                        if (CryptStringToBinary(pemData, pemLen,
                                                CRYPT_STRING_BASE64HEADER, derData,
                                                &derLen, NULL, NULL)) {
                            hex_dump(derData, derLen);

                            // calculate space for key
                            if (CryptDecodeObjectEx(
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    PKCS_RSA_PRIVATE_KEY, derData, derLen, 0,
                                    NULL, NULL, keyLen)) {
                                keyData = (PBYTE)xmalloc(*keyLen);

                                if (keyData != NULL) {
                                    // decode DER
                                    CryptDecodeObjectEx(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        PKCS_RSA_PRIVATE_KEY, derData, derLen, 0,
                                        NULL, keyData, keyLen);
                                    hex_dump(keyData, *keyLen);
                                }
                            } else xstrerror("CryptDecodeObjectEx");
                        }

                        xfree(derData);
                    }
                } else xstrerror("CryptStringToBinary");

                xfree(pemData);
            }
        }

        CloseHandle(in);
    } else xstrerror("CreateFile");

    return keyData;
}

// decodes a public or private key in PEM format
LPVOID decode_public(char *file, PDWORD keyLen)
{
    HANDLE in;
    PBYTE  derData, baseData, pemData, keyData = NULL;
    DWORD  read, derLen, baseLen, pemLen;
    // try open PEM file
    in = CreateFile(file, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (in != INVALID_HANDLE_VALUE) {
        // get size of PEM data
        pemLen = GetFileSize(in, NULL);

        if (pemLen != 0) {
            // allocate memory for base64 string
            pemData = xmalloc(pemLen);

            if (pemData != NULL) {
                // read contents
                ReadFile(in, pemData, pemLen, &read, NULL);
                hex_dump(pemData, pemLen);

                // calculate how much space required for DER format
                if (CryptStringToBinary(pemData, pemLen,
                                        CRYPT_STRING_BASE64HEADER, NULL,
                                        &derLen, NULL, NULL)) {
                    derData = xmalloc(derLen);

                    if (derData != NULL) {
                        // decode PEM string
                        if (CryptStringToBinary(pemData, pemLen,
                                                CRYPT_STRING_BASE64HEADER, derData,
                                                &derLen, NULL, NULL)) {
                            hex_dump(derData, derLen);

                            // calculate space for key
                            if (CryptDecodeObjectEx(
                                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    X509_PUBLIC_KEY_INFO, derData, derLen, 0,
                                    NULL, NULL, keyLen)) {
                                keyData = (PBYTE)xmalloc(*keyLen);

                                if (keyData != NULL) {
                                    // decode DER
                                    CryptDecodeObjectEx(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        X509_PUBLIC_KEY_INFO, derData, derLen, 0,
                                        NULL, keyData, keyLen);
                                    hex_dump(keyData, *keyLen);
                                }
                            } else xstrerror("CryptDecodeObjectEx");
                        }

                        xfree(derData);
                    }
                } else xstrerror("CryptStringToBinary");

                xfree(pemData);
            }
        }

        CloseHandle(in);
    } else xstrerror("CreateFile");

    return keyData;
}

int main(int argc, char *argv[])
{
    HCRYPTPROV prov;
    HCRYPTKEY  key;
    DWORD      keyLen;
    DWORD      type = PUBLIC_KEY;
    LPVOID     keyData = NULL;

    // X509_PUBLIC_KEY_INFO for public keys
    // PKCS_RSA_PRIVATE_KEY for private keys

    if (argc != 2) {
        printf("\ndecode <PEM file>\n");
        return 0;
    }

    keyData = decode_public(argv[1], &keyLen);

    if (keyData == NULL) {
        type = PRIVATE_KEY;
        keyData = decode_private(argv[1], &keyLen);
    }

    if (keyData != NULL) {
        // acquire a crypto provider
        if (CryptAcquireContext(&prov, NULL, NULL,
                                PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            if (type == PRIVATE_KEY) {
                if (CryptImportKey(prov, keyData, keyLen,
                                   0, CRYPT_EXPORTABLE, &key)) {
                    printf("Private Key imported");
                    // destroy key
                    CryptDestroyKey(key);
                } else xstrerror("CryptImportKey");
            } else {
                // import the key
                if (CryptImportPublicKeyInfo(prov, X509_ASN_ENCODING,
                                             (PCERT_PUBLIC_KEY_INFO)keyData, &key)) {
                    printf("Public Key imported");
                    // destroy key
                    CryptDestroyKey(key);
                } else xstrerror("CryptImportPublicKeyInfo");
            }

            // free crypto provider
            CryptReleaseContext(prov, 0);
        } else xstrerror("CryptAcquireContext");
    }

    return 0;
}

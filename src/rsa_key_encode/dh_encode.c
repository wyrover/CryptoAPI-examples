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

#pragma comment(lib, "shlwapi.lib")
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
LPVOID xmalloc(SIZE_T dwSize)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc(LPVOID lpMem, SIZE_T dwSize)
{
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lpMem, dwSize);
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

// The key size, in bits.
#define DHKEYSIZE 512

// Prime in little-endian format.
static const BYTE g_rgbPrime[] = {
    0x91, 0x02, 0xc8, 0x31, 0xee, 0x36, 0x07, 0xec,
    0xc2, 0x24, 0x37, 0xf8, 0xfb, 0x3d, 0x69, 0x49,
    0xac, 0x7a, 0xab, 0x32, 0xac, 0xad, 0xe9, 0xc2,
    0xaf, 0x0e, 0x21, 0xb7, 0xc5, 0x2f, 0x76, 0xd0,
    0xe5, 0x82, 0x78, 0x0d,

    0x4f, 0x32, 0xb8, 0xcb,
    0xf7, 0x0c, 0x8d, 0xfb, 0x3a, 0xd8, 0xc0, 0xea,
    0xcb, 0x69, 0x68, 0xb0, 0x9b, 0x75, 0x25, 0x3d,
    0xaa, 0x76, 0x22, 0x49, 0x94, 0xa4, 0xf2, 0x8d
};

// Generator in little-endian format.
static BYTE g_rgbGenerator[] = {
    0x02, 0x88, 0xd7, 0xe6, 0x53, 0xaf, 0x72, 0xc5,
    0x8c, 0x08, 0x4b, 0x46, 0x6f, 0x9f, 0x2e, 0xc4,
    0x9c, 0x5c, 0x92, 0x21, 0x95, 0xb7, 0xe5, 0x58,
    0xbf, 0xba, 0x24, 0xfa, 0xe5, 0x9d, 0xcb, 0x71,
    0x2e, 0x2c, 0xce, 0x99, 0xf3, 0x10, 0xff, 0x3b,
    0xcb, 0xef, 0x6c, 0x95, 0x22, 0x55, 0x9d, 0x29,
    0x00, 0xb5, 0x4c, 0x5b, 0xa5, 0x63, 0x31, 0x41,
    0x13, 0x0a, 0xea, 0x39, 0x78, 0x02, 0x6d, 0x62
};

char public_start[] = "-----BEGIN DH PARAMETERS-----\n";
char public_end[]   = "-----END DH PARAMETERS-----\n";

typedef struct _KEY_FORMAT_T {
    BLOBHEADER    blobheader;
    DHPUBKEY_VER3 keylen;
    BYTE          p[DHKEYSIZE / 8]; // Where P is the prime modulus
    BYTE          q[DHKEYSIZE / 8]; // Where Q is a large factor of P-1
    BYTE          g[DHKEYSIZE / 8]; // Where G is the generator parameter
    BYTE          j[DHKEYSIZE / 8]; // Where J is (P-1)/Q
    BYTE          y[DHKEYSIZE / 8]; // Where Y is (G^X) mod P
} DH_PARAMS, *PDH_PARAMS;

void encode_public(HCRYPTKEY key)
{
    FILE       *out;
    PBYTE      pem, pemData, derData;
    PBYTE      keyInfo;
    DWORD      encodeLen, keyLen, derLen, pemLen;
    PDH_PARAMS params;

    // get length of encoding
    if (CryptExportKey(key, 0, PUBLICKEYBLOB, CRYPT_BLOB_VER3, NULL, &keyLen)) {
        // allocate memory for encoding
        keyInfo = xmalloc(keyLen);

        // export public key
        if (CryptExportKey(key, 0, PUBLICKEYBLOB, CRYPT_BLOB_VER3, keyInfo, &keyLen)) {
            hex_dump(keyInfo, keyLen);

            // convert to DER format
            if (CryptEncodeObjectEx(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    RSA_CSP_PUBLICKEYBLOB, keyInfo, 0,
                    NULL, NULL, &derLen)) {
                derData = (PBYTE)xmalloc(derLen);

                if (CryptEncodeObjectEx(
                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        RSA_CSP_PUBLICKEYBLOB, keyInfo, 0,
                        NULL, derData, &derLen)) {
                    hex_dump(derData, derLen);
                    CryptBinaryToString(derData, derLen,
                                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR,
                                        NULL, &pemLen);
                    pemData = (PBYTE)xmalloc(pemLen);
                    CryptBinaryToString(derData, derLen,
                                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR,
                                        pemData, &pemLen);
                    hex_dump(pemData, pemLen);
                    out = fopen("dhpx.pem", "wb");

                    if (out != NULL) {
                        fwrite(public_start, sizeof(public_start) - 1, 1, out);
                        fwrite(pemData, pemLen, 1, out);
                        fwrite(public_end, sizeof(public_end) - 1, 1, out);
                        fclose(out);
                    }
                }
            } else xstrerror("CryptEncodeObjectEx");
        }
    } else xstrerror("CryptExportPublicKeyInfo");
}

int main(void)
{
    HCRYPTPROV prov;
    HCRYPTKEY  key;
    DWORD      keyLen, encodeLen, pemLen;
    PRSA_KEY   rsaKey;
    DATA_BLOB  P;
    DATA_BLOB  G;
    P.cbData = DHKEYSIZE / 8;
    P.pbData = (BYTE*)(g_rgbPrime);
    G.cbData = DHKEYSIZE / 8;
    G.pbData = (BYTE*)(g_rgbGenerator);

    // acquire a crypto provider
    if (CryptAcquireContext(&prov, NULL, NULL,
                            PROV_DSS_DH, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        // generate RSA key
        if (CryptGenKey(prov, CALG_DH_EPHEM,
                        DHKEYSIZE << 16 | CRYPT_EXPORTABLE | CRYPT_PREGEN, &key)) {
            // Set the prime for party 1's private key.
            CryptSetKeyParam(
                key,
                KP_P,
                (PBYTE)&P, 0);
            xstrerror("CryptSetKeyParam");
            // Set the generator for party 1's private key.
            CryptSetKeyParam(
                key,
                KP_G,
                (PBYTE)&G, 0);
            xstrerror("CryptSetKeyParam");
            encode_public(key);
            // destroy key
            CryptDestroyKey(key);
        }

        // free crypto provider
        CryptReleaseContext(prov, 0);
    }

    return 0;
}

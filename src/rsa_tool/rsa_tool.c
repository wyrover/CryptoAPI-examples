/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.

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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <shlwapi.h>
#ifdef _MSC_VER
    #pragma comment(lib, "shlwapi.lib")
#endif

#include "rsa.h"

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
        printf("\n  [ %s : %ld", buffer, dwError);
    }
}

/**
 *
 * verify a signature using public key
 *
 */
int verify(
    const char *pubkey,
    const char *file,
    const char *signature)
{
    int ok = 0;
    RSA *rsa = rsa_open();

    if (rsa != NULL) {
        printf("\n  [ Reading public key from %s...", pubkey);

        if (rsa_read_key(rsa, pubkey,  RSA_PUBLIC_KEY)) {
            printf("\n  [ Reading signature for %s from %s...",
                   file, signature);
            ok = rsa_verify(rsa, file, signature);
        } else xstrerror("rsa_read_key()");

        rsa_close(rsa);
    }

    return ok;
}

/**
 *
 * sign a file using private key
 *
 */
int sign(
    const char *privkey,
    const char *file,
    const char *signature)
{
    int ok = 0;
    RSA *rsa = rsa_open();

    if (rsa != NULL) {
        printf("\n  [ Reading private key from %s...", privkey);

        if (rsa_read_key(rsa, privkey,  RSA_PRIVATE_KEY)) {
            printf("\n  [ Writing signature for %s to %s...",
                   file, signature);
            ok = rsa_sign(rsa, file, signature);
        } else xstrerror("rsa_read_key()");

        rsa_close(rsa);
    }

    return ok;
}

/**
 *
 * generate RSA key pair
 *
 */
int genkey(
    const char *pubkey,
    const char *privkey,
    int bits)
{
    int  ok = 1;
    RSA  *rsa;
    rsa = rsa_open();

    if (rsa != NULL) {
        if (rsa_genkey(rsa, bits)) {
            printf("\n  [ Saving public key to %s...", pubkey);

            if (rsa_write_key(rsa, pubkey,  RSA_PUBLIC_KEY)) {
                printf("ok\n  [ Saving private key to %s...", privkey);

                if (rsa_write_key(rsa, privkey, RSA_PRIVATE_KEY)) {
                    printf("ok\n");
                } else xstrerror("rsa_write_key()");
            } else xstrerror("rsa_write_key()");
        } else xstrerror("rsa_genkey()");

        rsa_close(rsa);
    }

    return ok;
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
    printf("  [ usage: rsa_tool [options] <file>\n\n");
    printf("     -g <bitlen>  Generate RSA key pair of <bitlen>\n");
    printf("     -s <file>    Using private key in <file>\n");
    printf("     -x <file>    Read signature from <file>\n");
    printf("     -v <file>    Using public key in <file>\n\n");
    exit(0);
}

int main(int argc, char *argv[])
{
    int  i, g = 0, s = 0, v = 0, bitlen;
    char opt;
    char *priv = "private.pem",
          *pub = "public.pem", *sig = NULL,
           *file = NULL;
    puts("\n  [ RSA Tool v0.1"
         "\n  [ copyright (c) 2017 @odzhancode\n");

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-' || argv[i][0] == '/') {
            opt = argv[i][1];

            switch (opt) {
            case 'g': // generate RSA key pair
                g = 1;
                bitlen = atoi(getparam(argc, argv, &i));
                break;

            case 's': // private key
                priv = getparam(argc, argv, &i);
                s = 1;
                break;

            case 'x': // signature file
                sig  = getparam(argc, argv, &i);
                break;

            case 'v': // verify RSA signature
                pub  = getparam(argc, argv, &i);
                v = 1;
                break;

            default:
                usage();
                break;
            }
        } else {
            file = argv[i];
        }
    }

    // generate keys?
    if (g) {
        printf("  [ generating RSA key pair of %i-bits\n", bitlen);
        genkey(pub, priv, bitlen);
    } else

        // generate signature of message using RSA private key?
        if (s == 1 && v == 0) {
            // have file?
            if (file == NULL) {
                printf("  [ signing requires a file\n");
                return 0;
            }

            printf("\n  [ signing file using RSA : %s\n",
                   sign(priv, file, sig) ? "OK" : "FAILED");
        } else

            // verify signature using RSA public key?
            if (v) {
                // have input + signature?
                if (file == NULL || sig == NULL) {
                    printf("  [ verification requires file and signature\n");
                    return 0;
                }

                printf("\n  [ verifying signature using RSA : %s\n",
                       verify(pub, file, sig) ? "OK" : "FAILED");
            } else {
                usage();
            }

    return 0;
}
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

#include "encode.h"

/**
 *
 * convert base64 string to binary
 *
 */
LPVOID b64tobin(LPVOID in, DWORD inLen, DWORD flags, PDWORD outLen)
{
    LPVOID out = NULL;

    // calculate how much space required
    if (CryptStringToBinary(in, inLen,
                            CRYPT_STRING_BASE64 | flags,
                            NULL, outLen, NULL, NULL)) {
        out = xmalloc(*outLen);

        if (out != NULL) {
            // decode base64
            CryptStringToBinary(in, inLen,
                                CRYPT_STRING_BASE64 | flags,
                                out, outLen, NULL, NULL);
        }
    }

    return out;
}

/**
 *
 * convert binary to base64 string
 *
 */
LPVOID bintob64(LPVOID in, DWORD inLen, DWORD flags)
{
    DWORD  outLen;
    LPVOID out = NULL;

    // calculate space for string
    if (CryptBinaryToString(in, inLen,
                            CRYPT_STRING_BASE64 | flags, NULL, &outLen)) {
        out = xmalloc(outLen);

        // convert it
        if (out != NULL) {
            CryptBinaryToString(in, inLen,
                                CRYPT_STRING_BASE64 | flags, out, &outLen);
        }
    }

    return out;
}


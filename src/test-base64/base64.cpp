bool Base64EncodeA(char **dest, unsigned long *dlen, const unsigned char *src, unsigned long slen)
{
    if (src == NULL)
        return false;

    if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, dlen))
        return false;

    *dest = (char *)malloc(*dlen * sizeof(char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, *dlen * sizeof(char));

    if (!CryptBinaryToStringA(src, slen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, *dest, dlen)) {
        SAFE_FREE(*dest);
        return false;
    }

    return true;
}

bool Base64DecodeA(unsigned char **dest, unsigned long *dlen, const char *src, unsigned long slen)
{
    if (src == NULL)
        return false;

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, NULL, dlen, NULL, NULL))
        return false;

    *dest = (unsigned char *)malloc((*dlen + 1) * sizeof(unsigned char));

    if (*dest == NULL) return false;

    SecureZeroMemory(*dest, (*dlen + 1) * sizeof(unsigned char));

    if (!CryptStringToBinaryA(src, slen, CRYPT_STRING_BASE64, *dest, dlen, NULL, NULL)) {
        SAFE_FREE(*dest);
        return false;
    }

    return true;
}



#define SAFE_FREE(x) if(x) { free(x); x=NULL; }

char *encoded = 0;
unsigned long encodedLen = 0, decodedLen = 0;
char *decoded = 0;

if (Base64EncodeA(&encoded, &encodedLen, argv[1], strlen(argv[1])))
{
    printf("Base64 encoded: %s\n", encoded);

    if (Base64DecodeA(&decoded, &decodedLen, encoded, encodedLen)) {
        printf("Base64 decoded: %s\n", decoded);
        SAFE_FREE(encoded);
        SAFE_FREE(decoded);
    }
}
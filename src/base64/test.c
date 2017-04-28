

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "encode.h"

int main(int argc, char *argv[])
{
    void *b64, *bin;
    int  len;

    if (argc != 2) {
        printf("\nusage: test <string>\n");
        return 0;
    }

    b64 = bintob64(argv[1], strlen(argv[1]), CRYPT_STRING_NOCR);
    printf("\n%s", b64);
    bin = b64tobin(b64, strlen(b64), 0, &len);
    xfree(b64);
    xfree(bin);
    return 0;
}

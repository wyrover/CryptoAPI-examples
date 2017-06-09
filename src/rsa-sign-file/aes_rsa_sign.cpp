#include "aes_rsa_sign.h"
#include "crypto_api_aes.h"
#include "crypto_api_rsa.h"
#include "common.h"
#include <vector>
#include <string>


bool aes_encrypt_file_and_rsa_sign(const char* filename, const char* outfilename)
{
    bool retval = false;
    std::vector<BYTE> inData;
    std::string out_filename = std::string(outfilename);

    do {
        char base64_key[] = "JUC/gPtu9fygSLbZaS/o1mxrfOGfRMkbZOOAsAaW9MU=";
        char base64_iv[] = "jJGbbzjndPzqgof8ou9MQA==";

        if (!aes_encrypt_file(base64_key, base64_iv, filename, out_filename.c_str())) {
            break;
        }

        if (!sign_file2(out_filename)) {
            break;
        }

        retval = true;
    } while (0);

    return retval;
}

bool rsa_verify_file_and_aes_decrypt(const char* filename, std::string& out_string)
{
    bool retval = false;
    std::vector<BYTE> key;
    std::vector<BYTE> iv;

    do {
        if (!verify_file2(filename)) {
            break;
        }

        std::vector<BYTE> inData;

        if (!get_enc_file_data(filename, inData)) {
            break;
        }

        char base64_key[] = "JUC/gPtu9fygSLbZaS/o1mxrfOGfRMkbZOOAsAaW9MU=";
        char base64_iv[] = "jJGbbzjndPzqgof8ou9MQA==";

        if (!get_key_iv_from_base64(base64_key, base64_iv, key, iv)) {
            break;
        }

        DWORD inData_len = inData.size();
        DWORD Decrypt_Len = aes_Decrypt(&key[0], key.size(), &iv[0], (LPBYTE)&inData[0], &inData_len);

        if (!Decrypt_Len)
            break;

        out_string = std::string((char*)&inData[0]);
        out_string.at(Decrypt_Len) = '\0';
        out_string.resize(Decrypt_Len);
        retval = true;
    } while (0);

    return retval;
}


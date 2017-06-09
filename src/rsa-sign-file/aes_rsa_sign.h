#ifndef __CACTUS_AES_RSA_SIGN_H__
#define __CACTUS_AES_RSA_SIGN_H__

#include <Windows.h>
#include <string>

bool aes_encrypt_file_and_rsa_sign(const char* filename, const char* outfilename);
bool rsa_verify_file_and_aes_decrypt(const char* filename, std::string& out_string);


#endif // __CACTUS_AES_RSA_SIGN_H__

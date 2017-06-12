
:: 创建 AES256 key 和 iv
rsa-sign-file.exe -gen_aes256_key >aes256_key_iv.txt


:: 创建 RSA 2048 密钥对
rsa-sign-file.exe -genkey >rsa_key.txt


:: AES256 加解密
rsa-sign-file.exe --aes_encrypt --aes_base64_key="JUC/gPtu9fygSLbZaS/o1mxrfOGfRMkbZOOAsAaW9MU=" --aes_base64_iv="jJGbbzjndPzqgof8ou9MQA==" --aes_in_filename=test1.txt --aes_out_filename=test1.aes.encrypted.txt

rsa-sign-file.exe --aes_base64_key="JUC/gPtu9fygSLbZaS/o1mxrfOGfRMkbZOOAsAaW9MU=" --aes_base64_iv="jJGbbzjndPzqgof8ou9MQA==" --aes_in_filename=test1.aes.encrypted.txt --aes_out_filename=test1.aes.decrypted.txt


::rsa-sign-file.exe --src_filename=test1.aes.encrypted.txt
::
::rsa-sign-file.exe --enc_filename=test1.aes.encrypted.txt.enc



:: AES256 加密并 RSA 签名

rsa-sign-file.exe --aes_rsa_sign_in_filename=test1.txt --aes_rsa_sign_out_filename=test1.aes256.signed

:: RSA 签名验证 并 AES256 解密

rsa-sign-file.exe --rsa_verify_aes_filename=test1.aes256.signed




pause
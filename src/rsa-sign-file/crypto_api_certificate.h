#ifndef __CACTUS_CRYPTO_API_CERTIFICATE_H__
#define __CACTUS_CRYPTO_API_CERTIFICATE_H__





#include <Windows.h>
#include <wincrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSIGN_ERROR_NONE 0
#define OPENSIGN_ERROR_DIGEST_VALUE_UNAVAILABLE 1
#define OPENSIGN_ERROR_DIGEST_SIZE_UNAVAILABLE 2
#define OPENSIGN_ERROR_HHASH_DESTROY_FAILURE 3
#define OPENSIGN_ERROR_HHASH_CREATE_FAILURE 4
#define OPENSIGN_ERROR_HHASH_SIGNATURE_VALUE_UNAVAILABLE 11
#define OPENSIGN_ERROR_HHASH_SIGNATURE_SIZE_UNAVAILABLE 13
#define OPENSIGN_ERROR_HHASH_HASHDATA_FAILURE 15
#define OPENSIGN_ERROR_HCRYPTPROV_RELEASE_FAILURE 5
#define OPENSIGN_ERROR_HCRYPTPROV_ACQUIRE_FAILURE 6
#define OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE 7
#define OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND 8
#define OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE 9
#define OPENSIGN_ERROR_CCONTEXT_PROVINFO_VALUE_UNAVAILABLE 10
#define OPENSIGN_ERROR_CCONTEXT_PROVINFO_SIZE_UNAVAILABLE 14
#define OPENSIGN_ERROR_CERTGETNAMESTRING_SIZE_FAILURE 16
#define OPENSIGN_ERROR_CERTGETNAMESTRING_VALUE_FAILURE 17
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE 29
#define OPENSIGN_ERROR_KEYUSAGE_NOT_PRESENT 19
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_1 20
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_2 21
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_3 22
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_4 23
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_5 24
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_6 25
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_7 26
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_8 27
#define OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_9 28

	extern int lastError;

	struct byte_array_t{
		BYTE* data;
		long size;
	};

	struct certificate_data {
		byte_array_t* pbCertEncoded;
		long count;
		certificate_data *prev;

	};

	void freeCertificateList(struct certificate_data* head);

	struct certificate_data* getCertificatesInMyStore();

	int digest(BYTE *to_be_hashed,
		DWORD to_be_hashed_length,
		BYTE **digest_value,
		DWORD *digest_value_length,
		ALG_ID alg_id);

	int sign(BYTE *certificate,
		DWORD certificate_length,
		BYTE *to_be_signed,
		DWORD to_be_signed_length,
		BYTE **signature,
		DWORD *signature_length,
		ALG_ID alg_id);

	int getCertificateDn(BYTE *certificate,
		DWORD certificate_length,
		DWORD issuerFlag,
		WCHAR **issuerDn,
		DWORD *dnLen);

	int getCertificateVersion(BYTE *certificate,
		DWORD certificate_length,
		DWORD *version);

	int getCertificateTimestamp(BYTE *certificate,
		DWORD certificate_length,
		BOOL notBefore,
		FILETIME *timestamp);

	int getCertificateSerialNumber(BYTE* certificate,
		DWORD certificate_length,
		CRYPT_INTEGER_BLOB *blSerialNumber);

	int getCertificateKeyUsage(BYTE *certificate,
		DWORD certificate_length,
		BYTE* keyusage);


#ifdef __cplusplus
}
#endif
#endif // __CACTUS_CRYPTO_API_CERTIFICATE_H__f

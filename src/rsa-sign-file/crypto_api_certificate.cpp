

#include "crypto_api_certificate.h"
//#include "global.h"
//#include "utils.h"
#include "common.h"


#include <stdio.h>
#include <stdlib.h>

#include <wincrypt.h>
#define CRYPTOMATHIC_PRIMECSP   "CRYPTOMATHiC RSA Full Provider 1.2"

int lastError;

PCCERT_CONTEXT locateCertificate(HCERTSTORE hStore, BYTE* certificate, DWORD certificate_length) {
	PCCERT_CONTEXT pCertContext = NULL;
	while (pCertContext = CertEnumCertificatesInStore(hStore, pCertContext)) {
		if (pCertContext) {
			if (pCertContext->cbCertEncoded == certificate_length) {
				if (!memcmp(pCertContext->pbCertEncoded, certificate, certificate_length)) {
					break;
				}
			}
		}
	}
	return pCertContext;
}

int getCertificateDn(BYTE* certificate,
	DWORD certificate_length,
	DWORD issuerFlag,
	WCHAR** dn,
	DWORD* dnLen) {

	BOOL b;
	HCERTSTORE hSystemStore = 0;
	PCCERT_CONTEXT pCertContext = NULL;

	lastError = OPENSIGN_ERROR_NONE;
	if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
		0,
		0,
		CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
		L"My"
		)) {


		pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

		if (pCertContext) {

			DWORD cchNameString;
			DWORD dwTypePara;

			dwTypePara = CERT_X500_NAME_STR + CERT_NAME_STR_REVERSE_FLAG;

			*dn = NULL;
			*dnLen = 0;

			if (cchNameString = CertGetNameStringW(pCertContext,
				CERT_NAME_RDN_TYPE,
				issuerFlag,
				(void*)&dwTypePara,
				*dn,
				0)) {

				*dn = (WCHAR*)malloc(cchNameString * sizeof(WCHAR));

				if (*dn) {
					if (cchNameString = CertGetNameStringW(pCertContext,
						CERT_NAME_RDN_TYPE,
						issuerFlag,
						(void*)&dwTypePara,
						*dn,
						cchNameString)) {
						*dnLen = cchNameString;
					}
					else {
						lastError = OPENSIGN_ERROR_CERTGETNAMESTRING_VALUE_FAILURE;
					}
				}
				else {
					lastError = OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE;
				}
			}
			else {
				lastError = OPENSIGN_ERROR_CERTGETNAMESTRING_SIZE_FAILURE;
			}
			CertFreeCertificateContext(pCertContext);
		}

		b = CertCloseStore(hSystemStore, 0);
		if (!b) {
			lastError = OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE;
		}
	}
	else {
		lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
	}

	return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}

int sign(BYTE* certificate, DWORD certificate_length, BYTE* to_be_signed, DWORD to_be_signed_length, BYTE** signature, DWORD* signature_length, ALG_ID alg_id) {

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;

    if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My"
                                    )) {

        pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

        if (pCertContext) {
            DWORD pcbData = 0;
            CRYPT_KEY_PROV_INFO* keyProvInfo;

            if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &pcbData)) {
                keyProvInfo = (CRYPT_KEY_PROV_INFO*)malloc(pcbData);
                if (keyProvInfo != NULL) {
                    if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, keyProvInfo, &pcbData)) {
                        HCRYPTPROV hCryptProv;
                        HCRYPTHASH hHash;
                        //char *containerName, *providerName;

                        //containerName = utf16string_convert(keyProvInfo->pwszContainerName);
                        //providerName = utf16string_convert(keyProvInfo->pwszProvName);
                        LPCWSTR containerName, providerName;

                        containerName = keyProvInfo->pwszContainerName;
                        providerName = keyProvInfo->pwszProvName;
                        if (containerName != NULL) {
                            if (CryptAcquireContextW(
                                        &hCryptProv,
                                        containerName,
                                        providerName,
                                        keyProvInfo->dwProvType,
                                        0)) {

                                if (CryptCreateHash(
                                            hCryptProv,
                                            alg_id,
                                            0,
                                            0,
                                            &hHash)) {
                                    BYTE* data;
                                    DWORD dataLen;

                                    if (CryptHashData(
                                                hHash,
                                                to_be_signed,
                                                to_be_signed_length,
                                                0)) {

                                        int success = 1;

                                        DWORD dwKeySpec = AT_KEYEXCHANGE;

                                        if (CryptSignHash(
                                                    hHash,
                                                    dwKeySpec,
                                                    NULL,
                                                    0,
                                                    NULL,
                                                    signature_length)) {
                                        } else {
                                            dwKeySpec = AT_SIGNATURE;
                                            if (CryptSignHash(
                                                        hHash,
                                                        dwKeySpec,
                                                        NULL,
                                                        0,
                                                        NULL,
                                                        signature_length)) {
                                            } else {
                                                success = 0;
                                            }
                                        }

                                        if (success) {
                                            *signature = (BYTE*)malloc(sizeof(BYTE) * (*signature_length));
                                            if (*signature != NULL) {

                                                if (CryptSignHash(
                                                            hHash,
                                                            dwKeySpec,
                                                            NULL,
                                                            0,
                                                            *signature,
                                                            signature_length)) {
                                                    reverse(*signature, *signature_length);
                                                    lastError = OPENSIGN_ERROR_NONE;
                                                } else {
                                                    lastError = OPENSIGN_ERROR_HHASH_SIGNATURE_VALUE_UNAVAILABLE;
                                                }
                                            } else {
                                                lastError = OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_1;

                                            }
                                        } else {
                                            lastError = OPENSIGN_ERROR_HHASH_SIGNATURE_SIZE_UNAVAILABLE;
                                        }

                                        if (!CryptDestroyHash(hHash)) {
                                            lastError = OPENSIGN_ERROR_HHASH_DESTROY_FAILURE;
                                        }
                                    } else {
                                        lastError = OPENSIGN_ERROR_HHASH_HASHDATA_FAILURE;
                                    }
                                    if (CryptReleaseContext(hCryptProv, 0)) {
                                    } else {
                                        lastError = OPENSIGN_ERROR_HCRYPTPROV_RELEASE_FAILURE;
                                    }
                                } else {
                                    lastError = OPENSIGN_ERROR_HHASH_CREATE_FAILURE;
                                }
                            } else {
                                lastError = OPENSIGN_ERROR_HCRYPTPROV_ACQUIRE_FAILURE;
                            }
                        } else {
                            /* containerName == NULL || providerName == NULL */
                            lastError = OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_2;
                        }

                        //if ( providerName ) {
                        //	free(providerName);
                        //}
                        //if ( containerName ) {
                        //	free(containerName);
                        //}
                    } else {
                        lastError = OPENSIGN_ERROR_CCONTEXT_PROVINFO_VALUE_UNAVAILABLE;
                    }
                    free(keyProvInfo);
                } else {
                    /* keyProvInfo == NULL */
                    lastError = OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_3;
                }
            } else {
                lastError = OPENSIGN_ERROR_CCONTEXT_PROVINFO_SIZE_UNAVAILABLE;
            }
            CertFreeCertificateContext(pCertContext);
            b = CertCloseStore(hSystemStore, 0);
            if (!b && (lastError == OPENSIGN_ERROR_NONE)) {
                lastError = OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE;
            }
        } else {
            lastError = OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND;
        }
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
    }

    return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}



int digest(BYTE* to_be_hashed, DWORD to_be_hashed_length, BYTE** digest_value, DWORD* digest_value_length, ALG_ID alg_id) {

    HCRYPTPROV hCryptProv;

    if (CryptAcquireContext(&hCryptProv,
                            NULL,
                            CRYPTOMATHIC_PRIMECSP,
                            PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT)) {

        HCRYPTHASH hHash;

        if (CryptCreateHash(hCryptProv,
                            alg_id,
                            0,
                            0,
                            &hHash)) {

            if (CryptHashData(hHash,
                              to_be_hashed,
                              to_be_hashed_length,
                              0)) {

                *digest_value = NULL;

                if (CryptGetHashParam(hHash,
                                      HP_HASHVAL,
                                      *digest_value,
                                      digest_value_length,
                                      0)) {
                    if ((alg_id == CALG_SHA1 && *digest_value_length != 20) || (alg_id == CALG_SHA_256 && *digest_value_length != 32)) {
                        lastError = OPENSIGN_ERROR_DIGEST_SIZE_UNAVAILABLE;
                        return -1;
                    }

                    *digest_value = (BYTE*)malloc(sizeof(BYTE) * (*digest_value_length));
                    if (*digest_value == NULL) {
                        lastError = OPENSIGN_ERROR_MEMORY_ALLOCATION_FAILURE_4;
                    }

                    if (*digest_value != NULL && CryptGetHashParam(hHash,
                            HP_HASHVAL,
                            *digest_value,
                            digest_value_length,
                            0)) {
                        /* all ok */
                        lastError = OPENSIGN_ERROR_NONE;
                    } else {
                        lastError = OPENSIGN_ERROR_DIGEST_VALUE_UNAVAILABLE;
                    }
                } else {
                    lastError = OPENSIGN_ERROR_DIGEST_SIZE_UNAVAILABLE;
                }
            }

            if (CryptDestroyHash(hHash)) {
            } else {
                lastError = OPENSIGN_ERROR_HHASH_DESTROY_FAILURE;
            }
        } else {
            lastError = OPENSIGN_ERROR_HHASH_CREATE_FAILURE;

        }

        if (CryptReleaseContext(hCryptProv,
                                0)) {
        } else {
            lastError = OPENSIGN_ERROR_HCRYPTPROV_RELEASE_FAILURE;
        }
    } else {
        lastError = OPENSIGN_ERROR_HCRYPTPROV_ACQUIRE_FAILURE;
    }

    return (lastError == OPENSIGN_ERROR_NONE) ? 0 : -1;
}

void freeCertificateList(struct certificate_data* head) {
	while (head != NULL) {
		struct certificate_data* l;
		l = head;
		if (l->pbCertEncoded) {

			for (int i = 0; i < l->count; ++i) {
				if (l->pbCertEncoded[i].data)
					free(l->pbCertEncoded[i].data);
			}

			free(l->pbCertEncoded);
		}
		head = head->prev;
		free(l);
	}
}

PCCERT_CHAIN_CONTEXT getChain(PCCERT_CONTEXT pCertContext) {

	CERT_CHAIN_PARA         ChainPara;
	PCCERT_CHAIN_CONTEXT    pChainContext = NULL;
	DWORD                   dwErr = NO_ERROR;
	ZeroMemory(&ChainPara, sizeof(ChainPara));
	ChainPara.cbSize = sizeof(ChainPara);

	CertGetCertificateChain(
		NULL,
		pCertContext,
		NULL,
		pCertContext->hCertStore,
		&ChainPara,
		0,
		NULL,
		&pChainContext);

	return pChainContext;

}


struct certificate_data* getCertificatesInMyStore() {

    struct certificate_data* certificate_list_head = NULL;

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;

    hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                 0,
                                 0,
                                 CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                 L"My"
                                );

    if (hSystemStore) {
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
        return NULL;
    }

    while (pCertContext = CertEnumCertificatesInStore(hSystemStore, pCertContext)) {
        if (pCertContext) {
            DWORD pcbData;

            /* check whether we can obtain a key provider info struct
            we use this as a way of telling whether we can access
            the private key associated with the certificate
            */
            if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &pcbData)) {

                PCCERT_CHAIN_CONTEXT certChain = getChain(pCertContext);
                PCERT_SIMPLE_CHAIN chain = certChain->rgpChain[0];

                struct certificate_data* entry;

                entry = (certificate_data*)malloc(sizeof(struct certificate_data));
                if (!entry) {
                    // FIXME: insert error handling
                    return NULL;
                }

                entry->pbCertEncoded = (byte_array_t*)malloc(chain->cElement * sizeof(byte_array_t));

                for (int i = 0; i < chain->cElement; ++i) {

                    byte_array_t& ba = entry->pbCertEncoded[i];

                    ba.size = chain->rgpElement[i]->pCertContext->cbCertEncoded * sizeof(byte);
                    ba.data = (byte*)malloc(ba.size);

                    for (int cert_encoding_iterator = 0; cert_encoding_iterator < chain->rgpElement[i]->pCertContext->cbCertEncoded; cert_encoding_iterator++) {
                        ba.data[cert_encoding_iterator] = chain->rgpElement[i]->pCertContext->pbCertEncoded[cert_encoding_iterator];
                    }
                    entry->count = i + 1;

                }

                entry->prev = certificate_list_head;

                certificate_list_head = entry;

                CertFreeCertificateChain(certChain);
            }
        }
    }
    if (CertCloseStore(hSystemStore, 0)) {
        //FIXME: insert error handling
    }

    return certificate_list_head;
}

int getCertificateTimestamp(BYTE* certificate,
                            DWORD certificate_length,
                            BOOL notBefore,
                            FILETIME* timestamp) {

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    lastError = OPENSIGN_ERROR_NONE;

    if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My"
                                    )) {

        pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

        if (pCertContext != NULL && pCertContext->pCertInfo != NULL) {
            *timestamp = notBefore ? pCertContext->pCertInfo->NotBefore : pCertContext->pCertInfo->NotAfter;
            CertFreeCertificateContext(pCertContext);
        } else {
            lastError = OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND;
        }

        b = CertCloseStore(hSystemStore, 0);
        if (b && lastError == 0) {
            lastError = OPENSIGN_ERROR_NONE;
        } else if (!b) {
            lastError = OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE;
        }
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
    }

    return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}

int getCertificateVersion(BYTE* certificate,
                          DWORD certificate_length,
                          DWORD* version) {

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    lastError = OPENSIGN_ERROR_NONE;

    if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My"
                                    )) {

        pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

        if (pCertContext != NULL && pCertContext->pCertInfo != NULL) {
            *version = pCertContext->pCertInfo->dwVersion;
            CertFreeCertificateContext(pCertContext);
        } else {
            lastError = OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND;
        }

        b = CertCloseStore(hSystemStore, 0);
        if (!b) {
            lastError = OPENSIGN_ERROR_NONE;
        }
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
    }
    return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}

int getCertificateSerialNumber(BYTE* certificate,
                               DWORD certificate_length,
                               CRYPT_INTEGER_BLOB* blSerialNumber) {

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    lastError = OPENSIGN_ERROR_NONE;

    if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My"
                                    )) {

        pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

        if (pCertContext != NULL && pCertContext->pCertInfo != NULL) {
            //*blSerialNumber = pCertContext->pCertInfo->SerialNumber;
            blSerialNumber->pbData = (BYTE*)malloc(sizeof(BYTE) * (pCertContext->pCertInfo->SerialNumber.cbData));
            memcpy(blSerialNumber->pbData, pCertContext->pCertInfo->SerialNumber.pbData, pCertContext->pCertInfo->SerialNumber.cbData);
            blSerialNumber->cbData = pCertContext->pCertInfo->SerialNumber.cbData;
            CertFreeCertificateContext(pCertContext);
        } else {
            lastError = OPENSIGN_ERROR_CERTSTORE_CERTIFICATE_NOT_FOUND;
        }

        b = CertCloseStore(hSystemStore, 0);
        if (!b) {
            lastError = OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE;
        }
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
    }
    return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}

int getCertificateKeyUsage(BYTE* certificate,
                           DWORD certificate_length,
                           BYTE* keyusage) {

    BOOL b;
    HCERTSTORE hSystemStore = 0;
    PCCERT_CONTEXT pCertContext = NULL;

    if (hSystemStore = CertOpenStore((LPCSTR)CERT_STORE_PROV_SYSTEM,
                                     0,
                                     0,
                                     CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER,
                                     L"My"
                                    )) {

        pCertContext = locateCertificate(hSystemStore, certificate, certificate_length);

        if (pCertContext) {
            BYTE keyUsage[2];
            if (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        pCertContext->pCertInfo,
                                        keyusage,
                                        2)) {
            } else {
                lastError = OPENSIGN_ERROR_KEYUSAGE_NOT_PRESENT;
            }
        }

        b = CertCloseStore(hSystemStore, 0);
        if (!b && lastError == OPENSIGN_ERROR_NONE) {
            lastError = OPENSIGN_ERROR_CERTSTORE_CLOSE_FAILURE;
        }
    } else {
        lastError = OPENSIGN_ERROR_CERTSTORE_OPEN_FAILURE;
    }
    return lastError == OPENSIGN_ERROR_NONE ? 0 : -1;
}


// Read a single cert from a file
HRESULT ReadCertFromFile(LPCWSTR pwzFileName, CERT_CONTEXT** ppCert, HCRYPTPROV* phCryptProv)
{
    BOOL bRet = FALSE;
    FILE* pFile = NULL;
    errno_t err;

    // open cert file for local cert
    err = _wfopen_s(&pFile, pwzFileName, L"rb");
    if (err)
    {
        return CRYPT_E_FILE_ERROR;
    }

    const DWORD SIXTYFOUR_K = 64 * 1024;
    BYTE s_fileBuf[SIXTYFOUR_K] = { 0 };
    
    // read local cert into *ppLocalCert, allocating memory
    fread(s_fileBuf, sizeof(s_fileBuf), 1, pFile);
    fclose(pFile);

    CRYPT_DATA_BLOB blob;
    blob.cbData = sizeof(s_fileBuf);
    blob.pbData = s_fileBuf;
    HCERTSTORE hCertStore = PFXImportCertStore(&blob, L"DRT Rocks!", CRYPT_EXPORTABLE);
    if (NULL == hCertStore)
        return HRESULT_FROM_WIN32(GetLastError());

    // TODO: does this have to be a c style cast? I get compile errors if I try reinterpret or static cast
    // the first cert is always the leaf cert (since we encoded it that way)
    CERT_CONTEXT* pCertContext = (CERT_CONTEXT*)CertEnumCertificatesInStore(hCertStore, NULL);
    if (NULL == pCertContext)
        return HRESULT_FROM_WIN32(GetLastError());

    // retreive the crypt provider which has the private key for this certificate
    DWORD dwKeySpec = 0;
    HCRYPTPROV hCryptProv = NULL;
    bRet = CryptAcquireCertificatePrivateKey(pCertContext,
        CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
        NULL, &hCryptProv, &dwKeySpec, NULL);
    if (!bRet)
        return HRESULT_FROM_WIN32(GetLastError());

    // make sure provider stays around for duration of the test run. We need hCryptProv of root cert to sign local certs
    CryptContextAddRef(hCryptProv, NULL, 0);

    // everything succeeded, safe to set outparam
    *ppCert = pCertContext;
    if (NULL != phCryptProv)
        *phCryptProv = hCryptProv;

    return S_OK;
}



#pragma once

#include <openssl/ossl_typ.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KeyStore_st KeyStore;

void KeyStoreFree(KeyStore* ks);

size_t KeyStoreKeyNum(const KeyStore* ks);
size_t KeyStoreCertNum(const KeyStore* ks);

const EVP_PKEY* KeyStoreGetKey(const KeyStore* ks, size_t pos);
const X509* KeyStoreGetCert(const KeyStore* ks, size_t pos);

#ifdef __cplusplus
}
#endif

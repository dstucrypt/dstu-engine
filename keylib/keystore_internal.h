#pragma once

#include "keystore.h"

#ifdef __cplusplus
extern "C" {
#endif

KeyStore* KeyStoreNew(size_t keyNum, size_t certNum);

void KeyStoreSetKey(KeyStore* ks, size_t pos, EVP_PKEY* key);
void KeyStoreSetCert(KeyStore* ks, size_t pos, X509* cert);

#ifdef __cplusplus
}
#endif

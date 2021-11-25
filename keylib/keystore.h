#pragma once

/** @file keystore.h
 *  @brief KeyStore is a container for keys and certificates.
 */

#include <openssl/ossl_typ.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @typedef KeyStore
 *  @brief KeyStore container handle. It owns all keys and certificates inside.
 */
typedef struct KeyStore_st KeyStore;

/** @fn void KeyStoreFree(KeyStore* ks)
 *  @brief destroys KeyStore data.
 *  @param ks KeyStore handle;
 */
void KeyStoreFree(KeyStore* ks);

/** @fn size_t KeyStoreKeyNum(const KeyStore* ks)
 *  @brief returns a number of entries for keys allocated inside the KeyStore.
 *  @param ks KeyStore handle.
 *  @return the number of key entries in the store.
 */
size_t KeyStoreKeyNum(const KeyStore* ks);

/** @fn size_t KeyStoreCertNum(const KeyStore* ks)
 *  @brief returns a number of entries for certificates allocated inside the KeyStore.
 *  @param ks KeyStore handle.
 *  @return the number of cert entries in the store.
 */
size_t KeyStoreCertNum(const KeyStore* ks);

/** @fn const EVP_PKEY* KeyStoreGetKey(const KeyStore* ks, size_t pos)
 *  @brief returns a pointer to the key entry number 'pos'. The first entry is 0.
 *  @param ks KeyStore handle;
 *  @param pos key entry number starting from 0.
 *  @return the pointer to the key entry.
 */
const EVP_PKEY* KeyStoreGetKey(const KeyStore* ks, size_t pos);

/** @fn const X509* KeyStoreGetCert(const KeyStore* ks, size_t pos)
 *  @brief returns a pointer to the cert entry number 'pos'. The first entry is 0.
 *  @param ks KeyStore handle;
 *  @param pos cert entry number starting from 0.
 *  @return the pointer to the cert entry.
 */
const X509* KeyStoreGetCert(const KeyStore* ks, size_t pos);

#ifdef __cplusplus
}
#endif

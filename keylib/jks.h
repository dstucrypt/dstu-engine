#pragma once

/** @file jks.h
 *  @brief Functions for reading keys from Java Key Storage.
 */

#include "keystore.h"

#include <openssl/ossl_typ.h>

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @fn int parseJKS(const void* data, size_t size, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store.
 *  @param data container data;
 *  @param size container data size;
 *  @param storagePass container password;
 *  @param storagePassSize container password size;
 *  @param keyPass key password;
 *  @param keyPassSize key password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int parseJKS(const void* data, size_t size, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks);

/** @fn int readJKS(FILE* fp, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store file.
 *  @param fp file handle;
 *  @param storagePass container password;
 *  @param storagePassSize container password size;
 *  @param keyPass key password;
 *  @param keyPassSize key password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int readJKS(FILE* fp, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks);

/** @fn int readJKS_bio(BIO* bio, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store using OpenSSL BIO interface.
 *  @param bio OpenSSL BIO;
 *  @param storagePass container password;
 *  @param storagePassSize container password size;
 *  @param keyPass key password;
 *  @param keyPassSize key password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int readJKS_bio(BIO* bio, const char* storagePass, size_t storagePassSize, const char* keyPass, size_t keyPassSize, KeyStore** ks);

#ifdef __cplusplus
}
#endif

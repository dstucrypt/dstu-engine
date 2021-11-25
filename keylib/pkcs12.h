#pragma once

/** @file pkcs12.h
 *  @brief Functions for reading keys from PKCS#12 container.
 */

#include "keystore.h"

#include <openssl/ossl_typ.h>

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @fn int parsePKCS12(const void* data, size_t size, const char* password, size_t passSize, KeyStore** ks)
 *  @brief extracts private keys from PKCS#12 container.
 *  @param data container data;
 *  @param size container data size;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int parsePKCS12(const void* data, size_t dataSize, const char* password, size_t passSize, KeyStore** ks);

/** @fn int readPKCS12(FILE* fp, const char* password, size_t passSize, KeyStore** ks)
 *  @brief extracts private keys from PKCS#12 container.
 *  @param fp file handle;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int readPKCS12(FILE* fp, const char* password, size_t passSize, KeyStore** ks);

/** @fn int readPKCS12_bio(BIO* bio, const char* password, size_t passSize, KeyStore** ks)
 *  @brief extracts private keys from PKCS#12 container.
 *  @param bio OpenSSL BIO;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param ks KeyStore pointer outparam.
 *  @return 1 for success, 0 in case of failure.
 */
int readPKCS12_bio(BIO* bio, const char* password, size_t passSize, KeyStore** ks);

#ifdef __cplusplus
}
#endif

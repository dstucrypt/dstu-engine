#pragma once

/** @file key6.h
 *  @brief Functions for reading keys from IIT Key-6.dat container.
 */

#include <openssl/evp.h>
#include <openssl/bio.h>

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @fn int parseKey6(const void* data, size_t size, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
 *  @brief extracts private keys from IIT Key-6.dat container.
 *  @param data container data;
 *  @param size container data size;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param keys a pointer to an array of EVP_PKEY pointers, extracted keys will be stored here;
 *  @param numKeys a number of extracted keys (usually 1 or 2).
 *  @return 1 for success, 0 in case of failure.
 */
int parseKey6(const void* data, size_t size, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys);

/** @fn int readKey6(FILE* fp, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
 *  @brief extracts private keys from IIT Key-6.dat container.
 *  @param fp file handle;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param keys a pointer to an array of EVP_PKEY pointers, extracted keys will be stored here;
 *  @param numKeys a number of extracted keys (usually 1 or 2).
 *  @return 1 for success, 0 in case of failure.
 */
int readKey6(FILE* fp, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys);

/** @fn int readKey6_bio(BIO* bio, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys)
 *  @brief extracts private keys from IIT Key-6.dat container.
 *  @param bio OpenSSL BIO;
 *  @param password container encryption password;
 *  @param passSize password size;
 *  @param keys a pointer to an array of EVP_PKEY pointers, extracted keys will be stored here;
 *  @param numKeys a number of extracted keys (usually 1 or 2).
 *  @return 1 for success, 0 in case of failure.
 */
int readKey6_bio(BIO* bio, const char* password, size_t passSize, EVP_PKEY*** keys, size_t* numKeys);

#ifdef __cplusplus
}
#endif

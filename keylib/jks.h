#pragma once

/** @file jks.h
 *  @brief Functions for reading keys from Java Key Storage.
 */

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @typedef JKS
 *  @brief JKS container handle.
 */
typedef struct jks_st JKS;
/** @typedef JKSEntry
 *  @brief an element of a JKS container.
 */
typedef struct jks_entry_st JKSEntry;

/** @fn void JKSFree(JKS* jks)
 *  @brief destroys JKS data.
 *  @param jks JKS data;
 */
void JKSFree(JKS* jks);

/** @def JKS_TYPE_JKS
 *  @brief JKS in the original format.
 */
#define JKS_TYPE_JKS 0
/** @def JKS_TYPE_JCEKS
 *  @brief JKS in the improved fromat.
 */
#define JKS_TYPE_JCEKS 1

/** @fn size_t JKSType(const JKS* jks)
 *  @brief returns JKS type.
 *  @param jks JKS data.
 *  @return the type of JKS. JKS_TYPE_JKS - original keystore format, JKS_TYPE_JCEKS - improved format.
 */
size_t JKSType(const JKS* jks);

/** @fn size_t JKSEntryNum(const JKS* jks)
 *  @brief returns a number of JKS entries.
 *  @param jks JKS data.
 *  @return the number of entries in the store.
 */
size_t JKSEntryNum(const JKS* jks);
/** @fn JKSEntry JKSEntryGet(const JKS* jks, size_t pos)
 *  @brief returns a pointer to the entry number 'pos'. The first entry is 0.
 *  @param jks JKS data;
 *  @param pos entry number starting from 0.
 *  @return the pointer to the entry.
 */
JKSEntry* JKSEntryGet(const JKS* jks, size_t pos);

/** @def JKS_ENTRY_PRIVATE_KEY
 *  @brief private key JKS entry.
 */
#define JKS_ENTRY_PRIVATE_KEY 1
/** @def JKS_ENTRY_CERT
 *  @brief certificate JKS entry.
 */
#define JKS_ENTRY_CERT 2

/** @fn size_t JKSEntryType(const JKSEntry* entry)
 *  @brief returns JKS entry type.
 *  @param entry a pointer to the JKS entry.
 *  @return the type of the entry. JKS_ENTRY_PRIVATE_KEY - private key material, JKS_ENTRY_CERT - certificate.
 */
size_t JKSEntryType(const JKSEntry* entry);

/** @fn int JKSEntryDecrypt(JKSEntry* entry, const char* password, size_t passSize)
 *  @brief decrypts an entry with private key material. Does nothig for other entry types.
 *  @param entry a pointer to the JKS entry;
 *  @param password private key encryption password;
 *  @param passSize password size.
 *  @return 1 for success, 0 in case of failure.
 */
int JKSEntryDecrypt(JKSEntry* entry, const char* password, size_t passSize);

/** @fn const char* JKSEntryPKeyName(const JKSEntry* entry)
 *  @brief returns an alias of a private key. Returns NULL for other entry types.
 *  @param entry a pointer to the JKS entry.
 *  @return the alias of the private key or NULL.
 */
const char* JKSEntryPKeyName(const JKSEntry* entry);
/** @fn size_t JKSEntryPKeyNum(const JKSEntry* entry)
 *  @brief returns a number of private keys in this entry.
 *  @param entry a pointer to the JKS entry.
 *  @return the number of private keys.
 *  @note the entry must be decrypted first. Otherwise, the function returns 0.
 */
size_t JKSEntryPKeyNum(const JKSEntry* entry);
/** @fn const EVP_PKEY* JKSEntryPKey(const JKSEntry* entry, size_t pos)
 *  @brief returns a pointer to an EVP_PKEY number 'pos'.
 *  @param entry a pointer to the JKS entry;
 *  @param pos EVP_PKEY number, starting from 0.
 *  @return the pointer to the EVP_PKEY.
 *  @note the entry must be decrypted first. Otherwise, the function returns NULL.
 */
const EVP_PKEY* JKSEntryPKey(const JKSEntry* entry, size_t pos);

/** @fn size_t JKSEntryCertNum(const JKSEntry* entry)
 *  @brief returns a number of certificates in this entry.
 *  @param entry a pointer to the JKS entry.
 *  @return the number of certificates.
 */
size_t JKSEntryCertNum(const JKSEntry* entry);
/** @fn const X509* JKSEntryCert(const JKSEntry* entry, size_t pos)
 *  @brief returns a pointer to a certificate number 'pos'.
 *  @param entry a pointer to the JKS entry;
 *  @param pos certificate number, starting from 0.
 *  @return the pointer to the certificate.
 */
const X509* JKSEntryCert(const JKSEntry* entry, size_t pos);
/** @fn const char* JKSEntryCertType(const JKSEntry* entry, size_t pos)
 *  @brief returns a type of a certificate number 'pos'.
 *  @param entry a pointer to the JKS entry;
 *  @param pos certificate number, starting from 0.
 *  @return the type of the certificate. Usually 'X509'.
 */
const char* JKSEntryCertType(const JKSEntry* entry, size_t pos);

/** @fn int parseJKS(const void* data, size_t size, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store.
 *  @param data container data;
 *  @param size container data size;
 *  @param password container password;
 *  @param passSize password size;
 *  @param keys JKS handle, extracted keys will be stored here.
 *  @return 1 for success, 0 in case of failure.
 */
int parseJKS(const void* data, size_t size, const char* password, size_t passSize, JKS** keys);

/** @fn int readJKS(FILE* fp, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store file.
 *  @param fp file handle;
 *  @param password container password;
 *  @param passSize password size;
 *  @param keys JKS handle, extracted keys will be stored here.
 *  @return 1 for success, 0 in case of failure.
 */
int readJKS(FILE* fp, const char* password, size_t passSize, JKS** keys);

/** @fn int readJKS_bio(BIO* bio, const char* password, size_t passSize, JKS** keys)
 *  @brief extracts private keys and certs from Java Key Store using OpenSSL BIO interface.
 *  @param bio OpenSSL BIO;
 *  @param password container password;
 *  @param passSize password size;
 *  @param keys JKS handle, extracted keys will be stored here.
 *  @return 1 for success, 0 in case of failure.
 */
int readJKS_bio(BIO* bio, const char* password, size_t passSize, JKS** keys);

#ifdef __cplusplus
}
#endif

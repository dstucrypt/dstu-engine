#pragma once

#include "keystore.h"

#include <openssl/ossl_typ.h>

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int parsePKCS12(const void* data, size_t dataSize, const char* password, size_t passSize, KeyStore** ks);
int readPKCS12(FILE* fp, const char* password, size_t passSize, KeyStore** ks);
int readPKCS12_bio(BIO* bio, const char* password, size_t passSize, KeyStore** ks);

#ifdef __cplusplus
}
#endif

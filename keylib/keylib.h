#pragma once

#include <openssl/evp.h>
#include <openssl/bio.h>

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int parseKey6(const void* data, size_t size, const char* password, size_t passSize, EVP_PKEY** keys, size_t* numKeys);
int readKey6(FILE* fp, const char* password, size_t passSize, EVP_PKEY** keys, size_t* numKeys);
int readKey6_bio(BIO* bio, const char* password, size_t passSize, EVP_PKEY** keys, size_t* numKeys);

#ifdef __cplusplus
}
#endif

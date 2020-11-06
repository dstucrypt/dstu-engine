#pragma once

#include <openssl/evp.h>

EVP_CIPHER *dstu_cipher_new();
void dstu_cipher_free(EVP_CIPHER *cipher);

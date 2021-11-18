#pragma once

#include <openssl/ossl_typ.h>

EVP_CIPHER *dstu_cipher_new();
void dstu_cipher_free(EVP_CIPHER *cipher);

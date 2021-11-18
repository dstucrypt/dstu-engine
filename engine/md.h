#pragma once

#include <openssl/ossl_typ.h>

EVP_MD *dstu_digest_new();
void dstu_digest_free(EVP_MD *digest);

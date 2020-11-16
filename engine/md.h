#pragma once

#include <openssl/evp.h>

EVP_MD *dstu_digest_new();
void dstu_digest_free(EVP_MD *digest);

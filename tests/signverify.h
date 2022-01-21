#pragma once

#include "keystore.h"

#include <openssl/ossl_typ.h>

#include <string>
#include <vector>

namespace DSTUEngine
{

void testSignVerify(ENGINE* engine, const KeyStore* ks, const void* data, size_t size);
void testSignVerify(ENGINE* engine, EVP_PKEY* pub, EVP_PKEY* priv, const void* data, size_t size);
void testVerify(ENGINE* engine, EVP_PKEY* pub, const std::string& signature, const void* data, size_t size);

}

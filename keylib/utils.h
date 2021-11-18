#pragma once

#include <openssl/ossl_typ.h>

#include <stddef.h>

int keysFromPKCS8(const void* data, size_t size, EVP_PKEY*** keys, size_t* numKeys);

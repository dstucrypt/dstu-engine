#pragma once

#include <openssl/evp.h>

#include <stddef.h>

int keysFromPKCS8(const void* data, size_t size, EVP_PKEY*** keys, size_t* numKeys);

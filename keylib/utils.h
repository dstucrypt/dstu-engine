#pragma once

#include "keystore.h"

#include <openssl/ossl_typ.h>

#include <stddef.h>

int keysFromPKCS8(const void* data, size_t size, KeyStore** ks);

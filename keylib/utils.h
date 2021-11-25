#pragma once

#include "keystore.h"

#include <stddef.h>

int keysFromPKCS8(const void* data, size_t size, KeyStore** ks);

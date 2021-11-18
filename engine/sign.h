#pragma once

#include <openssl/ossl_typ.h>

#include <stddef.h>

int dstu_do_sign(const EC_KEY *key, const unsigned char *tbs, size_t tbslen,
                 unsigned char *sig);
int dstu_do_verify(const EC_KEY *key, const unsigned char *tbs, size_t tbslen,
                   const unsigned char *sig, size_t siglen);

#pragma once

#include <openssl/ossl_typ.h>

EVP_PKEY_METHOD *dstu_pkey_meth_new(int nid);
void dstu_pkey_meth_free(EVP_PKEY_METHOD *method);

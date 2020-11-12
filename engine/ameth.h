#pragma once

#include <openssl/evp.h>

EVP_PKEY_ASN1_METHOD *dstu_asn1_meth_new(int nid);
void dstu_asn1_meth_free(EVP_PKEY_ASN1_METHOD *method);

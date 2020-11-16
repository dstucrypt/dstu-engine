#pragma once

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct IITParams_st
{
    ASN1_OCTET_STRING* mac;
    ASN1_OCTET_STRING* pad;
} IITParams;

typedef struct IITHeader_st
{
    ASN1_OBJECT* type;
    IITParams* params;
} IITHeader;

typedef struct IITStore_st
{
    IITHeader* header;
    ASN1_OCTET_STRING* data;
} IITStore;

DECLARE_ASN1_FUNCTIONS(IITStore)

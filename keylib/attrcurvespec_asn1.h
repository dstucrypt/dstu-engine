#pragma once

#include "asn1.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct DSTU_AttrCurveSpec_st
{
    DSTU_CustomCurveSpec* spec;
    ASN1_OCTET_STRING* dke;
    ASN1_OCTET_STRING* dke1;
} DSTU_AttrCurveSpec;

DECLARE_ASN1_FUNCTIONS(DSTU_AttrCurveSpec)
DECLARE_ASN1_PRINT_FUNCTION(DSTU_AttrCurveSpec)

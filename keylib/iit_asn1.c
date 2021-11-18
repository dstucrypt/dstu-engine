#include "iit_asn1.h"

#include <openssl/asn1t.h>

ASN1_SEQUENCE(IITParams) =
{
    ASN1_SIMPLE(IITParams, mac, ASN1_OCTET_STRING),
    ASN1_OPT(IITParams, pad, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(IITParams)

ASN1_SEQUENCE(IITHeader) =
{
    ASN1_SIMPLE(IITHeader, type, ASN1_OBJECT),
    ASN1_SIMPLE(IITHeader, params, IITParams)
}ASN1_SEQUENCE_END(IITHeader)

ASN1_SEQUENCE(IITStore) =
{
    ASN1_SIMPLE(IITStore, header, IITHeader),
    ASN1_SIMPLE(IITStore, data, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(IITStore)

IMPLEMENT_ASN1_FUNCTIONS(IITStore)

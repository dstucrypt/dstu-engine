#include "attrcurvespec_asn1.h"

ASN1_SEQUENCE(DSTU_AttrCurveSpec) =
{
    ASN1_SIMPLE(DSTU_AttrCurveSpec, spec, DSTU_CustomCurveSpec),
    ASN1_SIMPLE(DSTU_AttrCurveSpec, dke,  ASN1_OCTET_STRING),
    ASN1_SIMPLE(DSTU_AttrCurveSpec, dke1, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(DSTU_AttrCurveSpec)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_AttrCurveSpec)

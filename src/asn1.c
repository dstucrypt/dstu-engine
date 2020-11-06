/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */
#include "asn1.h"

ASN1_SEQUENCE(DSTU_Pentanomial) =
{
    ASN1_SIMPLE(DSTU_Pentanomial, k, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_Pentanomial, j, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_Pentanomial, l, ASN1_INTEGER)
}ASN1_SEQUENCE_END(DSTU_Pentanomial)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_Pentanomial)

ASN1_CHOICE(DSTU_Polynomial) =
{
    ASN1_SIMPLE(DSTU_Polynomial, poly.k, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_Polynomial, poly.pentanomial, DSTU_Pentanomial)
}ASN1_CHOICE_END(DSTU_Polynomial)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_Polynomial)

ASN1_SEQUENCE(DSTU_BinaryField) =
{
    ASN1_SIMPLE(DSTU_BinaryField, m, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_BinaryField, poly, DSTU_Polynomial)
}ASN1_SEQUENCE_END(DSTU_BinaryField)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_BinaryField)

ASN1_SEQUENCE(DSTU_CustomCurveSpec) =
{
    ASN1_SIMPLE(DSTU_CustomCurveSpec, field, DSTU_BinaryField),
    ASN1_SIMPLE(DSTU_CustomCurveSpec, a, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_CustomCurveSpec, b, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DSTU_CustomCurveSpec, n, ASN1_INTEGER),
    ASN1_SIMPLE(DSTU_CustomCurveSpec, bp, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(DSTU_CustomCurveSpec)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_CustomCurveSpec)

ASN1_CHOICE(DSTU_CurveSpec) =
{
    ASN1_SIMPLE(DSTU_CurveSpec, curve.named_curve, ASN1_OBJECT),
    ASN1_SIMPLE(DSTU_CurveSpec, curve.custom_curve, DSTU_CustomCurveSpec)
}ASN1_CHOICE_END(DSTU_CurveSpec)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_CurveSpec)

ASN1_SEQUENCE(DSTU_AlgorithmParameters) =
{
    ASN1_SIMPLE(DSTU_AlgorithmParameters, curve, DSTU_CurveSpec),
    ASN1_OPT(DSTU_AlgorithmParameters, sbox, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(DSTU_AlgorithmParameters)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_AlgorithmParameters)

ASN1_SEQUENCE(DSTU_Gost28147Parameters) =
{
    ASN1_SIMPLE(DSTU_Gost28147Parameters, iv, ASN1_OCTET_STRING),
    ASN1_SIMPLE(DSTU_Gost28147Parameters, dke, ASN1_OCTET_STRING)
}ASN1_SEQUENCE_END(DSTU_Gost28147Parameters)

IMPLEMENT_ASN1_FUNCTIONS(DSTU_Gost28147Parameters)

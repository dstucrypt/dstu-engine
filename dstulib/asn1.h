/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#ifndef DSTU_ASN1_H_
#define DSTU_ASN1_H_

#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>

typedef struct DSTU_Pentanomial_st
{
    ASN1_INTEGER *k;
    ASN1_INTEGER *j;
    ASN1_INTEGER *l;
} DSTU_Pentanomial;

DECLARE_ASN1_FUNCTIONS(DSTU_Pentanomial)

typedef struct DSTU_Polynomial_st
{

#define DSTU_TRINOMIAL 0
#define DSTU_PENTANOMIAL 1

    int type;
    union
    {
        ASN1_INTEGER *k;
        DSTU_Pentanomial *pentanomial;
    } poly;
} DSTU_Polynomial;

DECLARE_ASN1_FUNCTIONS(DSTU_Polynomial)

typedef struct DSTU_BinaryField_st
{
    ASN1_INTEGER *m;
    DSTU_Polynomial *poly;
} DSTU_BinaryField;

DECLARE_ASN1_FUNCTIONS(DSTU_BinaryField)

typedef struct DSTU_CustomCurveSpec_st
{
    DSTU_BinaryField *field;
    ASN1_INTEGER *a;
    ASN1_OCTET_STRING *b;
    ASN1_INTEGER *n;
    ASN1_OCTET_STRING *bp;
} DSTU_CustomCurveSpec;

DECLARE_ASN1_FUNCTIONS(DSTU_CustomCurveSpec)

typedef struct DSTU_CurveSpec_st
{

#define DSTU_STANDARD_CURVE 0
#define DSTU_CUSTOM_CURVE 1

    int type;
    union
    {
        ASN1_OBJECT *named_curve;
        DSTU_CustomCurveSpec *custom_curve;
    } curve;
} DSTU_CurveSpec;

DECLARE_ASN1_FUNCTIONS(DSTU_CurveSpec)

typedef struct DSTU_AlgorithmParameters_st
{
    DSTU_CurveSpec *curve;
    ASN1_OCTET_STRING *sbox;
} DSTU_AlgorithmParameters;

DECLARE_ASN1_FUNCTIONS(DSTU_AlgorithmParameters)

typedef struct DSTU_Gost28147Parameters_st
{
    ASN1_OCTET_STRING *iv;
    ASN1_OCTET_STRING *dke;
} DSTU_Gost28147Parameters;

DECLARE_ASN1_FUNCTIONS(DSTU_Gost28147Parameters)

#endif /* DSTU_ASN1_H_ */

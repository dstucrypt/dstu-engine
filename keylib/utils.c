#include "utils.h"

#include "keystore_internal.h"

#include "attrcurvespec_asn1.h"

#include "asn1.h"
#include "compress.h"
#include "key.h"
#include "params.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>

static const char dstu4145CurveOID[] = "1.3.6.1.4.1.19398.1.1.2.2";
static const char dstu4145KeyOID[] = "1.3.6.1.4.1.19398.1.1.2.3";

static BIGNUM* getPrivateKeyNum(BN_CTX* ctx, X509_ATTRIBUTE* attr)
{
    int count = X509_ATTRIBUTE_count(attr);
    int i = 0;
    int type = 0;
    int length;
    ASN1_STRING* str = NULL;
    unsigned char b = 0;
    const unsigned char* data = NULL;
    unsigned char* buf = NULL;
    BIGNUM* res = NULL;

    if (count < 1)
        return NULL;
    for (i = 0; i < count; ++i)
    {
        type = ASN1_TYPE_get(X509_ATTRIBUTE_get0_type(attr, i));
        if (type != V_ASN1_OCTET_STRING && type != V_ASN1_BIT_STRING)
            continue;
        str = X509_ATTRIBUTE_get0_data(attr, i, type, NULL);
        if (str != NULL)
            break;
    }
    if (str == NULL)
        return NULL;
    length = ASN1_STRING_length(str);
    data = ASN1_STRING_get0_data(str);
    buf = OPENSSL_malloc(length);
    for (i = 0; i < length; ++i)
    {
        // Swap bits
        b = data[i];
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        // Swap bytes
        buf[length - i - 1] = b;
    }

    res = BN_bin2bn(buf,length, BN_CTX_get(ctx));

    OPENSSL_clear_free(buf, length);

    return res;
}

static BIGNUM* makePoly(BN_CTX* ctx, const DSTU_BinaryField* field)
{
    BIGNUM* res = BN_CTX_get(ctx);
    int poly[6];
    poly[0] = ASN1_INTEGER_get(field->m);
    if (field->poly->type == 0)
    {
        // Trinominal
        poly[1] = ASN1_INTEGER_get(field->poly->poly.k);
        poly[2] = 0;
        poly[3] = -1;
    }
    else
    {
        // Pentanominal
        poly[1] = ASN1_INTEGER_get(field->poly->poly.pentanomial->k);
        poly[2] = ASN1_INTEGER_get(field->poly->poly.pentanomial->j);
        poly[3] = ASN1_INTEGER_get(field->poly->poly.pentanomial->l);
        poly[4] = 0;
        poly[5] = -1;
    }
    if (BN_GF2m_arr2poly(poly, res) == 0)
        return NULL;
    return res;
}

static EC_POINT* makePoint(BN_CTX* ctx, const EC_GROUP* group, const ASN1_OCTET_STRING* p)
{
    (void) ctx;
    EC_POINT* res = EC_POINT_new(group);
    if (dstu_point_expand(ASN1_STRING_get0_data(p), ASN1_STRING_length(p), group, res) == 0)
    {
        EC_POINT_free(res);
        return NULL;
    }
    return res;
}

static EC_GROUP* makeECGROUPFromSpec(BN_CTX* ctx, const DSTU_CustomCurveSpec* spec)
{
    BIGNUM* poly = makePoly(ctx, spec->field);
    BIGNUM* a = BN_CTX_get(ctx);
    BIGNUM* b = BN_bin2bn(ASN1_STRING_get0_data(spec->b), ASN1_STRING_length(spec->b), BN_CTX_get(ctx));
    BIGNUM* n = BN_CTX_get(ctx);
    EC_POINT* point = NULL;
    EC_GROUP* res = EC_GROUP_new_curve_GF2m(poly, a, b, ctx);

    if (res == NULL)
        return NULL;

    ASN1_INTEGER_to_BN(spec->a, a);

    point = makePoint(ctx, res, spec->bp);
    if (point == NULL)
    {
        EC_GROUP_free(res);
        return NULL;
    }
    if (EC_POINT_is_on_curve(res, point, ctx) == 0)
    {
        EC_POINT_free(point);
        EC_GROUP_free(res);
        return NULL;
    }
    ASN1_INTEGER_to_BN(spec->n, n);
    if (EC_GROUP_set_generator(res, point, n, BN_value_one()) == 0)
    {
        EC_GROUP_free(res);
        res = NULL;
    }
    EC_POINT_free(point);
    return res;
}

static EC_GROUP* makeECGROUP(BN_CTX* ctx, X509_ATTRIBUTE* attr)
{
    DSTU_AttrCurveSpec* spec = NULL;
    int count = X509_ATTRIBUTE_count(attr);
    int i = 0;
    EC_GROUP* res = NULL;

    if (count < 1)
        return NULL;

    for (i = 0; i < count; ++i)
    {
        spec = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(DSTU_AttrCurveSpec), X509_ATTRIBUTE_get0_type(attr, i));
        if (spec != NULL)
            break;
    }

    if (spec == NULL)
        return NULL;

    res = makeECGROUPFromSpec(ctx, spec->spec);
    DSTU_AttrCurveSpec_free(spec);
    return res;
}

static EVP_PKEY* makePKey(X509_ATTRIBUTE* curveAttr, X509_ATTRIBUTE* keyAttr)
{
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = NULL;
    BIGNUM* pkNum = NULL;
    DSTU_KEY* key = NULL;
    EVP_PKEY* res = NULL;

    BN_CTX_start(ctx);

    pkNum = getPrivateKeyNum(ctx, keyAttr);
    group = makeECGROUP(ctx, curveAttr);
    if (pkNum == NULL || group == NULL)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
    }
    key = DSTU_KEY_new();
    if (key == NULL)
    {
        EC_GROUP_free(group);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
    }

    res = EVP_PKEY_new();

    if (res == NULL ||
        EC_KEY_set_group(key->ec, group) == 0 ||
        EC_KEY_set_private_key(key->ec, pkNum) == 0 ||
        dstu_add_public_key(key->ec) == 0)
    {
        DSTU_KEY_free(key);
        EC_GROUP_free(group);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_set_type(res, NID_dstu4145le) == 0 ||
        EVP_PKEY_assign(res, EVP_PKEY_id(res), key) == 0)
    {
        DSTU_KEY_free(key);
        EVP_PKEY_free(res);
        res = NULL;
    }

    EC_GROUP_free(group);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return res;
}

static EVP_PKEY* pkeyFromAttributes(const PKCS8_PRIV_KEY_INFO* pkcs8)
{
    const STACK_OF(X509_ATTRIBUTE)* attributes = PKCS8_pkey_get0_attrs(pkcs8);
    X509_ATTRIBUTE* curveAttr = NULL;
    X509_ATTRIBUTE* keyAttr = NULL;
    X509_ATTRIBUTE* attr = NULL;
    ASN1_OBJECT* dstu4145Curve = OBJ_txt2obj(dstu4145CurveOID, 1);
    ASN1_OBJECT* dstu4145Key = OBJ_txt2obj(dstu4145KeyOID, 1);
    ASN1_OBJECT* attrObject = NULL;
    EVP_PKEY* res = NULL;
    int nattr = sk_X509_ATTRIBUTE_num(attributes);
    int i = 0;

    for (i = 0; i < nattr; ++i)
    {
        attr = sk_X509_ATTRIBUTE_value(attributes, i);
        if (attr == NULL)
            continue;
        attrObject = X509_ATTRIBUTE_get0_object(attr);
        if (attrObject == NULL)
            continue;
        if (OBJ_cmp(attrObject, dstu4145Curve) == 0)
            curveAttr = attr;
        else if (OBJ_cmp(attrObject, dstu4145Key) == 0)
            keyAttr = attr;
    }

    ASN1_OBJECT_free(dstu4145Key);
    ASN1_OBJECT_free(dstu4145Curve);

    if (curveAttr == NULL || keyAttr == NULL)
        return NULL;

    res = makePKey(curveAttr, keyAttr);
    return res;
}

int keysFromPKCS8(const void* data, size_t size, KeyStore** ks)
{
    const unsigned char* ptr = data;
    PKCS8_PRIV_KEY_INFO* pkcs8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &ptr, size);
    EVP_PKEY* pkey1 = NULL;
    EVP_PKEY* pkey2 = NULL;

    if (pkcs8 == NULL)
        return 0;

    pkey1 = EVP_PKCS82PKEY(pkcs8);
    if (pkey1 == NULL)
    {
        PKCS8_PRIV_KEY_INFO_free(pkcs8);
        return 0;
    }
    pkey2 = pkeyFromAttributes(pkcs8);
    PKCS8_PRIV_KEY_INFO_free(pkcs8);

    if (pkey2 == NULL)
    {
        *ks = KeyStoreNew(1, 0);
        KeyStoreSetKey(*ks, 0, pkey1);
        return 1;
    }

    *ks = KeyStoreNew(2, 0);
    KeyStoreSetKey(*ks, 0, pkey1);
    KeyStoreSetKey(*ks, 1, pkey2);

    return 1;
}

/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "key.h"
#include "asn1.h"
#include "compress.h"
#include "params.h"

#include <openssl/objects.h>

#include <string.h>

DSTU_KEY *DSTU_KEY_new(void)
{
    DSTU_KEY *key = OPENSSL_malloc(sizeof(DSTU_KEY));

    if (!key)
        return NULL;

    key->ec = EC_KEY_new();
    if (!(key->ec))
    {
        OPENSSL_free(key);
        return NULL;
    }

    key->sbox = NULL;
    return key;
}

void DSTU_KEY_set(DSTU_KEY *key, EC_KEY *ec, unsigned char *sbox)
{
    if (ec)
    {
        if (key->ec)
            EC_KEY_free(key->ec);
        key->ec = ec;
    }

    if (sbox)
    {
        if (key->sbox)
            OPENSSL_free(key->sbox);
        key->sbox = sbox;
    }
}

void DSTU_KEY_free(DSTU_KEY *key)
{
    if (!key)
        return;

    if (key->sbox)
        OPENSSL_free(key->sbox);
    if (key->ec)
        EC_KEY_free(key->ec);
    OPENSSL_free(key);
}

DSTU_AlgorithmParameters *asn1_from_key(const DSTU_KEY *key,
                                        int is_little_endian)
{
    DSTU_AlgorithmParameters *params = DSTU_AlgorithmParameters_new(), *ret = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key->ec);
    int curve_nid, poly[6], field_size;
    BN_CTX *ctx = NULL;
    const EC_POINT *g = NULL;
    BIGNUM *p, *a, *b, *n;
    unsigned char *compressed = NULL;

    if (!params || !group)
        return NULL;

    if (key->sbox)
    {
        if (!is_default_sbox(key->sbox))
        {
            params->sbox = ASN1_OCTET_STRING_new();
            if (!params->sbox)
                goto err;

            if (!ASN1_OCTET_STRING_set(params->sbox, key->sbox, sizeof(default_sbox)))
                goto err;
        }
    }

    /* Checking if group represents a standard curve. If we get NID_undef, that means the curve is custom */
    curve_nid = curve_nid_from_group(group);
    if (NID_undef == curve_nid)
    {
        /* Custom curve */
        params->curve->curve.custom_curve = DSTU_CustomCurveSpec_new();
        if (!params->curve->curve.custom_curve)
            goto err;
        params->curve->type = DSTU_CUSTOM_CURVE;

        g = EC_GROUP_get0_generator(group);
        if (!g)
            goto err;

        ctx = BN_CTX_new();
        BN_CTX_start(ctx);

        p = BN_CTX_get(ctx);
        a = BN_CTX_get(ctx);
        b = BN_CTX_get(ctx);
        n = BN_CTX_get(ctx);

        if (!n)
            goto err;

        if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx))
            goto err;

        if (!EC_GROUP_get_order(group, n, ctx))
            goto err;

        if (!BN_GF2m_poly2arr(p, poly, sizeof(poly) / sizeof(int)))
            goto err;

        if (!ASN1_INTEGER_set(params->curve->curve.custom_curve->field->m, poly[0]))
            goto err;

        if ((-1 == poly[3]) && (0 == poly[2]))
        {
            /* We have a trinomial */
            params->curve->curve.custom_curve->field->poly->poly.k = ASN1_INTEGER_new();
            if (!params->curve->curve.custom_curve->field->poly->poly.k)
                goto err;
            params->curve->curve.custom_curve->field->poly->type = DSTU_TRINOMIAL;
            if (!ASN1_INTEGER_set(params->curve->curve.custom_curve->field->poly->poly.k, poly[1]))
                goto err;
        }
        else if ((-1 == poly[5]) && (0 == poly[4]))
        {
            /* We have a pentanomial */
            params->curve->curve.custom_curve->field->poly->poly.pentanomial = DSTU_Pentanomial_new();
            if (!params->curve->curve.custom_curve->field->poly->poly.pentanomial)
                goto err;
            params->curve->curve.custom_curve->field->poly->type = DSTU_PENTANOMIAL;

            if (!ASN1_INTEGER_set(params->curve->curve.custom_curve->field->poly->poly.pentanomial->l, poly[1]))
                goto err;

            if (!ASN1_INTEGER_set(params->curve->curve.custom_curve->field->poly->poly.pentanomial->j, poly[2]))
                goto err;

            if (!ASN1_INTEGER_set(params->curve->curve.custom_curve->field->poly->poly.pentanomial->k, poly[3]))
                goto err;
        }
        else
            goto err;

        if (!BN_to_ASN1_INTEGER(a, params->curve->curve.custom_curve->a))
            goto err;

        if (!BN_to_ASN1_INTEGER(n, params->curve->curve.custom_curve->n))
            goto err;

        field_size = (poly[0] + 7) / 8;

        compressed = OPENSSL_malloc(field_size);
        if (!compressed)
            goto err;

        if (!bn_encode(b, compressed, field_size))
            goto err;

        if (is_little_endian)
            reverse_bytes(compressed, field_size);

        if (!ASN1_OCTET_STRING_set(params->curve->curve.custom_curve->b, compressed, field_size))
            goto err;

        if (!dstu_point_compress(group, g, compressed, field_size))
            goto err;

        if (is_little_endian)
            reverse_bytes(compressed, field_size);

        if (!ASN1_OCTET_STRING_set(params->curve->curve.custom_curve->bp, compressed, field_size))
            goto err;
    }
    else
    {
        /* Standard curve */
        params->curve->curve.named_curve = OBJ_nid2obj(curve_nid);
        if (!params->curve->curve.named_curve)
            goto err;
        params->curve->type = DSTU_STANDARD_CURVE;
    }

    ret = params;
    params = NULL;

    err:

    if (compressed)
        OPENSSL_free(compressed);

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (params)
        DSTU_AlgorithmParameters_free(params);

    return ret;
}

EC_GROUP *group_from_asn1(const DSTU_CustomCurveSpec* spec, int is_little_endian)
{
    BIGNUM *p, *a, *b, *N;
    EC_GROUP *ret = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *g = NULL;
    BN_CTX *ctx = NULL;
    int poly[6];
    unsigned char *reverse_buffer = NULL;

    poly[0] = ASN1_INTEGER_get(spec->field->m);
    if (poly[0] <= 0)
        goto err;

    if (DSTU_TRINOMIAL == spec->field->poly->type)
    {
        poly[1] = ASN1_INTEGER_get(spec->field->poly->poly.k);
        if (poly[1] <= 0)
            goto err;
        poly[2] = 0;
        poly[3] = -1;
    }
    else
    {
        poly[1] = ASN1_INTEGER_get(spec->field->poly->poly.pentanomial->l);
        if (poly[1] <= 0)
            goto err;

        poly[2] = ASN1_INTEGER_get(spec->field->poly->poly.pentanomial->j);
        if (poly[2] <= 0)
            goto err;

        poly[3] = ASN1_INTEGER_get(spec->field->poly->poly.pentanomial->k);
        if (poly[3] <= 0)
            goto err;

        poly[4] = 0;
        poly[5] = -1;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        goto err;

    BN_CTX_start(ctx);

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    N = BN_CTX_get(ctx);

    if (!N)
        goto err;

    if (!BN_GF2m_arr2poly(poly, p))
        goto err;

    if (!ASN1_INTEGER_to_BN(spec->a, a))
        goto err;

    if (!BN_is_one(a) && !BN_is_zero(a))
        goto err;

    if (is_little_endian)
    {
        reverse_buffer = OPENSSL_malloc(ASN1_STRING_length(spec->b));
        if (!reverse_buffer)
            goto err;

        reverse_bytes_copy(reverse_buffer,
                           ASN1_STRING_get0_data(spec->b),
                           ASN1_STRING_length(spec->b));

        if (!BN_bin2bn(reverse_buffer,
                       ASN1_STRING_length(spec->b),
                       b))
        {
            OPENSSL_free(reverse_buffer);
            goto err;
        }

        OPENSSL_free(reverse_buffer);
    }
    else
    {
        if (!BN_bin2bn(ASN1_STRING_get0_data(spec->b),
                       ASN1_STRING_length(spec->b),
                       b))
            goto err;
    }

    if (!ASN1_INTEGER_to_BN(spec->n, N))
        goto err;

    group = EC_GROUP_new_curve_GF2m(p, a, b, ctx);
    if (!group)
        goto err;

    g = EC_POINT_new(group);
    if (!g)
        goto err;

    if (is_little_endian)
    {
        reverse_buffer = OPENSSL_malloc(ASN1_STRING_length(spec->bp));
        if (!reverse_buffer)
            goto err;

        reverse_bytes_copy(reverse_buffer,
                           ASN1_STRING_get0_data(spec->bp),
                           ASN1_STRING_length(spec->bp));

        if (!dstu_point_expand(reverse_buffer,
                               ASN1_STRING_length(spec->bp),
                               group, g))
        {
            OPENSSL_free(reverse_buffer);
            goto err;
        }

        OPENSSL_free(reverse_buffer);
    }
    else
    {
        if (!dstu_point_expand(ASN1_STRING_get0_data(spec->bp),
                               ASN1_STRING_length(spec->bp),
                               group, g))
            goto err;
    }

    if (!EC_GROUP_set_generator(group, g, N, BN_value_one()))
        goto err;

    ret = group;
    group = NULL;

    err:

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (g)
        EC_POINT_free(g);

    if (group)
        EC_GROUP_free(group);

    return ret;
}

DSTU_KEY *key_from_asn1(const DSTU_AlgorithmParameters *params,
                        int is_little_endian)
{
    DSTU_KEY *key = DSTU_KEY_new(), *ret = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *g = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
        return NULL;

    if (params->sbox)
    {
        if (64 != ASN1_STRING_length(params->sbox))
            goto err;

        if (!is_default_sbox(ASN1_STRING_get0_data(params->sbox)))
        {
            key->sbox = copy_sbox(ASN1_STRING_get0_data(params->sbox));
            if (!(key->sbox))
                goto err;
        }
    }

    if (DSTU_STANDARD_CURVE == params->curve->type)
    {
        group = group_from_nid(OBJ_obj2nid(params->curve->curve.named_curve));
        if (!group)
            goto err;

        if (!EC_KEY_set_group(key->ec, group))
            goto err;
    }
    else
    {
        group = group_from_asn1(params->curve->curve.custom_curve, is_little_endian);
        if (!group)
            goto err;

        if (!EC_KEY_set_group(key->ec, group))
            goto err;
    }

    ret = key;
    key = NULL;

    err:

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (g)
        EC_POINT_free(g);

    if (group)
        EC_GROUP_free(group);

    if (key)
        DSTU_KEY_free(key);

    return ret;
}

DSTU_KEY_CTX *DSTU_KEY_CTX_new(void)
{
    DSTU_KEY_CTX *ctx = OPENSSL_malloc(sizeof(DSTU_KEY_CTX));
    if (ctx)
    {
        memset(ctx, 0, sizeof(DSTU_KEY_CTX));
        return ctx;
    }
    return NULL;
}

void DSTU_KEY_CTX_set(DSTU_KEY_CTX *ctx, EC_GROUP *group, unsigned char *sbox)
{
    if (group)
    {
        if (ctx->group)
            EC_GROUP_free(ctx->group);
        ctx->group = group;
    }

    if (sbox)
    {
        if (ctx->sbox)
            OPENSSL_free(ctx->sbox);
        ctx->sbox = sbox;
    }
}

DSTU_KEY_CTX *DSTU_KEY_CTX_copy(const DSTU_KEY_CTX *ctx)
{
    DSTU_KEY_CTX *copy = DSTU_KEY_CTX_new();

    if (!copy)
        return NULL;

    copy->type = ctx->type;

    if (ctx->group)
    {
        copy->group = EC_GROUP_dup(ctx->group);
        if (!(copy->group))
        {
            DSTU_KEY_CTX_free(copy);
            return NULL;
        }
    }

    if (ctx->sbox)
    {
        copy->sbox = copy_sbox(ctx->sbox);
        if (!(copy->sbox))
        {
            DSTU_KEY_CTX_free(copy);
            return NULL;
        }
    }

    return copy;
}

void DSTU_KEY_CTX_free(DSTU_KEY_CTX* ctx)
{
    if (!ctx)
        return;

    if (ctx->group)
    {
        EC_GROUP_free(ctx->group);
        ctx->group = NULL;
    }
    if (ctx->sbox)
    {
        OPENSSL_free(ctx->sbox);
        ctx->sbox = NULL;
    }
    OPENSSL_free(ctx);
}

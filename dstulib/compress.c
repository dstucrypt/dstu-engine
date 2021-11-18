/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "compress.h"
#include "params.h"

#include <openssl/bn.h>
#include <openssl/ossl_typ.h>

#include <string.h>

static int bn_trace(const BIGNUM *bn, const BIGNUM *p, BN_CTX *ctx)
{
    BIGNUM *r = NULL;
    int res = -1, i;

    BN_CTX_start(ctx);

    r = BN_CTX_get(ctx);

    if (!BN_copy(r, bn))
        goto err;
    for (i = 1; i <= (BN_num_bits(p) - 2); i++)
    {
        if (!BN_GF2m_mod_sqr(r, r, p, ctx))
            goto err;
        if (!BN_GF2m_add(r, r, bn))
            goto err;
    }

    if (BN_is_one(r))
        res = 1;
    else if (BN_is_zero(r))
        res = 0;

    err:

    BN_CTX_end(ctx);
    return res;
}

int dstu_point_compress(const EC_GROUP *group, const EC_POINT *point,
                        unsigned char *compressed, int compressed_length)
{
    int field_size, res = 0, trace;
    BN_CTX *ctx;
    BIGNUM *p, *x_inv, *x, *y;

    field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (compressed_length < field_size)
        return 0;

    ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    x_inv = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    if (!y)
        goto err;

    if (!EC_GROUP_get_curve_GF2m(group, p, NULL, NULL, ctx))
        goto err;

    if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, ctx))
        goto err;

    if (BN_is_zero(x))
    {
        memset(compressed, 0, field_size);
        res = 1;
        goto err;
    }

    if (!BN_GF2m_mod_inv(x_inv, x, p, ctx))
        goto err;

    if (!BN_GF2m_mod_mul(y, y, x_inv, p, ctx))
        goto err;

    trace = bn_trace(y, p, ctx);
    if (-1 == trace)
        goto err;

    if (trace)
    {
        if (!BN_set_bit(x, 0))
            goto err;
    }
    else
    {
        if (!BN_clear_bit(x, 0))
            goto err;
    }

    if (bn_encode(x, compressed, field_size))
        res = 1;

    err:

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return res;
}

int dstu_point_expand(const unsigned char *compressed, int compressed_length,
                      const EC_GROUP *group, EC_POINT *point)
{
    int field_size, res = 0, trace, k;
    BN_CTX *ctx;
    BIGNUM *p, *a, *b, *x2, *x, *y;

    field_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (compressed_length < field_size)
        return 0;

    ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);

    if (!y)
        goto err;

    if (!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx))
        goto err;

    if (!BN_bin2bn(compressed, compressed_length, x))
        goto err;

    if (BN_is_zero(x))
    {
        if (!BN_GF2m_mod_sqrt(y, b, p, ctx))
            goto err;

        if (EC_POINT_set_affine_coordinates_GF2m(group, point, x, y, ctx))
            res = 1;

        goto err;
    }

    k = BN_is_bit_set(x, 0);

    if (!BN_clear_bit(x, 0))
        goto err;

    trace = bn_trace(x, p, ctx);
    if (-1 == trace)
        goto err;

    if ((trace && BN_is_zero(a)) || ((!trace) && BN_is_one(a)))
    {
        if (!BN_set_bit(x, 0))
            goto err;
    }

    if (!BN_GF2m_mod_sqr(x2, x, p, ctx))
        goto err;

    if (!BN_GF2m_mod_mul(y, x2, x, p, ctx))
        goto err;

    if (BN_is_one(a))
    {
        if (!BN_GF2m_add(y, y, x2))
            goto err;
    }

    if (!BN_GF2m_add(y, y, b))
        goto err;

    if (!BN_GF2m_mod_inv(x2, x2, p, ctx))
        goto err;

    if (!BN_GF2m_mod_mul(y, y, x2, p, ctx))
        goto err;

    if (!BN_GF2m_mod_solve_quad(y, y, p, ctx))
        goto err;

    trace = bn_trace(y, p, ctx);

    if ((k && !trace) || (!k && trace))
    {
        if (!BN_GF2m_add(y, y, BN_value_one()))
            goto err;
    }

    if (!BN_GF2m_mod_mul(y, y, x, p, ctx))
        goto err;

    if (EC_POINT_set_affine_coordinates_GF2m(group, point, x, y, ctx))
        res = 1;

    err:

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return res;
}

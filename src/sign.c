/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "sign.h"
#include "params.h" // bn_encode
#include "err.h"

#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include <string.h>
#include <stddef.h>

static int bn_truncate_bits(BIGNUM *bn, int bitsize)
{
    int num_bits = BN_num_bits(bn);
    while (num_bits > bitsize)
    {
        if (!BN_clear_bit(bn, num_bits - 1))
            return 0;
        num_bits = BN_num_bits(bn);
    }
    return 1;
}

static int hash_to_field(const unsigned char *hash, int hash_len, BIGNUM *fe,
                         int fieldsize)
{
    unsigned char *h = OPENSSL_malloc(hash_len);
    int i;
    if (!h)
        return 0;

    for (i = 0; i < hash_len; i++)
        h[i] = hash[hash_len - 1 - i];

    if (!BN_bin2bn(h, hash_len, fe))
    {
        OPENSSL_free(h);
        return 0;
    }

    OPENSSL_free(h);
    if (BN_is_zero(fe))
        BN_one(fe);

    return bn_truncate_bits(fe, fieldsize);
}

static int field_to_bn(BIGNUM *fe, const BIGNUM *order)
{
    return bn_truncate_bits(fe, BN_num_bits(order) - 1);
}

int dstu_do_sign(const EC_KEY* key, const unsigned char *tbs, size_t tbslen,
                 unsigned char *sig)
{
    const BIGNUM *d = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BIGNUM *e, *Fe, *h, *r, *s, *n, *p;
    BN_CTX *ctx = NULL;
    EC_POINT *eG = NULL;
    int field_size, ret = 0;

    if (!d || !group)
        return 0;

    /* DSTU supports only binary fields */
    if (NID_X9_62_characteristic_two_field != EC_METHOD_get_field_type(EC_GROUP_method_of(group)))
    {
        DSTUerr(DSTU_F_DSTU_DO_SIGN, DSTU_R_INCORRECT_FIELD_TYPE);
        return 0;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BN_CTX_start(ctx);

    e = BN_CTX_get(ctx);
    Fe = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    n = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);

    if (!s)
        goto err;

    if (!EC_GROUP_get_order(group, n, ctx))
        goto err;

    field_size = BN_num_bytes(n);

    if (!EC_GROUP_get_curve_GF2m(group, p, NULL, NULL, ctx))
        goto err;

    eG = EC_POINT_new(group);
    if (!eG)
        goto err;

    if (!hash_to_field(tbs, tbslen, h, EC_GROUP_get_degree(group)))
        goto err;

    do
    {
        do
        {
            do
            {
                if (!BN_rand_range(e, n))
                    goto err;

                if (!EC_POINT_mul(group, eG, e, NULL, NULL, ctx))
                    goto err;

                if (!EC_POINT_get_affine_coordinates_GF2m(group, eG, Fe, NULL,
                    ctx))
                    goto err;
            }
            while (BN_is_zero(Fe));

            if (!BN_GF2m_mod_mul(r, h, Fe, p, ctx))
                goto err;

            if (!field_to_bn(r, n))
                goto err;
        }
        while (BN_is_zero(r));

        if (!BN_mod_mul(s, d, r, n, ctx))
            goto err;

        if (!BN_mod_add_quick(s, s, e, n))
            goto err;
    }
    while (BN_is_zero(s));

    if (!bn_encode(s, sig, field_size))
        goto err;

    if (!bn_encode(r, sig + field_size, field_size))
        goto err;

    ret = 1;

    err:

    if (eG)
        EC_POINT_free(eG);

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

int dstu_do_verify(const EC_KEY *key, const unsigned char *tbs, size_t tbslen,
                   const unsigned char *sig, size_t siglen)
{
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *Q = EC_KEY_get0_public_key(key);
    int ret = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *R = NULL;
    BIGNUM *r, *s, *r1, *n, *Rx, *p;

    if (!group || !Q)
        return 0;

    /* DSTU supports only binary fields */
    if (NID_X9_62_characteristic_two_field != EC_METHOD_get_field_type(EC_GROUP_method_of(group)))
    {
        DSTUerr(DSTU_F_DSTU_DO_VERIFY, DSTU_R_INCORRECT_FIELD_TYPE);
        return 0;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        return 0;

    BN_CTX_start(ctx);

    n = BN_CTX_get(ctx);
    r1 = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    Rx = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);

    if (!s)
        goto err;

    if (!hash_to_field(tbs, tbslen, r1, EC_GROUP_get_degree(group)))
        goto err;

    if (!EC_GROUP_get_order(group, n, ctx))
        goto err;

    if (!EC_GROUP_get_curve_GF2m(group, p, NULL, NULL, ctx))
        goto err;

    if (!BN_bin2bn(sig, siglen / 2, s))
        goto err;

    if (!BN_bin2bn(sig + (siglen / 2), siglen / 2, r))
        goto err;

    if (BN_is_zero(s) || BN_is_zero(r))
        goto err;

    if ((BN_cmp(s, n) >= 0) || (BN_cmp(r, n) >= 0))
        goto err;

    R = EC_POINT_new(group);
    if (!R)
        goto err;

    if (!EC_POINT_mul(group, R, s, Q, r, ctx))
        goto err;

    if (EC_POINT_is_at_infinity(group, R))
        goto err;

    if (!EC_POINT_get_affine_coordinates_GF2m(group, R, Rx, NULL, ctx))
        goto err;

    if (!BN_GF2m_mod_mul(r1, r1, Rx, p, ctx))
        goto err;

    if (!field_to_bn(r1, n))
        goto err;

    if (!BN_cmp(r, r1))
        ret = 1;

    err:

    if (R)
        EC_POINT_free(R);

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

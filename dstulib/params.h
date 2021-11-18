/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#ifndef DSTU_PARAMS_H_
#define DSTU_PARAMS_H_

#include "gost/gost89.h"

#include <openssl/ec.h>
#include <openssl/ossl_typ.h>

#define DEFAULT_CURVE 6
#define get_default_group() group_from_named_curve(DEFAULT_CURVE)

typedef struct dstu_named_curve_st
{
    int nid;
    int poly[6];
    unsigned char *data;
} DSTU_NAMED_CURVE;

extern DSTU_NAMED_CURVE dstu_curves[];
extern unsigned char default_sbox[64];

void unpack_sbox(unsigned char *packed_sbox, gost_subst_block *unpacked_sbox);
void pack_sbox(gost_subst_block *unpacked_sbox, unsigned char *packed_sbox);
void dstu_get_sbox(gost_ctx *ctx, gost_subst_block *sbox);
int is_default_sbox(const unsigned char *sbox);
unsigned char* copy_sbox(const unsigned char *sbox);

EC_GROUP* group_from_named_curve(int curve_num);
EC_GROUP* group_from_nid(int nid);

int dstu_generate_key(EC_KEY *key);
int dstu_add_public_key(EC_KEY *key);

void reverse_bytes(void *mem, int size);
void reverse_bytes_copy(void *dst, const void *src, int size);

int bn_encode(const BIGNUM *bn, unsigned char* buffer, int length);

int curve_nid_from_group(const EC_GROUP *group);

#endif /* DSTU_PARAMS_H_ */

/* =====================================================================
 * Author: Ignat Korchagin <ignat.korchagin@gmail.com>
 * This file is distributed under the same license as OpenSSL
 ==================================================================== */

#include "md.h"
#include "params.h" // default_sbox, unpack_sbox
#include "key.h" // DSTU_KEY
#include "control.h"

#include "gost/gosthash.h" // gost_hash_ctx
#include "gost/gost89.h" // gost_subst_block

#include <string.h>

struct dstu_digest_ctx
{
    gost_hash_ctx dctx;
    gost_ctx cctx;
};

static int dstu_md_init(EVP_MD_CTX *ctx)
{
    gost_subst_block sbox;
    struct dstu_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    EVP_PKEY_CTX *pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
    EVP_PKEY *pkey = pkey_ctx ? EVP_PKEY_CTX_get0_pkey(pkey_ctx) : NULL;
    DSTU_KEY *dstu_key = pkey ? EVP_PKEY_get0(pkey) : NULL;
    unsigned char *sbox_source = dstu_key && dstu_key->sbox ? dstu_key->sbox : default_sbox;

    unpack_sbox(sbox_source, &sbox);
    memset(&(c->dctx), 0, sizeof(gost_hash_ctx));
    gost_init(&(c->cctx), &sbox);
    c->dctx.cipher_ctx = &(c->cctx);
    return 1;
}

static int dstu_md_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return hash_block((gost_hash_ctx *) (EVP_MD_CTX_md_data(ctx)), data, count);
}

static int dstu_md_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return finish_hash((gost_hash_ctx *) (EVP_MD_CTX_md_data(ctx)), md);
}

static int dstu_md_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct dstu_digest_ctx *to_ctx = EVP_MD_CTX_md_data(to);
    struct dstu_digest_ctx *from_ctx = EVP_MD_CTX_md_data(from);
    if (to_ctx && from_ctx)
    {
        memcpy(to_ctx, from_ctx, sizeof(struct dstu_digest_ctx));
        to_ctx->dctx.cipher_ctx = &(to_ctx->cctx);
    }
    return 1;
}

static int dstu_md_cleanup(EVP_MD_CTX *ctx)
{
    struct dstu_digest_ctx *c = EVP_MD_CTX_md_data(ctx);
    if (c)
        memset(c, 0, sizeof(struct dstu_digest_ctx));
    return 1;
}

static int dstu_md_ctrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    gost_subst_block sbox;
    struct dstu_digest_ctx *c = EVP_MD_CTX_md_data(ctx);

    switch (cmd)
    {
        case DSTU_SET_CUSTOM_SBOX:
            if ((!p2) || (sizeof(default_sbox) != p1))
                return 0;
            unpack_sbox((unsigned char *) p2, &sbox);
            gost_init(&(c->cctx), &sbox);
            return 1;
    }

    return 0;
}

EVP_MD *dstu_digest_new()
{
    EVP_MD *res = EVP_MD_meth_new(NID_dstu34311, 0);
    if (res == NULL)
        return NULL;
    if (!EVP_MD_meth_set_result_size(res, 32) ||
        !EVP_MD_meth_set_input_blocksize(res, 32) ||
        !EVP_MD_meth_set_app_datasize(res, sizeof(struct dstu_digest_ctx)) ||
        !EVP_MD_meth_set_flags(res, 0) ||
        !EVP_MD_meth_set_init(res, dstu_md_init) ||
        !EVP_MD_meth_set_update(res, dstu_md_update) ||
        !EVP_MD_meth_set_final(res, dstu_md_final) ||
        !EVP_MD_meth_set_copy(res, dstu_md_copy) ||
        !EVP_MD_meth_set_cleanup(res, dstu_md_cleanup) ||
        !EVP_MD_meth_set_ctrl(res, dstu_md_ctrl))
    {
        EVP_MD_meth_free(res);
        return NULL;
    }
    return res;
}

void dstu_digest_free(EVP_MD *digest)
{
    EVP_MD_meth_free(digest);
}
